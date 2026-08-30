#!/usr/bin/env python3
"""Core-driven real-traffic catalog scan.

Every TCP-reachable candidate is tested through the same connection path
validated locally:

    parse -> TCP candidate -> Xray config -> Xray -> local SOCKS5
    -> Xray outbound -> real HTTP traffic -> classification

TLS is not used as a gate before the Xray test.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import country_resolver
import real_delay
import real_delay_google_batch as publisher

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
XRAY = Path(os.environ.get("XRAY_BIN", "/opt/hostedtoolcache/xray/xray"))

WORKERS = max(1, int(os.environ.get("REAL_DELAY_WORKERS", "16")))
TIMEOUT = max(0.5, float(os.environ.get("REAL_DELAY_NODE_TIMEOUT", "10")))
BASE_PORT = int(os.environ.get("REAL_DELAY_SOCKS_BASE", "21000"))
BATCH_SIZE = max(50, min(int(os.environ.get("REAL_DELAY_XRAY_BATCH_SIZE", "500")), 1000))


def validate_batch(root: Path, items: list[dict]) -> tuple[list[dict], list[dict]]:
    """Validate an Xray config and isolate bad nodes by bisection."""
    failures: list[dict] = []
    if not items:
        return [], failures

    def check(chunk: list[dict]) -> bool:
        path = root / f"check-{time.monotonic_ns()}.json"
        real_delay.write_cfg(path, chunk)
        try:
            proc = subprocess.run(
                [str(XRAY), "-test", "-config", str(path)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(30, len(chunk) // 4 + 30),
            )
        except subprocess.TimeoutExpired:
            return False
        return proc.returncode == 0

    if check(items):
        return items, failures

    good: list[dict] = []
    stack = [items]
    while stack:
        chunk = stack.pop()
        if not chunk:
            continue
        if check(chunk):
            good.extend(chunk)
            continue
        if len(chunk) == 1:
            item = chunk[0]
            failures.append({
                "index": item["index"],
                "uri": item["uri"],
                "reason": "Xray config validation failed after isolation",
                "classification": "config_conversion_failed",
            })
            continue
        mid = len(chunk) // 2
        stack.append(chunk[:mid])
        stack.append(chunk[mid:])

    return good, failures


def scan_batch(root: Path, batch: list[dict], batch_no: int, total_batches: int, results: list[dict], failures: list[dict]) -> None:
    """Run one Xray process serving independent SOCKS ports per node."""
    local = [{**item, "port": BASE_PORT + i} for i, item in enumerate(batch)]
    included, batch_failures = validate_batch(root, local)
    failures.extend(batch_failures)

    if not included:
        print(f"INFO core_batch={batch_no}/{total_batches} included=0 config_failed={len(batch_failures)}")
        return

    cfg = root / f"batch-{batch_no}.json"
    log_path = root / f"batch-{batch_no}.log"
    real_delay.write_cfg(cfg, included)

    with log_path.open("w", encoding="utf-8", errors="replace") as log_file:
        proc = subprocess.Popen(
            [str(XRAY), "run", "-c", str(cfg)],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            if not real_delay.wait_port(included[0]["port"], timeout=20):
                tail = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
                raise RuntimeError(
                    f"Xray batch {batch_no} did not open first SOCKS port.\n{tail}"
                )

            done = 0
            with ThreadPoolExecutor(max_workers=WORKERS) as executor:
                future_map = {
                    executor.submit(real_delay.probe, item, TIMEOUT): item
                    for item in included
                }
                for future in as_completed(future_map):
                    item = future_map[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {
                            "index": item["index"],
                            "probe_passed": 0,
                            "internet_healthy": False,
                            "alive": False,
                            "classification": "failed",
                            "delay_ms": -1,
                            "details": {"exception": str(exc)[:300]},
                        }
                    results.append(result)
                    done += 1
                    if done % 100 == 0 or done == len(included):
                        active = sum(1 for row in results if row.get("classification") == "active")
                        backup = sum(1 for row in results if row.get("classification") == "backup")
                        print(
                            f"INFO core_batch_progress={batch_no}/{total_batches} "
                            f"nodes={done}/{len(included)} active={active} backup={backup}"
                        )
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass


def resolve_countries(publishable: list[dict]) -> dict:
    if not publishable:
        return {"hostname": 0, "geoip_local": 0, "unknown": 0, "database_loaded": False}

    rows = [
        {key: value for key, value in item.items() if key not in {"node", "result"}}
        for item in publishable
    ]
    resolution = country_resolver.resolve_rows(rows)

    for item, row in zip(publishable, rows):
        item["country"] = row.get("country") or "UNKNOWN"
        item["country_resolution"] = row.get("country_resolution") or "unknown"
        item["country_resolution_confidence"] = row.get("country_resolution_confidence")
    return resolution


def main() -> None:
    if not XRAY.exists():
        raise SystemExit(f"Xray binary not found: {XRAY}")

    pool = real_delay.load_pool()
    if not pool:
        raise SystemExit("No TCP-reachable nodes available")

    # TCP reachability is only the candidate gate. Every candidate now gets
    # the same Core-driven real-traffic test as the validated local tester.
    candidates: list[dict] = []
    for index, item in enumerate(pool):
        item = {**item, "index": index}
        if item.get("node", {}).get("port") not in {80, 443}:
            continue
        candidates.append(item)

    total_batches = (len(candidates) + BATCH_SIZE - 1) // BATCH_SIZE
    print(
        f"INFO tcp_candidates={len(candidates)} workers={WORKERS} "
        f"batch_size={BATCH_SIZE} timeout_s={TIMEOUT} batches={total_batches}"
    )
    print("INFO health_path=parse->tcp->xray_config->xray->socks5->real_https")

    results: list[dict] = []
    config_failures: list[dict] = []

    with tempfile.TemporaryDirectory(prefix="core-real-traffic-") as temp_dir:
        root = Path(temp_dir)
        for offset in range(0, len(candidates), BATCH_SIZE):
            batch_no = offset // BATCH_SIZE + 1
            scan_batch(
                root,
                candidates[offset:offset + BATCH_SIZE],
                batch_no,
                total_batches,
                results,
                config_failures,
            )
            active = sum(1 for row in results if row.get("classification") == "active")
            backup = sum(1 for row in results if row.get("classification") == "backup")
            failed = sum(1 for row in results if row.get("classification") == "failed")
            print(
                f"INFO core_batch_done={batch_no}/{total_batches} "
                f"results={len(results)} active={active} backup={backup} "
                f"failed={failed} config_failed={len(config_failures)}"
            )

    by_index = {row["index"]: row for row in results}
    active_nodes: list[dict] = []
    backup_nodes: list[dict] = []

    for item in candidates:
        result = by_index.get(item["index"])
        if not result:
            continue
        item2 = {**item, "result": result}
        classification = result.get("classification")
        if classification == "active":
            active_nodes.append(item2)
        elif classification == "backup":
            backup_nodes.append(item2)

    # Only nodes that completed real Core-driven traffic are published.
    resolution = resolve_countries(active_nodes + backup_nodes)

    stats = {
        "pool_total": len(pool),
        "included": len(results),
        "config_conversion_failed": len(config_failures),
        "failed": sum(1 for row in results if row.get("classification") == "failed"),
        "workers": WORKERS,
        "timeout_s": TIMEOUT,
        "batch_size": BATCH_SIZE,
    }

    published = len(active_nodes) + len(backup_nodes)
    print(
        f"INFO core_real_traffic_done pool={len(pool)} deep_checked={len(results)} "
        f"active={len(active_nodes)} backup={len(backup_nodes)} "
        f"failed={stats['failed']} config_failed={len(config_failures)} "
        f"published={published}"
    )

    publisher.publish(
        active_nodes,
        backup_nodes,
        resolution,
        stats,
    )

    meta = OUT / "metadata"
    meta.mkdir(parents=True, exist_ok=True)
    metadata = {
        "schema": 10,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": "core_driven_real_traffic",
        "tcp_candidates": len(candidates),
        "deep_checked": len(results),
        "active": len(active_nodes),
        "backup": len(backup_nodes),
        "failed_after_core": stats["failed"],
        "config_conversion_failed": len(config_failures),
        "published_total": published,
        "workers": WORKERS,
        "batch_size": BATCH_SIZE,
        "node_timeout_s": TIMEOUT,
        "allowed_ports": [80, 443],
        "health_policy": (
            "Xray Core + local SOCKS5 + three real HTTP probes: "
            "Microsoft Connect Test 200, Google 204, Firefox 200. "
            "3/3=ACTIVE, 1-2/3=BACKUP, 0/3=FAILED."
        ),
        "country_policy": (
            "Automatic country resolution from successful nodes only; "
            "no fixed country allowlist."
        ),
        "tls_policy": (
            "Direct TLS is not used as a pre-filter; node health is "
            "determined by the Xray-driven real-traffic path."
        ),
        "country_resolution": resolution,
    }
    (meta / "core_driven_health.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
