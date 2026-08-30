#!/usr/bin/env python3
"""FastNodes-style staged scan: cheap TLS promotion, bounded Xray deep checks."""
from __future__ import annotations

import json
import os
import socket
import ssl
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
TLS_WORKERS = max(1, int(os.environ.get("REAL_DELAY_TLS_WORKERS", "512")))
TLS_TIMEOUT = max(0.5, float(os.environ.get("REAL_DELAY_TLS_TIMEOUT", "4")))
DEEP_TIMEOUT = max(0.5, float(os.environ.get("REAL_DELAY_NODE_TIMEOUT", "10")))
DEEP_WORKERS = max(1, int(os.environ.get("REAL_DELAY_WORKERS", "256")))
BASE_PORT = int(os.environ.get("REAL_DELAY_SOCKS_BASE", "21000"))
BATCH_SIZE = max(100, min(int(os.environ.get("REAL_DELAY_XRAY_BATCH_SIZE", "2000")), 5000))
DEEP_BUDGET = max(100, int(os.environ.get("REAL_DELAY_DEEP_CHECK_BUDGET", "2621")))


def tls_applicable(node: dict) -> bool:
    scheme = str(node.get("scheme") or "").lower()
    if scheme == "trojan":
        return True
    if scheme == "vmess":
        return bool(node.get("tls"))
    if scheme == "vless":
        return str(node.get("security") or "").lower() == "tls"
    return False


def tls_probe(item: dict) -> dict:
    started = time.perf_counter()
    node = item["node"]
    host = str(node.get("server") or "").strip()
    port = int(node.get("port") or 443)
    sni = str(node.get("sni") or host).strip()
    try:
        sock = socket.create_connection((host, port), timeout=TLS_TIMEOUT)
        sock.settimeout(TLS_TIMEOUT)
        with ssl.create_default_context().wrap_socket(sock, server_hostname=sni):
            latency = round((time.perf_counter() - started) * 1000, 1)
            return {"ok": True, "latency_ms": latency, "detail": "TLS handshake succeeded", "sni": sni}
    except Exception as exc:
        return {"ok": False, "latency_ms": -1, "detail": str(exc)[:180], "sni": sni}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def validate_batch(root: Path, items: list[dict]) -> tuple[list[dict], list[dict]]:
    failures = []
    if not items:
        return [], failures

    def test(chunk: list[dict]) -> bool:
        path = root / f"test-{time.monotonic_ns()}.json"
        real_delay.write_cfg(path, chunk)
        try:
            res = subprocess.run([str(XRAY), "-test", "-config", str(path)], text=True, capture_output=True, timeout=max(30, len(chunk) // 4 + 30))
            return res.returncode == 0
        except subprocess.TimeoutExpired:
            return False

    if test(items):
        return items, failures
    good = []
    stack = [items]
    while stack:
        chunk = stack.pop()
        if not chunk:
            continue
        if test(chunk):
            good.extend(chunk)
        elif len(chunk) == 1:
            item = chunk[0]
            failures.append({"index": item["index"], "uri": item["uri"], "reason": "Xray config validation failed", "classification": "config_conversion_failed"})
        else:
            mid = len(chunk) // 2
            stack.append(chunk[:mid])
            stack.append(chunk[mid:])
    return good, failures


def wait_port(port: int, timeout: float = 20.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def deep_probe_batch(root: Path, batch: list[dict], batch_no: int, total_batches: int, results: list[dict], failures: list[dict]) -> None:
    local = [{**item, "port": BASE_PORT + i} for i, item in enumerate(batch)]
    included, batch_failures = validate_batch(root, local)
    failures.extend(batch_failures)
    if not included:
        return
    cfg = root / f"batch-{batch_no}.json"
    real_delay.write_cfg(cfg, included)
    proc = subprocess.Popen([str(XRAY), "run", "-c", str(cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if included and not wait_port(included[0]["port"]):
            raise SystemExit(f"Xray batch {batch_no} did not open first inbound")
        with ThreadPoolExecutor(max_workers=DEEP_WORKERS) as executor:
            future_map = {executor.submit(real_delay.probe, item, DEEP_TIMEOUT): item for item in included}
            for future in as_completed(future_map):
                item = future_map[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = {"index": item["index"], "probe_passed": 0, "internet_healthy": False, "alive": False, "classification": "failed", "delay_ms": -1, "details": {"exception": str(exc)[:180]}}
                result["tls_verified"] = bool(item.get("tls_verified"))
                results.append(result)
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()


def main() -> None:
    if not XRAY.exists():
        raise SystemExit(f"Xray binary not found: {XRAY}")
    pool = real_delay.load_pool()
    if not pool:
        raise SystemExit("No TCP-reachable nodes available")

    tls_items = []
    non_tls_items = []
    for index, item in enumerate(pool):
        item = {**item, "index": index}
        (tls_items if tls_applicable(item["node"]) else non_tls_items).append(item)

    tls_results = {}
    with ThreadPoolExecutor(max_workers=TLS_WORKERS) as executor:
        future_map = {executor.submit(tls_probe, item): item for item in tls_items}
        for future in as_completed(future_map):
            item = future_map[future]
            try:
                tls_results[item["index"]] = future.result()
            except Exception as exc:
                tls_results[item["index"]] = {"ok": False, "latency_ms": -1, "detail": str(exc)[:180]}

    tls_verified = []
    for item in tls_items:
        probe = tls_results.get(item["index"], {})
        item["tls_verified"] = bool(probe.get("ok"))
        item["tls_latency_ms"] = probe.get("latency_ms", -1)
        if item["tls_verified"]:
            tls_verified.append(item)

    ranked_tls = sorted(tls_verified, key=lambda x: (x.get("tls_latency_ms", 10**9) if x.get("tls_latency_ms", -1) >= 0 else 10**9, x["index"]))
    selected = ranked_tls[:DEEP_BUDGET]
    selected_ids = {x["index"] for x in selected}
    if len(selected) < DEEP_BUDGET:
        for item in sorted(pool, key=lambda x: x.get("index", 10**9)):
            if item["index"] not in selected_ids:
                selected.append(item)
                selected_ids.add(item["index"])
                if len(selected) >= DEEP_BUDGET:
                    break

    results = []
    failures = []
    total_batches = (len(selected) + BATCH_SIZE - 1) // BATCH_SIZE
    print(f"INFO staged_scan_pool={len(pool)} tls_applicable={len(tls_items)} tls_verified={len(tls_verified)} deep_selected={len(selected)} batches={total_batches}")

    with tempfile.TemporaryDirectory(prefix="fastnodes-staged-") as td:
        root = Path(td)
        for offset in range(0, len(selected), BATCH_SIZE):
            batch_no = offset // BATCH_SIZE + 1
            deep_probe_batch(root, selected[offset:offset + BATCH_SIZE], batch_no, total_batches, results, failures)
            print(f"INFO staged_batch_done={batch_no}/{total_batches} results={len(results)}")

    by_index = {r["index"]: r for r in results}
    active = []
    backup = []
    for item in selected:
        result = by_index.get(item["index"])
        if not result:
            continue
        item2 = {**item, "result": result}
        if result.get("classification") == "active":
            active.append(item2)
        elif result.get("classification") == "backup":
            backup.append(item2)

    # FastNodes-style promotion: TLS-verified nodes that were not deep-checked stay available
    # as promotion-only backup candidates rather than being discarded.
    for item in tls_verified:
        if item["index"] in selected_ids:
            continue
        result = {
            "index": item["index"], "probe_passed": 0,
            "internet_healthy": False, "alive": True,
            "classification": "backup", "delay_ms": item.get("tls_latency_ms", -1),
            "tls_verified": True,
            "details": {"tls_promotion": {"ok": True, "latency_ms": item.get("tls_latency_ms", -1), "detail": "TLS promotion-only; not deep checked"}},
        }
        backup.append({**item, "result": result})

    publishable = active + backup
    rows = [{k: v for k, v in item.items() if k not in {"node", "result"}} for item in publishable]
    if rows:
        resolution = country_resolver.resolve_rows(rows)
        for item, row in zip(publishable, rows):
            item["country"] = row.get("country") or "UNKNOWN"
            item["country_resolution"] = row.get("country_resolution") or "unknown"
            item["country_resolution_confidence"] = row.get("country_resolution_confidence")
    else:
        resolution = {"hostname": 0, "geoip_local": 0, "unknown": 0, "database_loaded": False}

    failed_deep = sum(1 for r in results if r.get("classification") == "failed")
    stats = {
        "pool_total": len(pool), "included": len(results),
        "config_conversion_failed": len(failures), "failed": failed_deep,
        "workers": DEEP_WORKERS, "timeout_s": DEEP_TIMEOUT, "batch_size": BATCH_SIZE,
    }
    print(f"INFO staged_scan_done pool={len(pool)} tls_verified={len(tls_verified)} deep_checked={len(results)} active={len(active)} backup={len(backup)} failed={failed_deep} published={len(active)+len(backup)}")
    publisher.publish(active, backup, resolution, stats)

    meta = OUT / "metadata"
    meta.mkdir(parents=True, exist_ok=True)
    (meta / "staged_health.json").write_text(json.dumps({
        "schema": 1, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": "fastnodes_style_staged", "pool_total": len(pool),
        "tls_applicable": len(tls_items), "tls_verified": len(tls_verified),
        "deep_selected": len(selected), "deep_checked": len(results),
        "active": len(active), "backup": len(backup), "published_total": len(active) + len(backup),
        "failed_deep": failed_deep, "config_conversion_failed": len(failures),
        "tls_timeout_s": TLS_TIMEOUT, "deep_timeout_s": DEEP_TIMEOUT, "deep_budget": DEEP_BUDGET,
        "policy": "TLS is promotion-only; bounded Xray deep checks; TLS-verified non-deep nodes retained as BACKUP; no fixed country allowlist.",
        "country_resolution": resolution,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
