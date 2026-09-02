#!/usr/bin/env python3
"""Isolated Xray pilot against an operator-owned HTTP 204 endpoint.

This script never publishes or rewrites the app-facing country/protocol feeds. It
loads the existing TCP-reachable pool, starts one Xray process for a small sample,
and verifies that each sampled node can reach an operator-controlled endpoint that
returns exactly HTTP 204.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import real_delay as rd

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output" / "metadata"
XRAY = Path(os.environ.get("XRAY_BIN", "/opt/hostedtoolcache/xray/xray"))
DEFAULT_LIMIT = max(1, int(os.environ.get("OWNED_204_PILOT_LIMIT", "20")))
DEFAULT_WORKERS = max(1, int(os.environ.get("OWNED_204_PILOT_WORKERS", "20")))
DEFAULT_TIMEOUT = max(0.5, float(os.environ.get("OWNED_204_TIMEOUT", "8")))
BASE_PORT = int(os.environ.get("OWNED_204_SOCKS_BASE", "31000"))


def parse_probe_url(value: str) -> tuple[str, str, bool]:
    value = value.strip()
    if not value:
        raise SystemExit("OWNED_204_URL is required")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"}:
        raise SystemExit("OWNED_204_URL must use http:// or https://")
    if not parsed.hostname:
        raise SystemExit("OWNED_204_URL must include a hostname")
    expected_port = 443 if parsed.scheme == "https" else 80
    if parsed.port not in {None, expected_port}:
        raise SystemExit("OWNED_204_URL must use the standard HTTP/HTTPS port")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return parsed.hostname, path, parsed.scheme == "https"


def select_sample(pool: list[dict], limit: int) -> list[dict]:
    def key(item: dict):
        latency = item.get("latency_ms")
        try:
            latency_value = float(latency)
        except (TypeError, ValueError):
            latency_value = 10**9
        return (latency_value, str(item.get("protocol") or ""), str(item.get("uri") or ""))

    return sorted(pool, key=key)[:limit]


def validate_items(items: list[dict], root: Path) -> tuple[list[dict], list[dict]]:
    valid: list[dict] = []
    rejected: list[dict] = []
    for item in items:
        cfg = root / f"validate-{item['index']}.json"
        rd.write_cfg(cfg, [item])
        try:
            check = subprocess.run(
                [str(XRAY), "-test", "-config", str(cfg)],
                text=True,
                capture_output=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            rejected.append({"index": item["index"], "uri": item["uri"], "reason": "xray-config-timeout"})
            continue
        if check.returncode == 0:
            valid.append(item)
        else:
            rejected.append({
                "index": item["index"],
                "uri": item["uri"],
                "reason": "xray-config-rejected",
                "detail": (check.stderr or check.stdout)[-1000:],
            })
    return valid, rejected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = parser.parse_args()

    if not XRAY.is_file():
        raise SystemExit(f"Xray binary not found: {XRAY}")

    probe_url = os.environ.get("OWNED_204_URL", "")
    host, path, use_tls = parse_probe_url(probe_url)
    limit = max(1, args.limit)
    workers = max(1, min(args.workers, limit))
    timeout = max(0.5, args.timeout)

    pool = rd.load_pool()
    if not pool:
        raise SystemExit("No TCP-reachable nodes available")
    selected = select_sample(pool, min(limit, len(pool)))

    prepared: list[dict] = []
    conversion_failed: list[dict] = []
    for idx, item in enumerate(selected):
        candidate = {**item, "index": idx, "port": BASE_PORT + idx}
        try:
            rd.xray_outbound(candidate["node"], f"node-{idx + 1}")
            prepared.append(candidate)
        except Exception as exc:
            conversion_failed.append({"index": idx, "uri": item["uri"], "reason": str(exc)[:500]})

    started = time.perf_counter()
    results: list[dict] = []
    config_rejected: list[dict] = []

    with tempfile.TemporaryDirectory(prefix="owned-204-pilot-") as td:
        root = Path(td)
        valid, config_rejected = validate_items(prepared, root)
        if not valid:
            raise SystemExit("No pilot nodes produced a valid Xray config")

        cfg = root / "pilot.json"
        rd.write_cfg(cfg, valid)
        check = subprocess.run(
            [str(XRAY), "-test", "-config", str(cfg)],
            text=True,
            capture_output=True,
            timeout=max(30, len(valid) + 30),
        )
        if check.returncode != 0:
            raise SystemExit("Combined pilot Xray config rejected: " + (check.stderr or check.stdout)[-2000:])

        proc = subprocess.Popen([str(XRAY), "run", "-c", str(cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if not rd.wait_port(valid[0]["port"]):
                raise SystemExit("Xray pilot process did not open its first SOCKS inbound")

            def probe(item: dict) -> dict:
                try:
                    ok, latency, detail = rd.socks_http(
                        item["port"], host, path, use_tls, 204, None, timeout
                    )
                except Exception as exc:
                    ok, latency, detail = False, -1, str(exc)[:180]
                return {
                    "index": item["index"],
                    "uri": item["uri"],
                    "protocol": item.get("protocol"),
                    "source": item.get("source"),
                    "tcp_latency_ms": item.get("latency_ms"),
                    "owned_204_ok": ok,
                    "owned_204_latency_ms": latency if ok else -1,
                    "detail": detail,
                }

            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(probe, item): item for item in valid}
                for number, future in enumerate(as_completed(futures), 1):
                    results.append(future.result())
                    if number % 10 == 0 or number == len(valid):
                        passed = sum(1 for row in results if row["owned_204_ok"])
                        print(f"INFO owned_204_progress={number}/{len(valid)} pass={passed}")
        finally:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()

    results.sort(key=lambda row: row["index"])
    passed = [row for row in results if row["owned_204_ok"]]
    report = {
        "schema": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": "isolated_xray_owned_204_pilot",
        "publishes_catalog": False,
        "probe": {
            "url": probe_url,
            "expected_status": 204,
            "tls": use_tls,
        },
        "pool_total": len(pool),
        "selected": len(selected),
        "config_conversion_failed": len(conversion_failed),
        "config_rejected": len(config_rejected),
        "xray_tested": len(results),
        "passed": len(passed),
        "failed": len(results) - len(passed),
        "pass_rate": round(len(passed) / len(results), 4) if results else 0.0,
        "workers": workers,
        "timeout_s": timeout,
        "elapsed_s": round(time.perf_counter() - started, 2),
        "conversion_failures": conversion_failed,
        "config_rejections": config_rejected,
        "nodes": results,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "xray_owned_204_pilot.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        f"INFO OWNED_204_PILOT selected={len(selected)} tested={len(results)} "
        f"pass={len(passed)} fail={len(results) - len(passed)} "
        f"report={path}"
    )
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
