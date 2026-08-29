#!/usr/bin/env python3
"""Google TCP-only health scan with bounded Xray batches."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import country_resolver
import real_delay

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
XRAY = Path(os.environ.get("XRAY_BIN", "/opt/hostedtoolcache/xray/xray"))
WORKERS = max(1, int(os.environ.get("REAL_DELAY_WORKERS", "256")))
TIMEOUT = max(0.5, float(os.environ.get("REAL_DELAY_NODE_TIMEOUT", "5")))
BASE_PORT = int(os.environ.get("REAL_DELAY_SOCKS_BASE", "21000"))
BATCH_SIZE = max(100, min(int(os.environ.get("REAL_DELAY_XRAY_BATCH_SIZE", "2000")), 5000))
GOOGLE_HOST = "www.google.com"
GOOGLE_PORT = 443


def google_tcp_probe(item: dict, timeout: float) -> dict:
    started = time.perf_counter()
    sock = None
    ok = False
    detail = "unknown"
    try:
        sock = socket.create_connection(("127.0.0.1", item["port"]), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2) != b"\x05\x00":
            detail = "socks-auth"
        else:
            hb = GOOGLE_HOST.encode("idna")
            sock.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + GOOGLE_PORT.to_bytes(2, "big"))
            reply = sock.recv(4)
            if len(reply) != 4:
                detail = "short-socks-reply"
            elif reply[0] != 5:
                detail = "invalid-socks-version"
            elif reply[1] != 0:
                detail = f"socks-connect-failed-{reply[1]}"
            else:
                atyp = reply[3]
                if atyp == 1:
                    need = 4
                elif atyp == 3:
                    lb = sock.recv(1)
                    need = lb[0] if len(lb) == 1 else -1
                elif atyp == 4:
                    need = 16
                else:
                    need = -1
                if need < 0:
                    detail = "invalid-socks-atyp"
                else:
                    remaining = need
                    while remaining:
                        chunk = sock.recv(remaining)
                        if not chunk:
                            detail = "short-socks-address"
                            break
                        remaining -= len(chunk)
                    else:
                        if len(sock.recv(2)) == 2:
                            ok = True
                            detail = "TCP CONNECT succeeded"
                        else:
                            detail = "short-socks-port"
    except Exception as exc:
        detail = str(exc)[:180]
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    latency = round((time.perf_counter() - started) * 1000, 1) if ok else -1
    return {
        "index": item["index"],
        "google_tcp_ok": ok,
        "internet_healthy": ok,
        "alive": ok,
        "delay_ms": latency,
        "msft_ok": False,
        "google_204_ok": False,
        "firefox_ok": False,
        "details": {
            "google_tcp": {
                "ok": ok,
                "latency_ms": latency,
                "detail": detail,
                "host": GOOGLE_HOST,
                "port": GOOGLE_PORT,
            }
        },
    }


def wait_port(port: int, timeout: float = 20.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def validate_batch(root: Path, items: list[dict]) -> tuple[list[dict], list[dict]]:
    failures: list[dict] = []
    if not items:
        return [], failures

    def write_and_test(chunk: list[dict]) -> bool:
        path = root / f"test-{time.monotonic_ns()}.json"
        real_delay.write_cfg(path, chunk)
        try:
            res = subprocess.run(
                [str(XRAY), "-test", "-config", str(path)],
                text=True,
                capture_output=True,
                timeout=max(30, len(chunk) // 4 + 30),
            )
        except subprocess.TimeoutExpired:
            return False
        return res.returncode == 0

    if write_and_test(items):
        return items, failures

    good: list[dict] = []
    stack = [items]
    while stack:
        chunk = stack.pop()
        if not chunk:
            continue
        if write_and_test(chunk):
            good.extend(chunk)
        elif len(chunk) == 1:
            item = chunk[0]
            failures.append({
                "index": item["index"],
                "uri": item["uri"],
                "reason": "Xray config validation failed after isolation",
                "classification": "config_conversion_failed",
            })
        else:
            mid = len(chunk) // 2
            stack.append(chunk[:mid])
            stack.append(chunk[mid:])
    return good, failures


def scan_batch(root: Path, batch: list[dict], batch_no: int, total_batches: int, results: list[dict], failures: list[dict]) -> None:
    local_items = []
    for local_idx, original in enumerate(batch):
        local_items.append({**original, "port": BASE_PORT + local_idx})

    included, batch_failures = validate_batch(root, local_items)
    failures.extend(batch_failures)
    if not included:
        print(f"INFO google_batch={batch_no}/{total_batches} included=0")
        return

    cfg = root / f"batch-{batch_no}.json"
    real_delay.write_cfg(cfg, included)
    log_path = root / f"xray-{batch_no}.log"
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.Popen([str(XRAY), "run", "-c", str(cfg)], stdout=log, stderr=subprocess.STDOUT, text=True)
        try:
            if not wait_port(included[0]["port"]):
                tail = log_path.read_text(encoding="utf-8", errors="replace")[-2500:]
                raise SystemExit(f"Xray batch {batch_no} did not open first inbound.\n{tail}")

            with ThreadPoolExecutor(max_workers=WORKERS) as executor:
                future_map = {executor.submit(google_tcp_probe, item, TIMEOUT): item for item in included}
                done = 0
                for future in as_completed(future_map):
                    item = future_map[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {
                            "index": item["index"],
                            "google_tcp_ok": False,
                            "internet_healthy": False,
                            "alive": False,
                            "delay_ms": -1,
                            "msft_ok": False,
                            "google_204_ok": False,
                            "firefox_ok": False,
                            "details": {"exception": str(exc)[:180]},
                        }
                    results.append(result)
                    done += 1
                    if done % 500 == 0 or done == len(included):
                        print(f"INFO google_batch_progress={batch_no}/{total_batches} nodes={done}/{len(included)} google_alive={sum(1 for r in results if r.get('google_tcp_ok'))}")
        finally:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()


def main() -> None:
    if not XRAY.exists():
        raise SystemExit(f"Xray binary not found: {XRAY}")

    raw_pool = real_delay.load_pool()
    if not raw_pool:
        raise SystemExit("No TCP-reachable nodes available")

    # Assign a stable global index once. real_delay.write_cfg expects it for
    # deterministic inbound/outbound tags, while each batch reuses local ports.
    pool = [{**item, "index": idx} for idx, item in enumerate(raw_pool)]

    total_batches = (len(pool) + BATCH_SIZE - 1) // BATCH_SIZE
    print(f"INFO google_scan_pool={len(pool)} workers={WORKERS} batch_size={BATCH_SIZE} batches={total_batches} target={GOOGLE_HOST}:{GOOGLE_PORT} mode=google_tcp_only")

    started = time.perf_counter()
    results: list[dict] = []
    failures: list[dict] = []

    with tempfile.TemporaryDirectory(prefix="google-delay-") as td:
        root = Path(td)
        for offset in range(0, len(pool), BATCH_SIZE):
            batch_no = offset // BATCH_SIZE + 1
            scan_batch(root, pool[offset:offset + BATCH_SIZE], batch_no, total_batches, results, failures)

    by_index = {r["index"]: r for r in results}
    healthy = []
    for item in pool:
        result = by_index.get(item["index"])
        if result and result.get("google_tcp_ok"):
            healthy.append({**item, "result": result})

    healthy.sort(key=lambda x: (x["result"].get("delay_ms", 10**9), x["index"]))
    rows = [{k: v for k, v in item.items() if k not in {"node", "result"}} for item in healthy]
    if rows:
        resolution = country_resolver.resolve_rows(rows)
        for item, row in zip(healthy, rows):
            item["country"] = row.get("country") or "UNKNOWN"
            item["country_resolution"] = row.get("country_resolution") or "unknown"
            item["country_resolution_confidence"] = row.get("country_resolution_confidence")
    else:
        resolution = {"hostname": 0, "geoip_local": 0, "unknown": 0, "database_loaded": False}

    alive = len(healthy)
    stats = {
        "pool_total": len(pool),
        "included": len(results),
        "config_conversion_failed": len(failures),
        "alive": alive,
        "healthy": alive,
        "workers": WORKERS,
        "timeout_s": TIMEOUT,
        "batch_size": BATCH_SIZE,
    }
    print(f"INFO google_scan_done pool={len(pool)} included={len(results)} config_conversion_failed={len(failures)} google_alive={alive} healthy={alive} elapsed_s={time.perf_counter()-started:.1f}")

    real_delay.publish_healthy(healthy, resolution, stats)

    meta = OUT / "metadata"
    meta.mkdir(parents=True, exist_ok=True)
    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **stats,
        "health_policy": "Google TCP CONNECT only: real SOCKS5 CONNECT through Xray to www.google.com:443",
        "health_gate": {"url": "tcp://www.google.com:443", "type": "SOCKS5 CONNECT through Xray", "required": True},
        "probes": {"google_tcp": {"url": "tcp://www.google.com:443", "type": "SOCKS5 CONNECT", "required": True}},
        "nodes": [{**{k: v for k, v in item.items() if k != "node"}, "result": item["result"]} for item in healthy],
        "config_failures": failures,
    }
    (meta / "real_delay.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    for name in ("index.json", "health.json"):
        path = meta / name
        if path.is_file():
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["health_policy"] = report["health_policy"]
            payload["health_gate"] = report["health_gate"]
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
