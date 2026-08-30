#!/usr/bin/env python3
"""Core-driven real-traffic health scan with Active/Backup classification."""
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

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
XRAY = Path(os.environ.get("XRAY_BIN", "/opt/hostedtoolcache/xray/xray"))
WORKERS = max(1, int(os.environ.get("REAL_DELAY_WORKERS", "256")))
TIMEOUT = max(0.5, float(os.environ.get("REAL_DELAY_NODE_TIMEOUT", "10")))
BASE_PORT = int(os.environ.get("REAL_DELAY_SOCKS_BASE", "21000"))
BATCH_SIZE = max(100, min(int(os.environ.get("REAL_DELAY_XRAY_BATCH_SIZE", "2000")), 5000))
PROBES = (
    ("microsoft_connect_test", "www.msftconnecttest.com", "/connecttest.txt", False, 200, b"Microsoft Connect Test"),
    ("google_generate_204", "www.gstatic.com", "/generate_204", True, 204, None),
    ("firefox_success", "detectportal.firefox.com", "/success.txt", False, 200, b"success"),
)


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
            res = subprocess.run([str(XRAY), "-test", "-config", str(path)], text=True, capture_output=True, timeout=max(30, len(chunk) // 4 + 30))
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
            failures.append({"index": item["index"], "uri": item["uri"], "reason": "Xray config validation failed after isolation", "classification": "config_conversion_failed"})
        else:
            mid = len(chunk) // 2
            stack.append(chunk[:mid])
            stack.append(chunk[mid:])
    return good, failures


def socks_http(port: int, host: str, path: str, use_tls: bool, expected_status: int, expected_body: bytes | None, timeout: float):
    started = time.perf_counter()
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2) != b"\x05\x00":
            return False, -1, "socks-auth"
        hb = host.encode("idna")
        remote_port = 443 if use_tls else 80
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + remote_port.to_bytes(2, "big"))
        reply = sock.recv(4)
        if len(reply) != 4 or reply[1] != 0:
            return False, -1, "socks-connect"
        if reply[3] == 1:
            need = 4
            sock.recv(need)
        elif reply[3] == 3:
            lb = sock.recv(1)
            if not lb:
                return False, -1, "short-socks-address"
            sock.recv(lb[0])
        elif reply[3] == 4:
            sock.recv(16)
        if len(sock.recv(2)) != 2:
            return False, -1, "short-socks-port"
        conn = sock
        if use_tls:
            conn = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        conn.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: AhmedVPN-RealDelay/8\r\n\r\n".encode())
        data = bytearray()
        while len(data) < 16384:
            chunk = conn.recv(min(4096, 16384 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        first = bytes(data).split(b"\r\n", 1)[0]
        parts = first.split()
        if len(parts) < 2 or not parts[1].isdigit():
            return False, -1, "no-http"
        status = int(parts[1])
        if status != expected_status:
            return False, -1, f"unexpected-status-{status}"
        if expected_body is not None and expected_body not in data:
            return False, -1, "expected-body-missing"
        return True, round((time.perf_counter() - started) * 1000, 1), f"HTTP {status}"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def probe(item: dict, timeout: float) -> dict:
    details = {}
    delays = []
    for name, host, path, tls, status, body in PROBES:
        try:
            ok, latency, detail = socks_http(item["port"], host, path, tls, status, body, timeout)
        except Exception as exc:
            ok, latency, detail = False, -1, str(exc)[:180]
        details[name] = {"ok": ok, "latency_ms": latency if ok else -1, "detail": detail}
        if ok:
            delays.append(latency)
    passed = sum(1 for value in details.values() if value["ok"])
    return {
        "index": item["index"],
        "msft_ok": details["microsoft_connect_test"]["ok"],
        "google_204_ok": details["google_generate_204"]["ok"],
        "firefox_ok": details["firefox_success"]["ok"],
        "probe_passed": passed,
        "internet_healthy": passed == len(PROBES),
        "alive": passed > 0,
        "classification": "active" if passed == len(PROBES) else ("backup" if passed > 0 else "failed"),
        "delay_ms": min(delays) if delays else -1,
        "details": details,
    }


def scan_batch(root: Path, batch: list[dict], batch_no: int, total_batches: int, results: list[dict], failures: list[dict]) -> None:
    local = [{**item, "port": BASE_PORT + i} for i, item in enumerate(batch)]
    included, batch_failures = validate_batch(root, local)
    failures.extend(batch_failures)
    if not included:
        print(f"INFO real_batch={batch_no}/{total_batches} included=0")
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
                future_map = {executor.submit(probe, item, TIMEOUT): item for item in included}
                done = 0
                for future in as_completed(future_map):
                    item = future_map[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {"index": item["index"], "probe_passed": 0, "msft_ok": False, "google_204_ok": False, "firefox_ok": False, "internet_healthy": False, "alive": False, "classification": "failed", "delay_ms": -1, "details": {"exception": str(exc)[:180]}}
                    results.append(result)
                    done += 1
                    if done % 500 == 0 or done == len(included):
                        active = sum(1 for r in results if r.get("classification") == "active")
                        backup = sum(1 for r in results if r.get("classification") == "backup")
                        print(f"INFO real_batch_progress={batch_no}/{total_batches} nodes={done}/{len(included)} active={active} backup={backup}")
        finally:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()


def resolve_and_group(items: list[dict]):
    if not items:
        return {"hostname": 0, "geoip_local": 0, "unknown": 0, "database_loaded": False}, []
    rows = [{k: v for k, v in item.items() if k not in {"node", "result"}} for item in items]
    resolution = country_resolver.resolve_rows(rows)
    for item, row in zip(items, rows):
        item["country"] = row.get("country") or "UNKNOWN"
        item["country_resolution"] = row.get("country_resolution") or "unknown"
        item["country_resolution_confidence"] = row.get("country_resolution_confidence")
    return resolution, items


def publish(active: list[dict], backup: list[dict], resolution: dict, stats: dict):
    import pycountry
    countries_dir = OUT / "countries"
    protocols_dir = OUT / "protocols"
    active_dir = OUT / "active"
    backup_dir = OUT / "backup"
    global_dir = OUT / "global"
    meta_dir = OUT / "metadata"
    for directory in (countries_dir, protocols_dir, active_dir, backup_dir, global_dir, meta_dir):
        directory.mkdir(parents=True, exist_ok=True)
    for directory in (countries_dir, protocols_dir, active_dir, backup_dir):
        for path in directory.glob("*.txt"):
            path.unlink()
    for path in global_dir.glob("*.txt"):
        path.unlink()

    iso_codes = {c.alpha_2.upper() for c in pycountry.countries}
    grouped = {"active": {}, "backup": {}}
    unknown = {"active": [], "backup": []}
    for kind, items in (("active", active), ("backup", backup)):
        items.sort(key=lambda x: (x.get("result", {}).get("delay_ms", 10**9), x.get("index", 10**9), x.get("uri", "")))
        for item in items:
            code = str(item.get("country") or "UNKNOWN").upper()
            if code in iso_codes:
                grouped[kind].setdefault(code, []).append(item)
            else:
                unknown[kind].append(item)

    target_codes = sorted(set(grouped["active"]) | set(grouped["backup"]))
    for code in target_codes:
        active_rows = grouped["active"].get(code, [])
        backup_rows = grouped["backup"].get(code, [])
        combined = active_rows + backup_rows
        (countries_dir / f"{code}.txt").write_text("\n".join(x["uri"] for x in combined) + ("\n" if combined else ""), encoding="utf-8")
        (active_dir / f"{code}.txt").write_text("\n".join(x["uri"] for x in active_rows) + ("\n" if active_rows else ""), encoding="utf-8")
        (backup_dir / f"{code}.txt").write_text("\n".join(x["uri"] for x in backup_rows) + ("\n" if backup_rows else ""), encoding="utf-8")

    if unknown["active"]:
        (global_dir / "active-unknown.txt").write_text("\n".join(x["uri"] for x in unknown["active"]) + "\n", encoding="utf-8")
    if unknown["backup"]:
        (global_dir / "backup-unknown.txt").write_text("\n".join(x["uri"] for x in unknown["backup"]) + "\n", encoding="utf-8")

    protocol_rows = {}
    for kind in ("active", "backup"):
        for code in target_codes:
            for item in grouped[kind].get(code, []):
                protocol = str(item.get("protocol") or item.get("node", {}).get("scheme") or "").lower()
                if protocol:
                    protocol_rows.setdefault(protocol, []).append(item["uri"])
    for protocol, lines in protocol_rows.items():
        (protocols_dir / f"{protocol}.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    country_counts = {code: {"active": len(grouped["active"].get(code, [])), "backup": len(grouped["backup"].get(code, [])), "total": len(grouped["active"].get(code, [])) + len(grouped["backup"].get(code, []))} for code in target_codes}
    metadata = {
        "schema": 9,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tcp_reachable_total": stats["pool_total"],
        "xray_included": stats["included"],
        "config_conversion_failed": stats["config_conversion_failed"],
        "active": len(active),
        "backup": len(backup),
        "failed_after_core": stats["failed"],
        "healthy": len(active),
        "published_total": len(active) + len(backup),
        "countries": len(target_codes),
        "published_by_country": country_counts,
        "country_names": {code: pycountry.countries.get(alpha_2=code).name for code in target_codes},
        "allowed_ports": [80, 443],
        "health_policy": "Core-driven real traffic: Xray SOCKS5 plus three HTTP probes (Microsoft 200, Google 204, Firefox 200). 3/3=ACTIVE, 1-2/3=BACKUP, 0/3=FAILED.",
        "ranking_policy": "ACTIVE first by measured delay, then BACKUP by measured delay; country files preserve that order.",
        "country_policy": "Automatic country resolution from successful nodes only; no fixed country allowlist.",
        "country_resolution": resolution,
    }
    (meta_dir / "index.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (meta_dir / "health.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (meta_dir / "countries.json").write_text(json.dumps({"countries": [{"code": code, "name": metadata["country_names"][code], "nodes": country_counts[code]["total"], "active": country_counts[code]["active"], "backup": country_counts[code]["backup"]} for code in target_codes]}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    if not XRAY.exists():
        raise SystemExit(f"Xray binary not found: {XRAY}")
    pool = real_delay.load_pool()
    if not pool:
        raise SystemExit("No TCP-reachable nodes available")
    print(f"INFO real_scan_pool={len(pool)} workers={WORKERS} batch_size={BATCH_SIZE} timeout={TIMEOUT}s probes=3 mode=core_driven_active_backup")
    started = time.perf_counter()
    results: list[dict] = []
    failures: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="real-delay-") as td:
        root = Path(td)
        for offset in range(0, len(pool), BATCH_SIZE):
            batch_no = offset // BATCH_SIZE + 1
            batch = [{**row, "index": offset + i} for i, row in enumerate(pool[offset:offset + BATCH_SIZE])]
            scan_batch(root, batch, batch_no, (len(pool) + BATCH_SIZE - 1) // BATCH_SIZE, results, failures)

    by_index = {r["index"]: r for r in results}
    active, backup = [], []
    failed = 0
    for index, item in enumerate(pool):
        result = by_index.get(index)
        if not result:
            failed += 1
            continue
        item2 = {**item, "result": result, "index": index}
        if result.get("classification") == "active":
            active.append(item2)
        elif result.get("classification") == "backup":
            backup.append(item2)
        else:
            failed += 1

    publishable = active + backup
    resolution, publishable = resolve_and_group(publishable)
    active = [x for x in publishable if x["result"].get("classification") == "active"]
    backup = [x for x in publishable if x["result"].get("classification") == "backup"]
    stats = {"pool_total": len(pool), "included": len(results), "config_conversion_failed": len(failures), "failed": failed, "workers": WORKERS, "timeout_s": TIMEOUT, "batch_size": BATCH_SIZE}
    print(f"INFO real_scan_done pool={len(pool)} included={len(results)} config_conversion_failed={len(failures)} active={len(active)} backup={len(backup)} failed={failed} published={len(active)+len(backup)} elapsed_s={time.perf_counter()-started:.1f}")
    publish(active, backup, resolution, stats)
    report = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **stats, "active": len(active), "backup": len(backup), "published_total": len(active) + len(backup), "health_policy": "Core-driven real traffic through Xray with three HTTP probes; 3/3 ACTIVE, 1-2/3 BACKUP, 0/3 FAILED.", "nodes": [{**{k: v for k, v in item.items() if k != "node"}, "result": item["result"]} for item in active + backup], "config_failures": failures}
    (OUT / "metadata" / "real_delay.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
