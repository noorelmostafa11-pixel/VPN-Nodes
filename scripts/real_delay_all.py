#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import socket
import ssl
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote

import benchmark_engines_v2 as base
from real_delay import protocol, node_country

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
XRAY = Path(os.environ.get("XRAY_BIN", "/opt/hostedtoolcache/xray/xray"))
WORKERS = int(os.environ.get("REAL_DELAY_WORKERS", "128"))
NODE_TIMEOUT = float(os.environ.get("REAL_DELAY_NODE_TIMEOUT", "6"))
SOCKS_BASE_PORT = int(os.environ.get("REAL_DELAY_SOCKS_BASE", "21000"))

PROBES = (
    {"name": "google_generate_204", "host": "www.gstatic.com", "path": "/generate_204", "tls": True, "status": 204},
    {"name": "microsoft_connect_test", "host": "www.msftconnecttest.com", "path": "/connecttest.txt", "tls": False, "status": 200, "body": b"Microsoft Connect Test"},
)


def load_pool() -> list[dict]:
    rows: dict[str, dict] = {}
    for path in sorted((OUT / "countries").glob("*.txt")):
        country = path.stem.upper()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            uri = line.strip()
            if not uri or not uri.lower().startswith(("vless://", "vmess://", "trojan://", "ss://")):
                continue
            key = hashlib.sha256(uri.encode("utf-8")).hexdigest()
            rows.setdefault(key, {"uri": uri, "country": country, "protocol": protocol(uri)})
    for path in sorted((OUT / "protocols").glob("*.txt")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            uri = line.strip()
            if not uri or not uri.lower().startswith(("vless://", "vmess://", "trojan://", "ss://")):
                continue
            key = hashlib.sha256(uri.encode("utf-8")).hexdigest()
            rows.setdefault(key, {"uri": uri, "country": node_country(uri), "protocol": protocol(uri)})
    return list(rows.values())


def wait_port(port: int, timeout: float = 15.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def socks5_http(port: int, host: str, path: str, use_tls: bool, expected_status: int, expected_body: bytes | None) -> tuple[bool, float, str]:
    started = time.perf_counter()
    s = socket.create_connection(("127.0.0.1", port), timeout=NODE_TIMEOUT)
    s.settimeout(NODE_TIMEOUT)
    try:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return False, -1, "socks-auth"
        hb = host.encode("idna")
        remote_port = 443 if use_tls else 80
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + remote_port.to_bytes(2, "big"))
        head = s.recv(4)
        if len(head) != 4 or head[1] != 0:
            return False, -1, "socks-connect"
        if head[3] == 1:
            s.recv(4)
        elif head[3] == 3:
            n = s.recv(1)[0]
            s.recv(n)
        elif head[3] == 4:
            s.recv(16)
        s.recv(2)
        conn = s
        if use_tls:
            conn = ssl.create_default_context().wrap_socket(s, server_hostname=host)
        conn.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: AhmedVPN-RealDelay-All/1\r\n\r\n".encode())
        data = bytearray()
        while len(data) < 16384:
            chunk = conn.recv(min(4096, 16384 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        raw = bytes(data)
        first = raw.split(b"\r\n", 1)[0]
        parts = first.split()
        if len(parts) < 2 or not parts[1].isdigit():
            return False, -1, "invalid-http"
        status = int(parts[1])
        if status != expected_status:
            return False, -1, f"unexpected-status-{status}"
        if expected_body is not None and expected_body not in raw:
            return False, -1, "expected-body-missing"
        return True, round((time.perf_counter() - started) * 1000, 1), f"HTTP {status}"
    except Exception as exc:
        return False, -1, str(exc)[:180]
    finally:
        try:
            s.close()
        except Exception:
            pass


def probe_one(idx: int, port: int) -> dict:
    out = {"index": idx, "msft_ok": False, "google_204_ok": False, "internet_healthy": False, "delay_ms": -1, "details": {}}
    delays: list[float] = []
    for p in PROBES:
        ok, delay, detail = socks5_http(port, p["host"], p["path"], p["tls"], p["status"], p.get("body"))
        out["details"][p["name"]] = detail
        if p["name"] == "microsoft_connect_test":
            out["msft_ok"] = ok
        else:
            out["google_204_ok"] = ok
        if ok:
            delays.append(delay)
    out["internet_healthy"] = out["msft_ok"] and out["google_204_ok"]
    if delays:
        out["delay_ms"] = min(delays)
    return out


def main() -> None:
    if not XRAY.exists():
        raise SystemExit(f"Xray binary not found: {XRAY}")
    pool = load_pool()
    if not pool:
        raise SystemExit("No nodes available for real-delay scan")
    print(f"INFO real_delay_pool={len(pool)} selected={len(pool)} workers={WORKERS} mode=single-long-lived-xray")

    start = time.perf_counter()
    failed_conversion: list[dict] = []
    included: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="real-delay-all-") as td:
        inbounds = []
        outbounds = []
        rules = []
        for idx, item in enumerate(pool):
            tag = f"node-{idx + 1}"
            try:
                outbound = base.xray_outbound(item["uri"], tag)
                outbounds.append(outbound)
                port = SOCKS_BASE_PORT + idx
                inbound_tag = f"in-{idx + 1}"
                inbounds.append({
                    "listen": "127.0.0.1",
                    "port": port,
                    "protocol": "socks",
                    "settings": {"udp": False},
                    "tag": inbound_tag,
                })
                rules.append({"type": "field", "inboundTag": [inbound_tag], "outboundTag": tag})
                included.append({**item, "index": idx, "port": port})
            except Exception as exc:
                failed_conversion.append({"index": idx, "reason": str(exc)[:500]})

        cfg = Path(td) / "config.json"
        cfg.write_text(json.dumps({
            "log": {"loglevel": "error"},
            "inbounds": inbounds,
            "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules},
        }, ensure_ascii=False), encoding="utf-8")

        chk = subprocess.run([str(XRAY), "-test", "-config", str(cfg)], text=True, capture_output=True, timeout=60)
        if chk.returncode != 0:
            raise SystemExit("Xray multi-outbound config rejected: " + (chk.stderr or chk.stdout)[-3000:])

        proc = subprocess.Popen([str(XRAY), "run", "-c", str(cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if included and not wait_port(included[0]["port"], 20):
                raise SystemExit("Xray multi-outbound process did not open the first inbound")

            results: list[dict] = []
            with ThreadPoolExecutor(max_workers=WORKERS) as executor:
                futures = {executor.submit(probe_one, item["index"], item["port"]): item for item in included}
                for n, future in enumerate(as_completed(futures), 1):
                    try:
                        result = future.result()
                    except Exception as exc:
                        item = futures[future]
                        result = {"index": item["index"], "msft_ok": False, "google_204_ok": False, "internet_healthy": False, "delay_ms": -1, "details": {"exception": str(exc)[:180]}}
                    results.append(result)
                    if n % 250 == 0 or n == len(included):
                        healthy = sum(int(r["internet_healthy"]) for r in results)
                        alive = sum(int(r["msft_ok"] or r["google_204_ok"]) for r in results)
                        print(f"INFO real_delay_progress={n}/{len(included)} alive={alive} internet_healthy={healthy}")
        finally:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()

    by_index = {r["index"]: r for r in results}
    final_results = []
    for item in pool:
        idx = item["index"] if "index" in item else None
        if idx is not None and idx in by_index:
            final_results.append({**item, **by_index[idx]})
    final_results.sort(key=lambda r: (
        r["country"],
        0 if r["internet_healthy"] else 1,
        0 if (r["msft_ok"] or r["google_204_ok"]) else 1,
        r["delay_ms"] if r["delay_ms"] > 0 else 10**9,
        r["protocol"],
        r["uri"],
    ))

    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out = OUT / "metadata" / "real_delay.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": 3,
        "generated_at": generated_at,
        "test": {
            "engine": "Xray",
            "mode": "single_long_lived_process_multi_outbound",
            "probes": [dict(p) for p in PROBES],
            "candidates": len(pool),
            "compatible": len(included),
            "config_conversion_failed": failed_conversion,
            "workers": WORKERS,
            "timeout_s": NODE_TIMEOUT,
        },
        "alive": sum(1 for r in final_results if r["msft_ok"] or r["google_204_ok"]),
        "internet_healthy": sum(1 for r in final_results if r["internet_healthy"]),
        "dead": sum(1 for r in final_results if not (r["msft_ok"] or r["google_204_ok"])),
        "elapsed_s": round(time.perf_counter() - start, 2),
        "results": final_results,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "selected": len(pool),
        "compatible": len(included),
        "config_conversion_failed": len(failed_conversion),
        "alive": payload["alive"],
        "internet_healthy": payload["internet_healthy"],
        "dead": payload["dead"],
        "elapsed_s": payload["elapsed_s"],
        "workers": WORKERS,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
