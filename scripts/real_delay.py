#!/usr/bin/env python3
"""Full-pool Internet health scan using one long-lived Xray process.

Input: output/countries/*.txt produced from the complete TCP-reachable pool.
No production candidate limit is applied. Every unique reachable URI is converted
into one Xray outbound + one local SOCKS inbound and probed in parallel.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
XRAY = Path(os.environ.get("XRAY_BIN", "/opt/hostedtoolcache/xray/xray"))
WORKERS = int(os.environ.get("REAL_DELAY_WORKERS", "256"))
NODE_TIMEOUT = float(os.environ.get("REAL_DELAY_NODE_TIMEOUT", "5"))
BASE_PORT = int(os.environ.get("REAL_DELAY_SOCKS_BASE", "21000"))
PROBES = (
    {"name": "microsoft_connect_test", "host": "www.msftconnecttest.com", "path": "/connecttest.txt", "tls": False, "status": 200, "body": b"Microsoft Connect Test"},
    {"name": "google_generate_204", "host": "www.gstatic.com", "path": "/generate_204", "tls": True, "status": 204, "body": None},
)


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def q(uri: str) -> dict[str, list[str]]:
    return urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query, keep_blank_values=True)


def first(params, *keys, default="") -> str:
    for key in keys:
        if params.get(key):
            return urllib.parse.unquote(params[key][0])
    return default


def scheme(uri: str) -> str:
    return urllib.parse.urlsplit(uri).scheme.lower()


def parse_uri(uri: str) -> dict:
    s = scheme(uri)
    p = urllib.parse.urlsplit(uri)
    params = q(uri)
    if s == "vmess":
        raw = uri.split("vmess://", 1)[1].split("#", 1)[0]
        obj = json.loads(b64d(raw).decode("utf-8"))
        return {"scheme": s, "server": obj.get("add") or obj.get("address"), "port": int(obj.get("port")),
                "uuid": obj.get("id"), "network": str(obj.get("net") or "tcp").lower(),
                "path": obj.get("path") or "/", "host": obj.get("host") or "",
                "tls": str(obj.get("tls") or "").lower() not in ("", "none", "false", "0"),
                "reality": False, "sni": obj.get("sni") or obj.get("host") or obj.get("add") or obj.get("address"),
                "alter_id": int(obj.get("aid", 0) or 0), "cipher": obj.get("scy") or "auto"}
    if s == "vless":
        return {"scheme": s, "server": p.hostname, "port": p.port or 443, "uuid": urllib.parse.unquote(p.username or ""),
                "network": first(params, "type", default="tcp").lower(), "path": first(params, "path", default="/"),
                "host": first(params, "host"), "tls": first(params, "security") == "tls", "reality": first(params, "security") == "reality",
                "sni": first(params, "sni", "serverName", default=p.hostname), "fp": first(params, "fp", default="chrome"),
                "pbk": first(params, "pbk"), "sid": first(params, "sid"), "service_name": first(params, "serviceName"),
                "authority": first(params, "authority")}
    if s == "trojan":
        return {"scheme": s, "server": p.hostname, "port": p.port or 443, "password": urllib.parse.unquote(p.username or ""),
                "network": first(params, "type", default="tcp").lower(), "path": first(params, "path", default="/"),
                "host": first(params, "host"), "sni": first(params, "sni", default=p.hostname),
                "service_name": first(params, "serviceName")}
    if s == "ss":
        raw = uri.split("ss://", 1)[1].split("#", 1)[0]
        if "@" in raw:
            ui, hp = raw.rsplit("@", 1)
            try:
                ui = b64d(ui).decode("utf-8")
            except Exception:
                ui = urllib.parse.unquote(ui)
        else:
            decoded = b64d(raw).decode("utf-8")
            ui, hp = decoded.rsplit("@", 1)
        if "?" in hp:
            hp = hp.split("?", 1)[0]
        if "/" in hp:
            hp = hp.split("/", 1)[0]
        if hp.startswith("["):
            host, port = hp.rsplit("]:", 1); host = host[1:]
        else:
            host, port = hp.rsplit(":", 1)
        method, password = urllib.parse.unquote(ui).split(":", 1)
        return {"scheme": s, "server": host, "port": int(port), "method": method, "password": password}
    raise ValueError(f"unsupported scheme: {s}")


def xray_outbound(node: dict, tag: str) -> dict:
    s = node["scheme"]
    if s == "vless":
        stream = {"network": node["network"], "security": "none"}
        if node["network"] == "ws":
            stream["wsSettings"] = {"path": node.get("path") or "/", "headers": {"Host": node.get("host") or ""}}
        elif node["network"] == "grpc":
            stream["grpcSettings"] = {"serviceName": node.get("service_name") or "", "authority": node.get("authority") or ""}
        if node.get("tls"):
            stream["security"] = "tls"; stream["tlsSettings"] = {"serverName": node.get("sni") or node["server"]}
            if node.get("fp"): stream["tlsSettings"]["fingerprint"] = node["fp"]
        elif node.get("reality"):
            stream["security"] = "reality"; stream["realitySettings"] = {"serverName": node.get("sni") or node["server"], "fingerprint": node.get("fp") or "chrome", "publicKey": node.get("pbk") or "", "shortId": node.get("sid") or "", "spiderX": "/"}
        return {"protocol": "vless", "tag": tag, "settings": {"vnext": [{"address": node["server"], "port": node["port"], "users": [{"id": node["uuid"], "encryption": "none"}]}]}, "streamSettings": stream}
    if s == "vmess":
        stream = {"network": node["network"], "security": "none"}
        if node["network"] == "ws": stream["wsSettings"] = {"path": node.get("path") or "/", "headers": {"Host": node.get("host") or ""}}
        if node.get("tls"): stream["security"] = "tls"; stream["tlsSettings"] = {"serverName": node.get("sni") or node["server"]}
        return {"protocol": "vmess", "tag": tag, "settings": {"vnext": [{"address": node["server"], "port": node["port"], "users": [{"id": node["uuid"], "alterId": node.get("alter_id", 0), "security": node.get("cipher", "auto")}]}]}, "streamSettings": stream}
    if s == "trojan":
        stream = {"network": node["network"], "security": "tls", "tlsSettings": {"serverName": node.get("sni") or node["server"]}}
        if node["network"] == "ws": stream["wsSettings"] = {"path": node.get("path") or "/", "headers": {"Host": node.get("host") or ""}}
        elif node["network"] == "grpc": stream["grpcSettings"] = {"serviceName": node.get("service_name") or ""}
        return {"protocol": "trojan", "tag": tag, "settings": {"servers": [{"address": node["server"], "port": node["port"], "password": node["password"]}]}, "streamSettings": stream}
    if s == "ss":
        return {"protocol": "shadowsocks", "tag": tag, "settings": {"servers": [{"address": node["server"], "port": node["port"], "method": node["method"], "password": node["password"]}]}}
    raise ValueError(s)


def load_pool() -> list[dict]:
    rows: dict[str, dict] = {}
    countries = OUT / "countries"
    if not countries.exists():
        raise SystemExit("Missing output/countries directory")
    for path in sorted(countries.glob("*.txt")):
        country = path.stem.upper()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            uri = line.strip()
            if not uri or not uri.lower().startswith(("vless://", "vmess://", "trojan://", "ss://")):
                continue
            try:
                node = parse_uri(uri)
                if node.get("port") not in {80, 443}: continue
            except Exception:
                continue
            key = hashlib.sha256(uri.encode("utf-8")).hexdigest()
            rows.setdefault(key, {"uri": uri, "country": country, "protocol": "shadowsocks" if scheme(uri) == "ss" else scheme(uri), "node": node})
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


def socks_http(port: int, host: str, path: str, use_tls: bool, expected_status: int, expected_body: bytes | None) -> tuple[bool, float, str]:
    started = time.perf_counter()
    s = socket.create_connection(("127.0.0.1", port), timeout=NODE_TIMEOUT); s.settimeout(NODE_TIMEOUT)
    try:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00": return False, -1, "socks-auth"
        hb = host.encode("idna"); remote_port = 443 if use_tls else 80
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + remote_port.to_bytes(2, "big"))
        h = s.recv(4)
        if len(h) != 4 or h[1] != 0: return False, -1, "socks-connect"
        if h[3] == 1: s.recv(4)
        elif h[3] == 3: s.recv(s.recv(1)[0])
        elif h[3] == 4: s.recv(16)
        s.recv(2)
        conn = s
        if use_tls: conn = ssl.create_default_context().wrap_socket(s, server_hostname=host)
        conn.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: AhmedVPN-RealDelay/3\r\n\r\n".encode())
        data = bytearray()
        while len(data) < 16384:
            chunk = conn.recv(min(4096, 16384 - len(data)))
            if not chunk: break
            data.extend(chunk)
        raw = bytes(data); first = raw.split(b"\r\n", 1)[0]
        m = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", first)
        if not m: return False, -1, "no-http"
        status = int(m.group(1))
        if status != expected_status: return False, -1, f"unexpected-status-{status}"
        if expected_body is not None and expected_body not in raw: return False, -1, "expected-body-missing"
        return True, round((time.perf_counter() - started) * 1000, 1), f"HTTP {status}"
    finally:
        try: s.close()
        except Exception: pass


def build_config(items: list[dict], root: Path) -> tuple[Path, list[dict], list[dict]]:
    inbounds: list[dict] = []; outbounds: list[dict] = []; rules: list[dict] = []; included: list[dict] = []; failures: list[dict] = []
    for idx, item in enumerate(items):
        tag = f"node-{idx + 1}"; inbound_tag = f"in-{idx + 1}"; port = BASE_PORT + idx
        try:
            outbounds.append(xray_outbound(item["node"], tag))
            inbounds.append({"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": False}, "tag": inbound_tag})
            rules.append({"type": "field", "inboundTag": [inbound_tag], "outboundTag": tag})
            included.append({**item, "index": idx, "port": port})
        except Exception as exc:
            failures.append({"index": idx, "uri": item["uri"], "reason": str(exc)[:500], "classification": "config_conversion_failed"})
    cfg = root / "xray.json"
    cfg.write_text(json.dumps({"log": {"loglevel": "error"}, "inbounds": inbounds, "outbounds": outbounds, "routing": {"domainStrategy": "AsIs", "rules": rules}}, ensure_ascii=False), encoding="utf-8")
    return cfg, included, failures


def probe_one(item: dict) -> dict:
    details = {}; ok_flags = []
    for probe in PROBES:
        try: ok, latency, detail = socks_http(item["port"], probe["host"], probe["path"], probe["tls"], probe["status"], probe["body"])
        except Exception as exc: ok, latency, detail = False, -1, str(exc)[:180]
        details[probe["name"]] = detail; ok_flags.append(ok)
    return {"index": item["index"], "msft_ok": ok_flags[0], "google_204_ok": ok_flags[1], "internet_healthy": all(ok_flags), "delay_ms": min([x for x, ok in zip([_latency(details.get(PROBES[0]["name"])), _latency(details.get(PROBES[1]["name"]))], ok_flags) if ok] or [-1]), "details": details}


def _latency(_: str | None) -> float:
    return 10**9


def main() -> None:
    ap = argparse.ArgumentParser(); ap.add_argument("--workers", type=int, default=WORKERS); ap.add_argument("--timeout", type=float, default=NODE_TIMEOUT); args = ap.parse_args()
    global WORKERS, NODE_TIMEOUT
    WORKERS = max(1, args.workers); NODE_TIMEOUT = max(0.5, args.timeout)
    if not XRAY.exists(): raise SystemExit(f"Xray binary not found: {XRAY}")
    pool = load_pool()
    if not pool: raise SystemExit("No reachable nodes available for Xray health scan")
    start = time.perf_counter(); print(f"INFO real_delay_pool={len(pool)} selected={len(pool)} workers={WORKERS} mode=single-long-lived-xray")
    results: list[dict] = []; failures: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="real-delay-") as td:
        cfg, included, failures = build_config(pool, Path(td))
        check = subprocess.run([str(XRAY), "-test", "-config", str(cfg)], text=True, capture_output=True, timeout=120)
        if check.returncode != 0:
            raise SystemExit("Xray multi-outbound config rejected: " + (check.stderr or check.stdout)[-4000:])
        proc = subprocess.Popen([str(XRAY), "run", "-c", str(cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if included and not wait_port(included[0]["port"], 20): raise SystemExit("Xray process did not open first inbound")
            with ThreadPoolExecutor(max_workers=WORKERS) as executor:
                futures = {executor.submit(probe_one, item): item for item in included}
                for n, future in enumerate(as_completed(futures), 1):
                    item = futures[future]
                    try: result = future.result()
                    except Exception as exc: result = {"index": item["index"], "msft_ok": False, "google_204_ok": False, "internet_healthy": False, "delay_ms": -1, "details": {"exception": str(exc)[:180]}}
                    results.append(result)
                    if n % 500 == 0 or n == len(included): print(f"INFO real_delay_progress={n}/{len(included)} alive={sum(1 for r in results if r['msft_ok'] or r['google_204_ok'])} healthy={sum(1 for r in results if r['internet_healthy'])}")
        finally:
            proc.terminate()
            try: proc.wait(5)
            except subprocess.TimeoutExpired: proc.kill()
    by_index = {r["index"]: r for r in results}
    output: list[dict] = []
    for idx, item in enumerate(pool):
        r = by_index.get(idx)
        if r is None: output.append({**item, "internet_healthy": False, "delay_ms": -1, "details": {"config_conversion_failed": next((x["reason"] for x in failures if x["index"] == idx), "not-tested")}})
        else: output.append({k: v for k, v in {**item, **r}.items() if k != "node"})
    output.sort(key=lambda r: (r["country"], 0 if r["internet_healthy"] else 1, r["delay_ms"] if r["delay_ms"] > 0 else 10**9, r["protocol"], r["uri"]))
    metadata = OUT / "metadata"; metadata.mkdir(parents=True, exist_ok=True)
    alive = sum(1 for r in output if r.get("msft_ok") or r.get("google_204_ok")); healthy = sum(1 for r in output if r.get("internet_healthy"))
    (metadata / "real_delay.json").write_text(json.dumps({"schema": 4, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "engine": "Xray", "mode": "single_long_lived_process_multi_outbound", "candidates": len(pool), "compatible": len(included), "config_conversion_failed": len(failures), "alive": alive, "internet_healthy": healthy, "dead": len(output)-alive, "workers": WORKERS, "timeout_s": NODE_TIMEOUT, "elapsed_s": round(time.perf_counter()-start, 2), "results": output}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"selected": len(pool), "compatible": len(included), "config_conversion_failed": len(failures), "alive": alive, "internet_healthy": healthy, "dead": len(output)-alive, "workers": WORKERS, "elapsed_s": round(time.perf_counter()-start, 2)}))


if __name__ == "__main__": main()
