#!/usr/bin/env python3
from __future__ import annotations

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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
XRAY = Path(os.environ.get("XRAY_BIN", "/opt/hostedtoolcache/xray/xray"))
MAX_REAL_DELAY_CANDIDATES = int(os.environ.get("REAL_DELAY_CANDIDATES", "3200"))
WORKERS = int(os.environ.get("REAL_DELAY_WORKERS", "32"))
NODE_TIMEOUT = float(os.environ.get("REAL_DELAY_NODE_TIMEOUT", "6.0"))
SOCKS_BASE_PORT = int(os.environ.get("REAL_DELAY_SOCKS_BASE", "21000"))
HEALTH_PROBES = (
    {"name": "google_generate_204", "host": "www.gstatic.com", "path": "/generate_204", "tls": True, "status": {204}},
    {"name": "microsoft_connect_test", "host": "www.msftconnecttest.com", "path": "/connecttest.txt", "tls": False, "status": {200}, "body": b"Microsoft Connect Test"},
)
ALIASES = {
    "uk":"GB","england":"GB","greatbritain":"GB","unitedkingdom":"GB","uae":"AE","emirates":"AE","unitedarabemirates":"AE","usa":"US","america":"US","unitedstates":"US","southkorea":"KR","korea":"KR","russia":"RU","iran":"IR","taiwan":"TW","japan":"JP","singapore":"SG","seychelles":"SC","germany":"DE","france":"FR","canada":"CA","australia":"AU","austria":"AT","netherlands":"NL","poland":"PL","slovenia":"SI","turkey":"TR","turkiye":"TR","hongkong":"HK","finland":"FI","sweden":"SE","denmark":"DK","bulgaria":"BG","azerbaijan":"AZ","china":"CN","estonia":"EE","czechrepublic":"CZ","czechia":"CZ","southafrica":"ZA","newzealand":"NZ","saudiarabia":"SA",
}

def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

def scheme(uri: str) -> str: return uri.split(":", 1)[0].lower()
def query(uri: str): return parse_qs(urlparse(uri).query, keep_blank_values=True)
def first(q, *keys, default=""):
    for k in keys:
        if q.get(k): return unquote(q[k][0])
    return default

def protocol(uri: str) -> str:
    s = scheme(uri)
    return "shadowsocks" if s == "ss" else s

def node_country(uri: str, fallback: str = "UNKNOWN") -> str:
    frag = unquote(urlparse(uri).fragment or "")
    compact = re.sub(r"[^a-z0-9]+", "", frag.lower())
    for token, code in ALIASES.items():
        if token in compact: return code
    for code in re.findall(r"(?<![A-Za-z0-9])([A-Z]{2})(?![A-Za-z0-9])", frag):
        if code.upper() not in {"WS", "SS", "TLS"}: return code.upper()
    return fallback

def load_pool():
    rows = {}
    for path in sorted((OUT / "countries").glob("*.txt")):
        country = path.stem.upper()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            uri = line.strip()
            if uri:
                rows.setdefault(hashlib.sha256(uri.encode()).hexdigest(), {"uri": uri, "country": country, "protocol": protocol(uri)})
    for path in sorted((OUT / "protocols").glob("*.txt")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            uri = line.strip()
            if uri:
                rows.setdefault(hashlib.sha256(uri.encode()).hexdigest(), {"uri": uri, "country": node_country(uri), "protocol": protocol(uri)})
    return list(rows.values())

def quota_select(pool):
    by_country = {}
    for item in pool: by_country.setdefault(item["country"], []).append(item)
    countries = sorted(by_country)
    if not pool: return []
    quotas = {c: max(1, int(MAX_REAL_DELAY_CANDIDATES * len(by_country[c]) / len(pool))) for c in countries}
    while sum(quotas.values()) > MAX_REAL_DELAY_CANDIDATES:
        c = max(quotas, key=lambda x: (quotas[x], len(by_country[x])))
        if quotas[c] <= 1: break
        quotas[c] -= 1
    while sum(quotas.values()) < min(MAX_REAL_DELAY_CANDIDATES, len(pool)):
        c = max(countries, key=lambda x: len(by_country[x]) - quotas[x])
        if quotas[c] >= len(by_country[c]): break
        quotas[c] += 1
    chosen = []
    for country in countries:
        items = by_country[country]; q = min(quotas[country], len(items))
        if q == len(items): chosen.extend(items); continue
        step = len(items) / q
        idxs = sorted({min(len(items)-1, int(i * step)) for i in range(q)})
        if 0 not in idxs: idxs[0] = 0
        chosen.extend(items[i] for i in idxs[:q])
    return chosen[:MAX_REAL_DELAY_CANDIDATES]

def vless_outbound(uri: str):
    p = urlparse(uri); q = query(uri); user = p.username or ""
    settings = {"vnext": [{"address": p.hostname, "port": p.port, "users": [{"id": unquote(user), "encryption": first(q, "encryption", default="none")}]}]}
    flow = first(q, "flow")
    if flow: settings["vnext"][0]["users"][0]["flow"] = flow
    stream = {"network": first(q, "type", default="tcp")}; sec = first(q, "security", default="none"); stream["security"] = sec
    net = stream["network"]
    if net == "ws": stream["wsSettings"] = {"path": first(q, "path", default="/"), "headers": {"Host": first(q, "host")}}
    elif net == "grpc": stream["grpcSettings"] = {"serviceName": first(q, "serviceName"), "authority": first(q, "authority")}
    elif net == "xhttp": stream["xhttpSettings"] = {"path": first(q, "path", default="/"), "mode": first(q, "mode", default="auto"), "host": first(q, "host")}
    if sec == "tls":
        tls = {"serverName": first(q, "sni", "serverName", default=p.hostname)}; fp = first(q, "fp"); alpn = first(q, "alpn")
        if fp: tls["fingerprint"] = fp
        if alpn: tls["alpn"] = [x for x in alpn.split(",") if x]
        stream["tlsSettings"] = tls
    elif sec == "reality": stream["realitySettings"] = {"serverName": first(q, "sni", "serverName", default=p.hostname), "fingerprint": first(q, "fp", default="chrome"), "publicKey": first(q, "pbk"), "shortId": first(q, "sid"), "spiderX": first(q, "spx", default="/")}
    return {"protocol": "vless", "settings": settings, "streamSettings": stream}

def vmess_outbound(uri: str):
    raw = uri.split("vmess://", 1)[1].split("#", 1)[0]
    try: obj = json.loads(b64d(raw).decode("utf-8"))
    except Exception:
        p = urlparse(uri); q = query(uri); obj = {"add": p.hostname, "port": p.port, "id": p.username or "", "net": first(q, "type", default="tcp"), "path": first(q, "path", default="/"), "host": first(q, "host"), "tls": first(q, "security", default="")}
    stream = {"network": obj.get("net", "tcp") or "tcp", "security": "tls" if obj.get("tls") else "none"}
    if stream["network"] == "ws": stream["wsSettings"] = {"path": obj.get("path") or "/", "headers": {"Host": obj.get("host") or ""}}
    if stream["security"] == "tls": stream["tlsSettings"] = {"serverName": obj.get("sni") or obj.get("host") or obj.get("add")}
    return {"protocol": "vmess", "settings": {"vnext": [{"address": obj.get("add"), "port": int(obj.get("port")), "users": [{"id": obj.get("id"), "alterId": int(obj.get("aid", 0) or 0), "security": obj.get("scy", "auto")}]}]}, "streamSettings": stream}

def trojan_outbound(uri: str):
    p = urlparse(uri); q = query(uri); stream = {"network": first(q, "type", default="tcp"), "security": first(q, "security", default="tls")}
    if stream["network"] == "ws": stream["wsSettings"] = {"path": first(q, "path", default="/"), "headers": {"Host": first(q, "host", default="")}}
    if stream["security"] == "tls": stream["tlsSettings"] = {"serverName": first(q, "sni", default=p.hostname)}
    return {"protocol": "trojan", "settings": {"servers": [{"address": p.hostname, "port": p.port, "password": unquote(p.username or "")} ]}, "streamSettings": stream}

def _safe_b64decode(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s.encode("utf-8")).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def _decode_ss_userinfo(value: str) -> str:
    value = unquote(value)
    if ":" in value:
        return value
    decoded = _safe_b64decode(value)
    return decoded or value

def ss_outbound(uri: str):
    """Parse legacy, SIP002 and common malformed-base64 Shadowsocks URIs."""
    raw = uri.strip()
    if raw.startswith("ss://"):
        raw = raw[5:]
    if "#" in raw:
        raw = raw.split("#", 1)[0]
    if "?" in raw:
        raw = raw.split("?", 1)[0]

    if "@" not in raw:
        decoded = _safe_b64decode(raw)
        if "@" not in decoded:
            raise ValueError("invalid shadowsocks URI: cannot decode userinfo and hostport")
        userinfo, hostpart = decoded.rsplit("@", 1)
    else:
        userinfo_part, hostpart = raw.rsplit("@", 1)
        userinfo = _decode_ss_userinfo(userinfo_part)

    userinfo = unquote(userinfo)
    if ":" not in userinfo:
        raise ValueError("invalid shadowsocks URI: missing method/password separator")
    method, password = userinfo.split(":", 1)

    if "://" in hostpart:
        hostpart = hostpart.split("://", 1)[1]
    if "/" in hostpart:
        hostpart = hostpart.split("/", 1)[0]
    parsed = urlparse("//" + hostpart)
    host = parsed.hostname or ""
    port = parsed.port
    if not host or port is None:
        if hostpart.startswith("[") and "]" in hostpart:
            end = hostpart.rfind("]")
            host = hostpart[1:end]
            port = int(hostpart[end + 2:])
        else:
            if ":" not in hostpart:
                raise ValueError("invalid shadowsocks URI: missing port")
            host, port_text = hostpart.rsplit(":", 1)
            port = int(port_text)
    return {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": host.strip("[]"),
                "port": int(port),
                "method": method.strip(),
                "password": password.strip(),
                "ota": False,
            }]
        }
    }

def outbound_for(uri: str):
    s = scheme(uri)
    if s == "vless": return vless_outbound(uri)
    if s == "vmess": return vmess_outbound(uri)
    if s == "trojan": return trojan_outbound(uri)
    if s == "ss": return ss_outbound(uri)
    raise ValueError("unsupported protocol")

def socks5_http(port: int, host: str, path: str, use_tls: bool, expected_status: set[int], expected_body: bytes | None = None) -> float:
    started = time.perf_counter(); s = socket.create_connection(("127.0.0.1", port), timeout=NODE_TIMEOUT); s.settimeout(NODE_TIMEOUT)
    try:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00": raise RuntimeError("SOCKS5 auth negotiation failed")
        hb = host.encode("idna"); remote_port = 443 if use_tls else 80
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + remote_port.to_bytes(2, "big"))
        head = s.recv(4)
        if len(head) != 4 or head[1] != 0: raise RuntimeError("SOCKS5 connect failed")
        atyp = head[3]
        if atyp == 1: s.recv(4)
        elif atyp == 3: n = s.recv(1)[0]; s.recv(n)
        elif atyp == 4: s.recv(16)
        s.recv(2); conn = s
        if use_tls: conn = ssl.create_default_context().wrap_socket(s, server_hostname=host)
        conn.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: AhmedVPN-RealDelay/2\r\n\r\n".encode())
        data = bytearray()
        while len(data) < 16384:
            chunk = conn.recv(min(4096, 16384 - len(data)))
            if not chunk: break
            data.extend(chunk)
        raw = bytes(data); first_line = raw.split(b"\r\n", 1)[0]; match = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", first_line)
        if not match: raise RuntimeError("invalid HTTP response")
        status = int(match.group(1))
        if status not in expected_status: raise RuntimeError(f"unexpected HTTP status {status}")
        if expected_body is not None and expected_body not in raw: raise RuntimeError("expected NCSI body missing")
        return round((time.perf_counter() - started) * 1000, 1)
    finally:
        try: s.close()
        except Exception: pass

def test_one(item, slot):
    port = SOCKS_BASE_PORT + slot
    with tempfile.TemporaryDirectory(prefix="xray-rd-") as td:
        root = Path(td); cfg_path = root / "config.json"; log_path = root / "xray.log"
        try:
            cfg_path.write_text(json.dumps({"log": {"loglevel": "error", "access": str(log_path), "error": str(log_path)}, "inbounds": [{"listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"udp":False}}], "outbounds": [outbound_for(item["uri"])]}, ensure_ascii=False), encoding="utf-8")
            proc = subprocess.Popen([str(XRAY), "run", "-c", str(cfg_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 2.5
            while time.monotonic() < deadline:
                try:
                    test_sock = socket.create_connection(("127.0.0.1", port), timeout=0.15); test_sock.close(); break
                except OSError: time.sleep(0.08)
            else: return {**item, "delay_ms": -1, "alive": False, "internet_healthy": False, "probe_results": {}, "error": "xray_start_timeout"}
            probe_results = {}
            try:
                for probe in HEALTH_PROBES:
                    try:
                        latency = socks5_http(port, probe["host"], probe["path"], probe["tls"], probe["status"], probe.get("body")); probe_results[probe["name"]] = {"ok": True, "latency_ms": latency}
                    except Exception as exc: probe_results[probe["name"]] = {"ok": False, "error": str(exc)[:180]}
                successful = [v["latency_ms"] for v in probe_results.values() if v.get("ok")]
                return {**item, "delay_ms": min(successful) if successful else -1, "alive": bool(successful), "internet_healthy": all(v.get("ok") for v in probe_results.values()), "probe_results": probe_results}
            finally:
                proc.terminate()
                try: proc.wait(timeout=1.5)
                except subprocess.TimeoutExpired: proc.kill()
        except Exception as exc: return {**item, "delay_ms": -1, "alive": False, "internet_healthy": False, "probe_results": {}, "error": str(exc)[:180]}

def main():
    if not XRAY.exists(): raise SystemExit(f"Xray binary not found: {XRAY}")
    pool = load_pool(); candidates = quota_select(pool); print(f"INFO real_delay_pool={len(pool)} selected={len(candidates)} workers={WORKERS} probes={','.join(p['name'] for p in HEALTH_PROBES)}")
    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = {executor.submit(test_one, item, i): (item, i) for i, item in enumerate(candidates)}
        for n, future in enumerate(as_completed(futures), 1):
            result = future.result(); results.append(result)
            if n % 100 == 0 or n == len(candidates):
                alive = sum(1 for r in results if r["alive"]); healthy = sum(1 for r in results if r.get("internet_healthy")); print(f"INFO real_delay_progress={n}/{len(candidates)} alive={alive} internet_healthy={healthy}")
    results.sort(key=lambda r: (r["country"], 0 if r["internet_healthy"] else 1, 0 if r["alive"] else 1, r["delay_ms"] if r["delay_ms"] > 0 else 10**9, r["protocol"], r["uri"]))
    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()); out = OUT / "metadata" / "real_delay.json"; out.parent.mkdir(parents=True, exist_ok=True)
    payload = {"schema": 2, "generated_at": generated_at, "test": {"engine": "Xray", "probes": [dict(p) for p in HEALTH_PROBES], "candidates": len(candidates)}, "alive": sum(1 for r in results if r["alive"]), "internet_healthy": sum(1 for r in results if r.get("internet_healthy")), "dead": sum(1 for r in results if not r["alive"]), "results": results}
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"generated_at": generated_at, "selected": len(candidates), "alive": payload["alive"], "internet_healthy": payload["internet_healthy"], "dead": payload["dead"]}, ensure_ascii=False))

if __name__ == "__main__": main()
