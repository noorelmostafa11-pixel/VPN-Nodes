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
TEST_HOST = os.environ.get("REAL_DELAY_TEST_HOST", "www.gstatic.com")
TEST_PATH = os.environ.get("REAL_DELAY_TEST_PATH", "/generate_204")

ALIASES = {
    "uk":"GB","england":"GB","greatbritain":"GB","unitedkingdom":"GB",
    "uae":"AE","emirates":"AE","unitedarabemirates":"AE","usa":"US",
    "america":"US","unitedstates":"US","southkorea":"KR","korea":"KR",
    "russia":"RU","iran":"IR","taiwan":"TW","japan":"JP","singapore":"SG",
    "seychelles":"SC","germany":"DE","france":"FR","canada":"CA","australia":"AU",
    "austria":"AT","netherlands":"NL","poland":"PL","slovenia":"SI",
    "turkey":"TR","turkiye":"TR","hongkong":"HK","finland":"FI","sweden":"SE",
    "denmark":"DK","bulgaria":"BG","azerbaijan":"AZ","china":"CN","estonia":"EE",
    "czechrepublic":"CZ","czechia":"CZ","southafrica":"ZA","newzealand":"NZ",
    "saudiarabia":"SA",
}


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def scheme(uri: str) -> str:
    return uri.split(":", 1)[0].lower()


def query(uri: str):
    return parse_qs(urlparse(uri).query, keep_blank_values=True)


def first(q, *keys, default=""):
    for k in keys:
        if q.get(k):
            return unquote(q[k][0])
    return default


def protocol(uri: str) -> str:
    s = scheme(uri)
    return "shadowsocks" if s == "ss" else s


def node_country(uri: str, fallback: str = "UNKNOWN") -> str:
    frag = unquote(urlparse(uri).fragment or "")
    compact = re.sub(r"[^a-z0-9]+", "", frag.lower())
    for token, code in ALIASES.items():
        if token in compact:
            return code
    for code in re.findall(r"(?<![A-Za-z0-9])([A-Z]{2})(?![A-Za-z0-9])", frag):
        if code.upper() != "WS" and code.upper() != "SS" and code.upper() != "TLS":
            return code.upper()
    return fallback


def load_pool():
    rows = {}
    country_dir = OUT / "countries"
    protocol_dir = OUT / "protocols"
    for path in sorted(country_dir.glob("*.txt")):
        country = path.stem.upper()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            uri = line.strip()
            if not uri:
                continue
            key = hashlib.sha256(uri.encode()).hexdigest()
            rows.setdefault(key, {"uri": uri, "country": country, "protocol": protocol(uri)})
    for path in sorted(protocol_dir.glob("*.txt")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            uri = line.strip()
            if not uri:
                continue
            key = hashlib.sha256(uri.encode()).hexdigest()
            rows.setdefault(key, {"uri": uri, "country": node_country(uri), "protocol": protocol(uri)})
    return list(rows.values())


def quota_select(pool):
    by_country = {}
    for item in pool:
        by_country.setdefault(item["country"], []).append(item)
    countries = sorted(by_country)
    if not pool:
        return []
    quotas = {c: max(1, int(MAX_REAL_DELAY_CANDIDATES * len(by_country[c]) / len(pool))) for c in countries}
    while sum(quotas.values()) > MAX_REAL_DELAY_CANDIDATES:
        c = max(quotas, key=lambda x: (quotas[x], len(by_country[x])))
        if quotas[c] <= 1:
            break
        quotas[c] -= 1
    while sum(quotas.values()) < min(MAX_REAL_DELAY_CANDIDATES, len(pool)):
        c = max(countries, key=lambda x: len(by_country[x]) - quotas[x])
        if quotas[c] >= len(by_country[c]):
            break
        quotas[c] += 1
    chosen = []
    for country in countries:
        items = by_country[country]
        q = min(quotas[country], len(items))
        if q == len(items):
            chosen.extend(items)
            continue
        step = len(items) / q
        # Deterministic spread: includes the strongest head of the country's file
        # and also reaches deeper entries so lower-priority sources are not ignored.
        idxs = sorted({min(len(items)-1, int(i * step)) for i in range(q)})
        if 0 not in idxs:
            idxs[0] = 0
        chosen.extend(items[i] for i in idxs[:q])
    return chosen[:MAX_REAL_DELAY_CANDIDATES]


def vless_outbound(uri: str):
    p = urlparse(uri)
    q = query(uri)
    user = p.username or ""
    settings = {"vnext": [{"address": p.hostname, "port": p.port, "users": [{"id": unquote(user), "encryption": first(q, "encryption", default="none")}]}]}
    flow = first(q, "flow")
    if flow:
        settings["vnext"][0]["users"][0]["flow"] = flow
    stream = {"network": first(q, "type", default="tcp")}
    sec = first(q, "security", default="none")
    stream["security"] = sec
    net = stream["network"]
    if net == "ws":
        stream["wsSettings"] = {"path": first(q, "path", default="/"), "headers": {"Host": first(q, "host")}} 
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": first(q, "serviceName"), "authority": first(q, "authority")}
    elif net == "xhttp":
        stream["xhttpSettings"] = {"path": first(q, "path", default="/"), "mode": first(q, "mode", default="auto"), "host": first(q, "host")}
    if sec == "tls":
        tls = {"serverName": first(q, "sni", "serverName", default=p.hostname)}
        fp = first(q, "fp")
        if fp:
            tls["fingerprint"] = fp
        alpn = first(q, "alpn")
        if alpn:
            tls["alpn"] = [x for x in alpn.split(",") if x]
        stream["tlsSettings"] = tls
    elif sec == "reality":
        stream["realitySettings"] = {
            "serverName": first(q, "sni", "serverName", default=p.hostname),
            "fingerprint": first(q, "fp", default="chrome"),
            "publicKey": first(q, "pbk"),
            "shortId": first(q, "sid"),
            "spiderX": first(q, "spx", default="/")
        }
    return {"protocol": "vless", "settings": settings, "streamSettings": stream}


def vmess_outbound(uri: str):
    raw = uri.split("vmess://", 1)[1].split("#", 1)[0]
    try:
        obj = json.loads(b64d(raw).decode("utf-8"))
    except Exception:
        p = urlparse(uri)
        q = query(uri)
        obj = {"add": p.hostname, "port": p.port, "id": p.username or "", "net": first(q, "type", default="tcp"), "path": first(q, "path", default="/"), "host": first(q, "host"), "tls": first(q, "security", default="")}
    stream = {"network": obj.get("net", "tcp") or "tcp", "security": "tls" if obj.get("tls") else "none"}
    if stream["network"] == "ws":
        stream["wsSettings"] = {"path": obj.get("path") or "/", "headers": {"Host": obj.get("host") or ""}}
    if stream["security"] == "tls":
        stream["tlsSettings"] = {"serverName": obj.get("sni") or obj.get("host") or obj.get("add")}
    return {"protocol": "vmess", "settings": {"vnext": [{"address": obj.get("add"), "port": int(obj.get("port")), "users": [{"id": obj.get("id"), "alterId": int(obj.get("aid", 0) or 0), "security": obj.get("scy", "auto")}]}]}, "streamSettings": stream}


def trojan_outbound(uri: str):
    p = urlparse(uri)
    q = query(uri)
    stream = {"network": first(q, "type", default="tcp"), "security": first(q, "security", default="tls")}
    if stream["network"] == "ws":
        stream["wsSettings"] = {"path": first(q, "path", default="/"), "headers": {"Host": first(q, "host", default="")}}
    if stream["security"] == "tls":
        stream["tlsSettings"] = {"serverName": first(q, "sni", default=p.hostname)}
    return {"protocol": "trojan", "settings": {"servers": [{"address": p.hostname, "port": p.port, "password": unquote(p.username or "")} ]}, "streamSettings": stream}


def ss_outbound(uri: str):
    p = urlparse(uri)
    raw = uri.split("ss://", 1)[1].split("#", 1)[0]
    if "@" in raw:
        userinfo, _ = raw.rsplit("@", 1)
        hostpart = raw.rsplit("@", 1)[1]
        try:
            decoded = b64d(userinfo).decode()
        except Exception:
            decoded = unquote(userinfo)
        method, password = decoded.split(":", 1)
        host, port = hostpart.rsplit(":", 1)
    else:
        decoded = b64d(raw).decode()
        userinfo, hostpart = decoded.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
        host, port = hostpart.rsplit(":", 1)
    return {"protocol": "shadowsocks", "settings": {"servers": [{"address": host, "port": int(port), "method": method, "password": password}]}}


def outbound_for(uri: str):
    s = scheme(uri)
    if s == "vless": return vless_outbound(uri)
    if s == "vmess": return vmess_outbound(uri)
    if s == "trojan": return trojan_outbound(uri)
    if s == "ss": return ss_outbound(uri)
    raise ValueError("unsupported protocol")


def socks5_https(port: int) -> float:
    started = time.perf_counter()
    s = socket.create_connection(("127.0.0.1", port), timeout=NODE_TIMEOUT)
    s.settimeout(NODE_TIMEOUT)
    try:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 auth negotiation failed")
        host = TEST_HOST.encode("idna")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + (443).to_bytes(2, "big"))
        head = s.recv(4)
        if len(head) != 4 or head[1] != 0:
            raise RuntimeError("SOCKS5 connect failed")
        atyp = head[3]
        if atyp == 1: s.recv(4)
        elif atyp == 3: s.recv(1); s.recv(s.recv(1)[0])
        elif atyp == 4: s.recv(16)
        s.recv(2)
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(s, server_hostname=TEST_HOST)
        req = f"GET {TEST_PATH} HTTP/1.1\r\nHost: {TEST_HOST}\r\nConnection: close\r\nUser-Agent: AhmedVPN-RealDelay/1\r\n\r\n".encode()
        tls.sendall(req)
        data = tls.recv(128)
        if b"HTTP/" not in data:
            raise RuntimeError("no HTTP response")
        return round((time.perf_counter() - started) * 1000, 1)
    finally:
        try: s.close()
        except Exception: pass


def test_one(item, slot):
    port = SOCKS_BASE_PORT + slot
    with tempfile.TemporaryDirectory(prefix="xray-rd-") as td:
        root = Path(td)
        cfg_path = root / "config.json"
        log_path = root / "xray.log"
        try:
            outbound = outbound_for(item["uri"])
            config = {
                "log": {"loglevel": "error", "access": str(log_path), "error": str(log_path)},
                "inbounds": [{"listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"udp":False}}],
                "outbounds": [outbound]
            }
            cfg_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
            proc = subprocess.Popen([str(XRAY), "run", "-c", str(cfg_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 2.5
            while time.monotonic() < deadline:
                try:
                    test_sock = socket.create_connection(("127.0.0.1", port), timeout=0.15)
                    test_sock.close()
                    break
                except OSError:
                    time.sleep(0.08)
            else:
                return {**item, "delay_ms": -1, "alive": False, "error": "xray_start_timeout"}
            try:
                delay = socks5_https(port)
                return {**item, "delay_ms": delay, "alive": True}
            except Exception as exc:
                return {**item, "delay_ms": -1, "alive": False, "error": str(exc)[:180]}
            finally:
                proc.terminate()
                try: proc.wait(timeout=1.5)
                except subprocess.TimeoutExpired: proc.kill()
        except Exception as exc:
            return {**item, "delay_ms": -1, "alive": False, "error": str(exc)[:180]}


def main():
    if not XRAY.exists():
        raise SystemExit(f"Xray binary not found: {XRAY}")
    pool = load_pool()
    candidates = quota_select(pool)
    print(f"INFO real_delay_pool={len(pool)} selected={len(candidates)} workers={WORKERS}")
    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = {executor.submit(test_one, item, i): (item, i) for i, item in enumerate(candidates)}
        for n, future in enumerate(as_completed(futures), 1):
            result = future.result()
            results.append(result)
            if n % 100 == 0 or n == len(candidates):
                alive = sum(1 for r in results if r["alive"])
                print(f"INFO real_delay_progress={n}/{len(candidates)} alive={alive}")

    results.sort(key=lambda r: (r["country"], 0 if r["alive"] else 1, r["delay_ms"] if r["delay_ms"] > 0 else 10**9, r["protocol"], r["uri"]))
    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out = OUT / "metadata" / "real_delay.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": 1,
        "generated_at": generated_at,
        "test": {"engine": "Xray", "target": f"https://{TEST_HOST}{TEST_PATH}", "candidates": len(candidates)},
        "alive": sum(1 for r in results if r["alive"]),
        "dead": sum(1 for r in results if not r["alive"]),
        "results": results,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # Promote successful Real Delay results into each country feed. Keep every
    # existing node after them so untested nodes are never silently discarded.
    by_country = {}
    for r in results:
        if r["alive"]:
            by_country.setdefault(r["country"], []).append(r)
    for country, rows in by_country.items():
        path = OUT / "countries" / f"{country}.txt"
        existing = path.read_text(encoding="utf-8", errors="replace").splitlines() if path.exists() else []
        existing_set = set(existing)
        promoted = [r["uri"] for r in sorted(rows, key=lambda x: x["delay_ms"]) ]
        merged = []
        seen = set()
        for uri in promoted + existing:
            if uri and uri not in seen:
                merged.append(uri); seen.add(uri)
        path.write_text("\n".join(merged) + "\n", encoding="utf-8")

    print(json.dumps({"generated_at": generated_at, "selected": len(candidates), "alive": payload["alive"], "dead": payload["dead"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
