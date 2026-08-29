#!/usr/bin/env python3
"""Full-pool Internet health scan using one long-lived Xray process."""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import country_resolver

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
XRAY = Path(os.environ.get("XRAY_BIN", "/opt/hostedtoolcache/xray/xray"))
DEFAULT_WORKERS = int(os.environ.get("REAL_DELAY_WORKERS", "256"))
DEFAULT_TIMEOUT = float(os.environ.get("REAL_DELAY_NODE_TIMEOUT", "5"))
BASE_PORT = int(os.environ.get("REAL_DELAY_SOCKS_BASE", "21000"))

PROBES = (
    ("microsoft_connect_test", "www.msftconnecttest.com", "/connecttest.txt", False, 200, b"Microsoft Connect Test"),
    ("google_generate_204", "www.gstatic.com", "/generate_204", True, 204, None),
    ("firefox_success", "detectportal.firefox.com", "/success.txt", False, 200, b"success"),
)


def b64d(v: str) -> bytes:
    v = v.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(v + "=" * (-len(v) % 4))


def params(uri: str):
    return urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query, keep_blank_values=True)


def first(q, *keys, default=""):
    for key in keys:
        if q.get(key):
            return urllib.parse.unquote(q[key][0])
    return default


def scheme(uri: str) -> str:
    return urllib.parse.urlsplit(uri).scheme.lower()


def parse_uri(uri: str) -> dict:
    s = scheme(uri)
    p = urllib.parse.urlsplit(uri)
    q = params(uri)
    if s == "vless":
        sec = first(q, "security", default="none")
        node = {
            "scheme": "vless",
            "server": p.hostname,
            "port": p.port or 443,
            "uuid": urllib.parse.unquote(p.username or ""),
            "network": first(q, "type", default="tcp").lower(),
            "path": first(q, "path", default="/"),
            "host": first(q, "host"),
            "security": sec,
            "sni": first(q, "sni", "serverName", default=p.hostname),
            "fp": first(q, "fp", default="chrome"),
            "pbk": first(q, "pbk", "publicKey"),
            "sid": first(q, "sid", "shortId"),
            "service_name": first(q, "serviceName"),
            "authority": first(q, "authority"),
        }
        if not node["server"]:
            raise ValueError("invalid VLESS server")
        if not node["uuid"] or len(node["uuid"].strip()) < 10:
            raise ValueError("invalid or empty VLESS UUID")
        if sec == "reality" and (not node["pbk"] or len(node["pbk"].strip()) < 20):
            raise ValueError("REALITY requires a valid non-empty publicKey (pbk)")
        return node
    if s == "vmess":
        obj = json.loads(b64d(uri.split("vmess://", 1)[1].split("#", 1)[0]).decode("utf-8"))
        server = obj.get("add") or obj.get("address")
        if not obj.get("id") or len(str(obj.get("id")).strip()) < 10:
            raise ValueError("invalid or empty VMess UUID")
        return {
            "scheme": "vmess",
            "server": server,
            "port": int(obj["port"]),
            "uuid": obj.get("id"),
            "network": str(obj.get("net") or "tcp").lower(),
            "path": obj.get("path") or "/",
            "host": obj.get("host") or "",
            "tls": str(obj.get("tls") or "").lower() not in ("", "none", "false", "0"),
            "sni": obj.get("sni") or obj.get("host") or server,
            "alter_id": int(obj.get("aid", 0) or 0),
            "cipher": obj.get("scy") or "auto",
        }
    if s == "trojan":
        password = urllib.parse.unquote(p.username or "")
        if not password:
            raise ValueError("invalid or empty Trojan password")
        return {
            "scheme": "trojan",
            "server": p.hostname,
            "port": p.port or 443,
            "password": password,
            "network": first(q, "type", default="tcp").lower(),
            "path": first(q, "path", default="/"),
            "host": first(q, "host"),
            "sni": first(q, "sni", default=p.hostname),
            "service_name": first(q, "serviceName"),
        }
    if s == "ss":
        raw = uri.split("ss://", 1)[1].split("#", 1)[0]
        if "@" in raw:
            ui, hp = raw.rsplit("@", 1)
            try:
                ui = b64d(ui).decode("utf-8")
            except Exception:
                ui = urllib.parse.unquote(ui)
        else:
            dec = b64d(raw).decode("utf-8")
            ui, hp = dec.rsplit("@", 1)
        hp = hp.split("?", 1)[0].split("/", 1)[0]
        if hp.startswith("["):
            host, port = hp.rsplit("]:", 1)
            host = host[1:]
        else:
            host, port = hp.rsplit(":", 1)
        user = urllib.parse.unquote(ui)
        if ":" not in user:
            raise ValueError("invalid Shadowsocks method:password")
        method, password = user.split(":", 1)
        if not method.strip() or not password:
            raise ValueError("invalid or empty Shadowsocks credentials")
        return {"scheme": "ss", "server": host, "port": int(port), "method": method, "password": password}
    raise ValueError(f"unsupported scheme: {s}")


def xray_outbound(n: dict, tag: str) -> dict:
    s = n["scheme"]
    if s == "vless":
        stream = {"network": n["network"], "security": "none"}
        if n["network"] == "ws":
            stream["wsSettings"] = {"path": n.get("path") or "/", "headers": {"Host": n.get("host") or ""}}
        elif n["network"] == "grpc":
            stream["grpcSettings"] = {"serviceName": n.get("service_name") or "", "authority": n.get("authority") or ""}
        if n.get("security") == "tls":
            stream["security"] = "tls"
            stream["tlsSettings"] = {"serverName": n.get("sni") or n["server"]}
            if n.get("fp"):
                stream["tlsSettings"]["fingerprint"] = n["fp"]
        elif n.get("security") == "reality":
            stream["security"] = "reality"
            stream["realitySettings"] = {
                "serverName": n.get("sni") or n["server"],
                "fingerprint": n.get("fp") or "chrome",
                "publicKey": n["pbk"].strip(),
                "shortId": n.get("sid") or "",
                "spiderX": "/",
            }
        return {
            "protocol": "vless",
            "tag": tag,
            "settings": {"vnext": [{"address": n["server"], "port": n["port"], "users": [{"id": n["uuid"], "encryption": "none"}]}]},
            "streamSettings": stream,
        }
    if s == "vmess":
        stream = {"network": n["network"], "security": "none"}
        if n["network"] == "ws":
            stream["wsSettings"] = {"path": n.get("path") or "/", "headers": {"Host": n.get("host") or ""}}
        if n.get("tls"):
            stream["security"] = "tls"
            stream["tlsSettings"] = {"serverName": n.get("sni") or n["server"]}
        return {
            "protocol": "vmess",
            "tag": tag,
            "settings": {"vnext": [{"address": n["server"], "port": n["port"], "users": [{"id": n["uuid"], "alterId": n.get("alter_id", 0), "security": n.get("cipher", "auto")}]}]},
            "streamSettings": stream,
        }
    if s == "trojan":
        stream = {"network": n["network"], "security": "tls", "tlsSettings": {"serverName": n.get("sni") or n["server"]}}
        if n["network"] == "ws":
            stream["wsSettings"] = {"path": n.get("path") or "/", "headers": {"Host": n.get("host") or ""}}
        elif n["network"] == "grpc":
            stream["grpcSettings"] = {"serviceName": n.get("service_name") or ""}
        return {"protocol": "trojan", "tag": tag, "settings": {"servers": [{"address": n["server"], "port": n["port"], "password": n["password"]}]}, "streamSettings": stream}
    if s == "ss":
        return {"protocol": "shadowsocks", "tag": tag, "settings": {"servers": [{"address": n["server"], "port": n["port"], "method": n["method"], "password": n["password"]}]}}
    raise ValueError(s)


def load_pool():
    path = OUT / "metadata" / "tcp_reachable.json"
    if not path.is_file():
        raise SystemExit(f"TCP candidate pool not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    pool = []
    for item in payload.get("nodes", []):
        uri = str(item.get("uri") or "").strip()
        if not uri:
            continue
        try:
            node = parse_uri(uri)
        except Exception:
            continue
        if node.get("port") not in {80, 443}:
            continue
        pool.append({**item, "uri": uri, "node": node, "country": "UNKNOWN"})
    return pool


def wait_port(port, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def socks_http(port, host, path, use_tls, status, body, timeout):
    started = time.perf_counter()
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return False, -1, "socks-auth"
        hb = host.encode("idna")
        rp = 443 if use_tls else 80
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + rp.to_bytes(2, "big"))
        h = s.recv(4)
        if len(h) != 4 or h[1] != 0:
            return False, -1, "socks-connect"
        if h[3] == 1:
            s.recv(4)
        elif h[3] == 3:
            s.recv(s.recv(1)[0])
        elif h[3] == 4:
            s.recv(16)
        s.recv(2)
        conn = s
        if use_tls:
            conn = ssl.create_default_context().wrap_socket(s, server_hostname=host)
        conn.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: AhmedVPN-RealDelay/7\r\n\r\n".encode())
        data = bytearray()
        while len(data) < 16384:
            chunk = conn.recv(min(4096, 16384 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        raw = bytes(data)
        first_line = raw.split(b"\r\n", 1)[0]
        match = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", first_line)
        if not match:
            return False, -1, "no-http"
        actual = int(match.group(1))
        if actual != status:
            return False, -1, f"unexpected-status-{actual}"
        if body is not None and body not in raw:
            return False, -1, "expected-body-missing"
        return True, round((time.perf_counter() - started) * 1000, 1), f"HTTP {status}"
    finally:
        try:
            s.close()
        except Exception:
            pass


def probe(item, timeout):
    details = {}
    delays = []
    for name, host, path, tls, status, body in PROBES:
        try:
            ok, lat, detail = socks_http(item["port"], host, path, tls, status, body, timeout)
        except Exception as exc:
            ok, lat, detail = False, -1, str(exc)[:180]
        details[name] = {"ok": ok, "latency_ms": lat if ok else -1, "detail": detail}
        if ok:
            delays.append(lat)
    healthy = all(details[name]["ok"] for name, *_ in PROBES)
    alive = any(details[name]["ok"] for name, *_ in PROBES)
    return {
        "index": item["index"],
        "msft_ok": details["microsoft_connect_test"]["ok"],
        "google_204_ok": details["google_generate_204"]["ok"],
        "firefox_ok": details["firefox_success"]["ok"],
        "internet_healthy": healthy,
        "delay_ms": min(delays) if delays else -1,
        "details": details,
        "alive": alive,
    }


def write_cfg(path: Path, items: list[dict]):
    ins = []
    outs = []
    rules = []
    for item in items:
        tag = f"node-{item['index'] + 1}"
        itag = f"in-{item['index'] + 1}"
        outs.append(xray_outbound(item["node"], tag))
        ins.append({"listen": "127.0.0.1", "port": item["port"], "protocol": "socks", "settings": {"udp": False}, "tag": itag})
        rules.append({"type": "field", "inboundTag": [itag], "outboundTag": tag})
    path.write_text(json.dumps({"log": {"loglevel": "error"}, "inbounds": ins, "outbounds": outs, "routing": {"domainStrategy": "AsIs", "rules": rules}}, ensure_ascii=False), encoding="utf-8")


def publish_healthy(healthy_items, resolution, stats):
    import pycountry

    countries_dir = OUT / "countries"
    protocols_dir = OUT / "protocols"
    global_dir = OUT / "global"
    meta_dir = OUT / "metadata"
    for directory in (countries_dir, protocols_dir, global_dir, meta_dir):
        directory.mkdir(parents=True, exist_ok=True)
    for path in countries_dir.glob("*.txt"):
        path.unlink()
    for path in protocols_dir.glob("*.txt"):
        path.unlink()
    for path in global_dir.glob("server-*.txt"):
        path.unlink()

    ordered = []
    for item in healthy_items:
        result = item["result"]
        row = {k: v for k, v in item.items() if k not in {"node", "result"}}
        row.update(result)
        ordered.append(row)
    ordered.sort(key=lambda row: (row.get("delay_ms", 10**9) if row.get("delay_ms", -1) >= 0 else 10**9, row.get("index", 10**9), row.get("uri", "")))

    iso_codes = {c.alpha_2.upper() for c in pycountry.countries}
    grouped = {}
    unknown = []
    for row in ordered:
        code = str(row.get("country") or "UNKNOWN").upper()
        if code in iso_codes:
            grouped.setdefault(code, []).append(row)
        else:
            unknown.append(row)

    target_codes = sorted(grouped)
    if unknown and target_codes:
        base, remainder = divmod(len(unknown), len(target_codes))
        cursor = 0
        for i, code in enumerate(target_codes):
            take = base + (1 if i < remainder else 0)
            grouped[code].extend(unknown[cursor:cursor + take])
            cursor += take
    elif unknown:
        (global_dir / "verified-unknown.txt").write_text("\n".join(row["uri"] for row in unknown) + "\n", encoding="utf-8")

    for code in target_codes:
        (countries_dir / f"{code}.txt").write_text("\n".join(row["uri"] for row in grouped[code]) + "\n", encoding="utf-8")

    protocol_rows = {}
    for code in target_codes:
        for row in grouped[code]:
            protocol = str(row.get("protocol") or "")
            if protocol:
                protocol_rows.setdefault(protocol, []).append(row["uri"])
    for protocol, lines in protocol_rows.items():
        (protocols_dir / f"{protocol}.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    counts = {code: len(grouped[code]) for code in target_codes}
    metadata = {
        "schema": 8,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tcp_reachable_total": stats["pool_total"],
        "xray_included": stats["included"],
        "config_conversion_failed": stats["config_conversion_failed"],
        "alive": stats["alive"],
        "healthy": stats["healthy"],
        "healthy_published_total": sum(counts.values()),
        "published_by_country": counts,
        "countries": len(target_codes),
        "country_names": {code: _country_name(code) for code in target_codes},
        "allowed_ports": [80, 443],
        "health_policy": "Xray triple HTTP probes: Microsoft 200 + Google 204 + Firefox 200; country resolution occurs only after triple-pass health",
        "ranking_policy": "healthy only; fastest delay first; country files preserve the same order with detected-country nodes before distributed verified-UNKNOWN nodes",
        "country_policy": "resolve only successful nodes; explicit node metadata then DNS/GeoLite2; verified UNKNOWN nodes are distributed equally after detected-country nodes",
        "country_resolution": resolution,
    }
    (meta_dir / "index.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (meta_dir / "health.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (meta_dir / "countries.json").write_text(json.dumps({"countries": [{"code": code, "name": _country_name(code), "nodes": counts[code], "reachable": counts[code], "cap_rejected": 0} for code in target_codes]}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _country_name(code):
    import pycountry
    item = pycountry.countries.get(alpha_2=code)
    return item.name if item else code


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = ap.parse_args()
    workers = max(1, args.workers)
    timeout = max(0.5, args.timeout)
    if not XRAY.exists():
        raise SystemExit(f"Xray binary not found: {XRAY}")

    pool = load_pool()
    if not pool:
        raise SystemExit("No TCP-reachable nodes available")
    print(f"INFO real_delay_pool={len(pool)} selected={len(pool)} workers={workers} mode=single_long_lived_xray probes=3")

    start = time.perf_counter()
    included = []
    failures = []
    results = []

    with tempfile.TemporaryDirectory(prefix="real-delay-") as td:
        root = Path(td)
        for idx, item in enumerate(pool):
            try:
                tag = f"node-{idx + 1}"
                item = {**item, "index": idx, "port": BASE_PORT + idx}
                xray_outbound(item["node"], tag)
                included.append(item)
            except Exception as exc:
                failures.append({"index": idx, "uri": item["uri"], "reason": str(exc)[:500], "classification": "config_conversion_failed"})

        cfg = root / "config.json"
        write_cfg(cfg, included)
        check = subprocess.run([str(XRAY), "-test", "-config", str(cfg)], text=True, capture_output=True, timeout=max(120, len(included) // 4 if included else 120))
        if check.returncode != 0:
            print("WARN Xray full config rejected; isolating invalid outbounds with divide-and-conquer")
            bad = []

            def valid_chunk(chunk):
                if not chunk:
                    return True
                path = root / f"test-{time.monotonic_ns()}.json"
                write_cfg(path, chunk)
                try:
                    response = subprocess.run([str(XRAY), "-test", "-config", str(path)], text=True, capture_output=True, timeout=max(30, len(chunk) // 4 + 30))
                except subprocess.TimeoutExpired:
                    return False
                return response.returncode == 0

            stack = [included]
            while stack:
                chunk = stack.pop()
                if not chunk:
                    continue
                if valid_chunk(chunk):
                    continue
                if len(chunk) == 1:
                    bad.append(chunk[0])
                    continue
                middle = len(chunk) // 2
                stack.append(chunk[:middle])
                stack.append(chunk[middle:])

            bad_idx = {item["index"] for item in bad}
            failures.extend({"index": item["index"], "uri": item["uri"], "reason": "Xray config validation failed after isolation", "classification": "config_conversion_failed"} for item in bad)
            included = [item for item in included if item["index"] not in bad_idx]
            write_cfg(cfg, included)
            check = subprocess.run([str(XRAY), "-test", "-config", str(cfg)], text=True, capture_output=True, timeout=max(120, len(included) // 4 if included else 120))
            if check.returncode != 0:
                raise SystemExit("Xray config still rejected after isolation: " + (check.stderr or check.stdout)[-4000:])

        proc = subprocess.Popen([str(XRAY), "run", "-c", str(cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if included and not wait_port(included[0]["port"]):
                raise SystemExit("Xray process did not open first inbound")
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(probe, item, timeout): item for item in included}
                for number, future in enumerate(as_completed(futures), 1):
                    item = futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {"index": item["index"], "msft_ok": False, "google_204_ok": False, "firefox_ok": False, "internet_healthy": False, "delay_ms": -1, "details": {"exception": str(exc)[:180]}, "alive": False}
                    results.append(result)
                    if number % 500 == 0 or number == len(included):
                        print(f"INFO real_delay_progress={number}/{len(included)} alive={sum(1 for r in results if r.get('alive'))} healthy={sum(1 for r in results if r.get('internet_healthy'))}")
        finally:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()

    by_index = {result["index"]: result for result in results}
    healthy = []
    for idx, item in enumerate(pool):
        result = by_index.get(idx)
        if result and result.get("internet_healthy"):
            healthy.append({**item, "result": result})

    healthy.sort(key=lambda item: (item["result"].get("delay_ms", 10**9) if item["result"].get("delay_ms", -1) >= 0 else 10**9, item["result"].get("index", 10**9), item.get("uri", "")))

    rows_for_resolution = []
    for item in healthy:
        rows_for_resolution.append({k: v for k, v in item.items() if k not in {"node", "result"}})

    if rows_for_resolution:
        resolution = country_resolver.resolve_rows(rows_for_resolution)
        for item, row in zip(healthy, rows_for_resolution):
            item["country"] = row.get("country") or "UNKNOWN"
            item["country_resolution"] = row.get("country_resolution") or "unknown"
            item["country_resolution_confidence"] = row.get("country_resolution_confidence")
    else:
        resolution = {"hostname": 0, "geoip_local": 0, "unknown": 0, "database_loaded": False}

    alive = sum(1 for result in results if result.get("alive"))
    stats = {
        "pool_total": len(pool),
        "included": len(included),
        "config_conversion_failed": len(failures),
        "alive": alive,
        "healthy": len(healthy),
        "workers": workers,
        "timeout_s": timeout,
    }
    print(f"INFO real_delay_done pool={len(pool)} included={len(included)} config_conversion_failed={len(failures)} alive={alive} healthy={len(healthy)} elapsed_s={time.perf_counter() - start:.1f}")

    publish_healthy(healthy, resolution, stats)
    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **stats,
        "probes": {
            "microsoft": {"url": "http://www.msftconnecttest.com/connecttest.txt", "status": 200, "body": "Microsoft Connect Test"},
            "google": {"url": "https://www.gstatic.com/generate_204", "status": 204},
            "firefox": {"url": "http://detectportal.firefox.com/success.txt", "status": 200, "body": "success"},
        },
        "nodes": [{**{k: v for k, v in item.items() if k not in {"node"}}, "result": item["result"]} for item in healthy],
    }
    meta = OUT / "metadata"
    meta.mkdir(parents=True, exist_ok=True)
    (meta / "real_delay.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
