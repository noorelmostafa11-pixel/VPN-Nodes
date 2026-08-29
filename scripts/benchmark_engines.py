#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
XRAY = Path(os.environ.get("XRAY_BIN", "/opt/hostedtoolcache/xray/xray"))
SING_BOX = Path(os.environ.get("SING_BOX_BIN", "/opt/hostedtoolcache/sing-box/sing-box"))
MIHOMO = Path(os.environ.get("MIHOMO_BIN", "/opt/hostedtoolcache/mihomo/mihomo"))
DEFAULT_NODES = 500
DEFAULT_WORKERS = 80
DEFAULT_TIMEOUT = 5.0
BASE_PORT = 18000
API_PORT = 19090

PROBES = (
    ("microsoft_connect_test", "www.msftconnecttest.com", "/connecttest.txt", False, 200, "Microsoft Connect Test"),
    ("google_generate_204", "www.gstatic.com", "/generate_204", False, 204, None),
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


def decode_vmess(uri: str) -> dict:
    raw = uri.split("vmess://", 1)[1].split("#", 1)[0]
    return json.loads(b64d(raw).decode())


def split_host_port(value: str) -> tuple[str, int]:
    value = value.strip()
    if value.startswith("["):
        host, port = value.rsplit("]:", 1)
        return host[1:], int(port)
    host, port = value.rsplit(":", 1)
    return host, int(port)


def parse_uri(uri: str) -> dict:
    s = scheme(uri)
    p = urllib.parse.urlsplit(uri)
    params = q(uri)
    remark = urllib.parse.unquote(p.fragment or "")
    if s == "vmess":
        obj = decode_vmess(uri)
        return {
            "scheme": s, "remark": remark, "server": obj.get("add"), "port": int(obj.get("port")),
            "uuid": obj.get("id"), "network": (obj.get("net") or "tcp").lower(), "path": obj.get("path") or "/",
            "host": obj.get("host") or "", "tls": str(obj.get("tls") or "").lower() not in ("", "none", "false", "0"),
            "reality": False, "sni": obj.get("sni") or obj.get("host") or obj.get("add"),
            "alter_id": int(obj.get("aid", 0) or 0), "cipher": obj.get("scy") or "auto",
        }
    if s == "vless":
        return {
            "scheme": s, "remark": remark, "server": p.hostname, "port": p.port or 443,
            "uuid": urllib.parse.unquote(p.username or ""), "network": first(params, "type", default="tcp").lower(),
            "path": first(params, "path", default="/"), "host": first(params, "host"),
            "tls": first(params, "security") == "tls", "reality": first(params, "security") == "reality",
            "sni": first(params, "sni", "serverName", default=p.hostname), "fp": first(params, "fp", default="chrome"),
            "pbk": first(params, "pbk"), "sid": first(params, "sid"), "service_name": first(params, "serviceName"),
            "authority": first(params, "authority"),
        }
    if s == "trojan":
        return {
            "scheme": s, "remark": remark, "server": p.hostname, "port": p.port or 443,
            "password": urllib.parse.unquote(p.username or ""), "network": first(params, "type", default="tcp").lower(),
            "path": first(params, "path", default="/"), "host": first(params, "host"),
            "tls": first(params, "security", default="tls") == "tls", "reality": False,
            "sni": first(params, "sni", default=p.hostname), "service_name": first(params, "serviceName"),
        }
    if s == "ss":
        raw = uri.split("ss://", 1)[1].split("#", 1)[0]
        if "@" in raw:
            userinfo, hp = raw.rsplit("@", 1)
            try:
                userinfo = b64d(userinfo).decode()
            except Exception:
                userinfo = urllib.parse.unquote(userinfo)
        else:
            decoded = b64d(raw).decode()
            userinfo, hp = decoded.rsplit("@", 1)
        host, port = split_host_port(hp)
        userinfo = urllib.parse.unquote(userinfo)
        method, password = userinfo.split(":", 1)
        return {"scheme": s, "remark": remark, "server": host, "port": port, "method": method, "password": password}
    raise ValueError(f"unsupported scheme: {s}")


def xray_outbound(node: dict, tag: str) -> dict:
    s = node["scheme"]
    if s == "vless":
        stream = {"network": node["network"], "security": "none"}
        if node.get("network") == "ws":
            stream["wsSettings"] = {"path": node.get("path") or "/", "headers": {"Host": node.get("host") or ""}}
        elif node.get("network") == "grpc":
            stream["grpcSettings"] = {"serviceName": node.get("service_name") or "", "authority": node.get("authority") or ""}
        if node.get("tls"):
            stream["security"] = "tls"
            stream["tlsSettings"] = {"serverName": node.get("sni") or node["server"]}
            if node.get("fp"):
                stream["tlsSettings"]["fingerprint"] = node["fp"]
        elif node.get("reality"):
            stream["security"] = "reality"
            stream["realitySettings"] = {"serverName": node.get("sni") or node["server"], "fingerprint": node.get("fp") or "chrome", "publicKey": node.get("pbk") or "", "shortId": node.get("sid") or "", "spiderX": "/"}
        return {"protocol": "vless", "tag": tag, "settings": {"vnext": [{"address": node["server"], "port": node["port"], "users": [{"id": node["uuid"], "encryption": "none"}]}]}, "streamSettings": stream}
    if s == "vmess":
        stream = {"network": node["network"], "security": "none"}
        if node.get("network") == "ws":
            stream["wsSettings"] = {"path": node.get("path") or "/", "headers": {"Host": node.get("host") or ""}}
        if node.get("tls"):
            stream["security"] = "tls"; stream["tlsSettings"] = {"serverName": node.get("sni") or node["server"]}
        return {"protocol": "vmess", "tag": tag, "settings": {"vnext": [{"address": node["server"], "port": node["port"], "users": [{"id": node["uuid"], "alterId": node.get("alter_id", 0), "security": node.get("cipher", "auto")}]}]}, "streamSettings": stream}
    if s == "trojan":
        stream = {"network": node["network"], "security": "tls", "tlsSettings": {"serverName": node.get("sni") or node["server"]}}
        if node.get("network") == "ws": stream["wsSettings"] = {"path": node.get("path") or "/", "headers": {"Host": node.get("host") or ""}}
        return {"protocol": "trojan", "tag": tag, "settings": {"servers": [{"address": node["server"], "port": node["port"], "password": node["password"]}]}, "streamSettings": stream}
    if s == "ss":
        return {"protocol": "shadowsocks", "tag": tag, "settings": {"servers": [{"address": node["server"], "port": node["port"], "method": node["method"], "password": node["password"]}]}}
    raise ValueError(s)


def sing_outbound(node: dict, tag: str) -> dict:
    s = node["scheme"]
    if s == "vless":
        out = {"type": "vless", "tag": tag, "server": node["server"], "server_port": node["port"], "uuid": node["uuid"], "network": node["network"]}
        if node.get("tls") or node.get("reality"):
            out["tls"] = {"enabled": True, "server_name": node.get("sni") or node["server"]}
            if node.get("reality"): out["tls"]["reality"] = {"enabled": True, "public_key": node.get("pbk") or "", "short_id": node.get("sid") or ""}
            if node.get("fp"): out["tls"]["utls"] = {"enabled": True, "fingerprint": node["fp"]}
        if node["network"] == "ws": out["transport"] = {"type": "ws", "path": node.get("path") or "/", "headers": {"Host": node.get("host") or ""}}
        elif node["network"] == "grpc": out["transport"] = {"type": "grpc", "service_name": node.get("service_name") or ""}
        return out
    if s == "vmess":
        out = {"type": "vmess", "tag": tag, "server": node["server"], "server_port": node["port"], "uuid": node["uuid"], "security": node.get("cipher", "auto"), "alter_id": node.get("alter_id", 0), "network": node["network"]}
        if node.get("tls"): out["tls"] = {"enabled": True, "server_name": node.get("sni") or node["server"]}
        if node["network"] == "ws": out["transport"] = {"type": "ws", "path": node.get("path") or "/", "headers": {"Host": node.get("host") or ""}}
        return out
    if s == "trojan":
        out = {"type": "trojan", "tag": tag, "server": node["server"], "server_port": node["port"], "password": node["password"], "tls": {"enabled": True, "server_name": node.get("sni") or node["server"]}}
        if node["network"] == "ws": out["transport"] = {"type": "ws", "path": node.get("path") or "/", "headers": {"Host": node.get("host") or ""}}
        return out
    if s == "ss": return {"type": "shadowsocks", "tag": tag, "server": node["server"], "server_port": node["port"], "method": node["method"], "password": node["password"]}
    raise ValueError(s)


def mihomo_proxy(node: dict, name: str) -> dict:
    s = node["scheme"]
    if s == "vless":
        out = {"name": name, "type": "vless", "server": node["server"], "port": node["port"], "uuid": node["uuid"], "udp": False}
        if node.get("tls") or node.get("reality"): out.update({"tls": True, "servername": node.get("sni") or node["server"]})
        if node.get("fp"): out["client-fingerprint"] = node["fp"]
        if node.get("reality"): out["reality-opts"] = {"public-key": node.get("pbk", ""), "short-id": node.get("sid", "")}
        if node["network"] == "ws": out.update({"network": "ws", "ws-opts": {"path": node.get("path") or "/", "headers": {"Host": node.get("host") or ""}}})
        elif node["network"] == "grpc": out.update({"network": "grpc", "grpc-opts": {"grpc-service-name": node.get("service_name") or ""}})
        return out
    if s == "vmess":
        out = {"name": name, "type": "vmess", "server": node["server"], "port": node["port"], "uuid": node["uuid"], "alterId": node.get("alter_id", 0), "cipher": node.get("cipher", "auto"), "udp": False, "tls": node.get("tls", False), "servername": node.get("sni") or node["server"]}
        if node["network"] == "ws": out.update({"network": "ws", "ws-opts": {"path": node.get("path") or "/", "headers": {"Host": node.get("host") or ""}}})
        return out
    if s == "trojan":
        out = {"name": name, "type": "trojan", "server": node["server"], "port": node["port"], "password": node["password"], "udp": False, "sni": node.get("sni") or node["server"]}
        if node["network"] == "ws": out.update({"network": "ws", "ws-opts": {"path": node.get("path") or "/", "headers": {"Host": node.get("host") or ""}}})
        return out
    if s == "ss": return {"name": name, "type": "ss", "server": node["server"], "port": node["port"], "cipher": node["method"], "password": node["password"], "udp": False}
    raise ValueError(s)


def load_sample(limit: int) -> tuple[list[str], dict]:
    rows, seen = [], set(); parse_failed = 0
    for path in sorted((OUT / "countries").glob("*.txt")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            uri = line.strip()
            if not uri or uri in seen: continue
            try: node = parse_uri(uri)
            except Exception: parse_failed += 1; continue
            if node.get("port") not in {80, 443}: continue
            seen.add(uri); rows.append(uri)
            if len(rows) >= limit: return rows, {"parse_failed": parse_failed}
    return rows, {"parse_failed": parse_failed}


def wait_port(port: int, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2): return True
        except OSError: time.sleep(0.08)
    return False


def safe_run(cmd: list[str], timeout: float = 20.0):
    try: return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    except Exception as exc: return subprocess.CompletedProcess(cmd, 1, "", str(exc))


def socks5_http(port: int, host: str, path: str, use_tls: bool, expected_status: int, expected_body: str | None, timeout: float):
    start = time.perf_counter(); s = socket.create_connection(("127.0.0.1", port), timeout=timeout); s.settimeout(timeout)
    try:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00": return False, -1.0, "socks_auth"
        hb = host.encode("idna"); remote_port = 443 if use_tls else 80
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + remote_port.to_bytes(2, "big"))
        head = s.recv(4)
        if len(head) != 4 or head[1] != 0: return False, -1.0, "socks_connect"
        atyp = head[3]
        if atyp == 1: s.recv(4)
        elif atyp == 3: n = s.recv(1)[0]; s.recv(n)
        elif atyp == 4: s.recv(16)
        s.recv(2)
        conn = s
        if use_tls:
            import ssl
            conn = ssl.create_default_context().wrap_socket(s, server_hostname=host)
        conn.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: AhmedVPN-EngineBenchmark/3\r\n\r\n".encode())
        data = bytearray()
        while len(data) < 16384:
            chunk = conn.recv(min(4096, 16384 - len(data)))
            if not chunk: break
            data.extend(chunk)
            if b"\r\n\r\n" in data and expected_body is None: break
            if expected_body is not None and expected_body.encode() in data: break
        raw = bytes(data); first_line = raw.split(b"\r\n", 1)[0]
        if not first_line.startswith(b"HTTP/"): return False, -1.0, "no_http"
        parts = first_line.split(); status = int(parts[1]) if len(parts) > 1 else -1
        if status != expected_status: return False, -1.0, f"status_{status}"
        if expected_body is not None and expected_body.encode() not in raw: return False, -1.0, "body_mismatch"
        return True, round((time.perf_counter() - start) * 1000, 1), f"status_{status}"
    except Exception as exc: return False, -1.0, str(exc)[:160]
    finally:
        try: s.close()
        except Exception: pass


def probe_ports(ports: list[int], workers: int, timeout: float) -> dict:
    start = time.perf_counter(); results = []
    def one(index: int, port: int):
        ms_ok, ms_delay, ms_detail = socks5_http(port, *PROBES[0][1:], timeout)
        g_ok, g_delay, g_detail = socks5_http(port, *PROBES[1][1:], timeout)
        return {"index": index, "msft_ok": ms_ok, "google_204_ok": g_ok, "internet_healthy": ms_ok and g_ok, "delay_ms": min([x for x in (ms_delay, g_delay) if x > 0], default=-1), "details": {"msft": ms_detail, "google": g_detail}}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(one, i, port): i for i, port in enumerate(ports)}
        for future in as_completed(futs):
            try: results.append(future.result())
            except Exception as exc: results.append({"index": futs[future], "msft_ok": False, "google_204_ok": False, "internet_healthy": False, "delay_ms": -1, "details": {"exception": str(exc)[:160]}})
    elapsed = time.perf_counter() - start
    return {"candidates": len(ports), "healthy": sum(r["internet_healthy"] for r in results), "msft_ok": sum(r["msft_ok"] for r in results), "google_204_ok": sum(r["google_204_ok"] for r in results), "nodes_per_sec": round(len(ports) / max(elapsed, .001), 2), "probe_elapsed_s": round(elapsed, 2), "results": results}


def validate_per_node(kind: str, uris: list[str], root: Path, binary: Path) -> tuple[list[str], list[str]]:
    valid, failures = [], []
    for i, uri in enumerate(uris):
        try:
            if kind == "xray":
                out = xray_outbound(parse_uri(uri), "p1"); cfg = root / f"xray-one-{i}.json"; cfg.write_text(json.dumps({"log": {"loglevel": "error"}, "inbounds": [{"listen": "127.0.0.1", "port": 0, "protocol": "socks", "settings": {"udp": False}}], "outbounds": [out]}), encoding="utf-8")
                check = safe_run([str(binary), "run", "-test", "-c", str(cfg)], 10)
            else:
                out = sing_outbound(parse_uri(uri), "p1"); cfg = root / f"sing-one-{i}.json"; cfg.write_text(json.dumps({"log": {"level": "error"}, "outbounds": [out]}), encoding="utf-8")
                check = safe_run([str(binary), "check", "-c", str(cfg)], 10)
            if check.returncode == 0: valid.append(uri)
            else:
                detail = (check.stderr or check.stdout or "validation_failed").strip().replace("\n", " "); failures.append(f"{i+1}:{detail[:180]}")
        except Exception as exc: failures.append(f"{i+1}:{type(exc).__name__}:{str(exc)[:160]}")
    return valid, failures


def build_engine_config(kind: str, uris: list[str], root: Path):
    outs, ins, rules, valid, failures = [], [], [], [], []
    for i, uri in enumerate(uris):
        tag, itag, port = f"p{i+1}", f"in{i+1}", BASE_PORT + i
        try:
            node = parse_uri(uri)
            out = xray_outbound(node, tag) if kind == "xray" else sing_outbound(node, tag)
            outs.append(out)
            if kind == "xray":
                ins.append({"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": False}, "tag": itag})
                rules.append({"type": "field", "inboundTag": [itag], "outboundTag": tag})
            else:
                ins.append({"type": "socks", "tag": itag, "listen": "127.0.0.1", "listen_port": port})
                rules.append({"inbound": [itag], "action": "route", "outbound": tag})
            valid.append(uri)
        except Exception as exc: failures.append(f"{i+1}:{type(exc).__name__}:{str(exc)[:120]}")
    cfg = root / f"{kind}.json"
    if kind == "xray": payload = {"log": {"loglevel": "error"}, "inbounds": ins, "outbounds": outs, "routing": {"domainStrategy": "AsIs", "rules": rules}}
    else: payload = {"log": {"level": "error"}, "inbounds": ins, "outbounds": outs, "route": {"rules": rules, "final": outs[0]["tag"] if outs else ""}}
    cfg.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return cfg, valid, failures


def start_engine(kind: str, uris: list[str], root: Path):
    path = resolve_binary(XRAY if kind == "xray" else SING_BOX, kind if kind == "sing-box" else "xray")
    if path is None: return {"engine": kind, "status": "unavailable"}, None, []
    cfg, valid, build_failures = build_engine_config(kind, uris, root)
    check_cmd = [str(path), "run", "-test", "-c", str(cfg)] if kind == "xray" else [str(path), "check", "-c", str(cfg)]
    check = safe_run(check_cmd, 30)
    if check.returncode != 0:
        valid, validation_failures = validate_per_node(kind, uris, root, path)
        if not valid: return {"engine": kind, "status": "config_rejected", "config_nodes": 0, "skipped": len(uris), "stderr": (check.stderr or check.stdout)[-1500:], "validation_failures": validation_failures[-20:]}, None, valid
        cfg, valid, build_failures = build_engine_config(kind, valid, root)
        check = safe_run(check_cmd[:2] + ["-test", "-c", str(cfg)] if kind == "xray" else [str(path), "check", "-c", str(cfg)], 30)
        if check.returncode != 0: return {"engine": kind, "status": "config_rejected", "config_nodes": len(valid), "stderr": (check.stderr or check.stdout)[-1500:]}, None, valid
    proc = subprocess.Popen([str(path), "run", "-c", str(cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if not wait_port(BASE_PORT, 10):
        try: err = proc.stderr.read()[-2000:] if proc.stderr else ""
        except Exception: err = ""
        proc.terminate(); return {"engine": kind, "status": "failed_to_start", "config_nodes": len(valid), "stderr": err}, None, valid
    return {"engine": kind, "status": "running", "config_nodes": len(valid), "skipped": len(uris)-len(valid), "config_build_failures": build_failures[-20:]}, proc, valid


def resolve_binary(path: Path, prefix: str) -> Path | None:
    if path.is_file(): return path
    if path.parent.exists():
        candidates = sorted([p for p in path.parent.iterdir() if p.is_file() and p.name.startswith(prefix)])
        if candidates: return candidates[0]
    return None


def run_single_engine(kind: str, uris: list[str], workers: int, timeout: float, root: Path) -> dict:
    start = time.perf_counter(); info, proc, valid = start_engine(kind, uris, root)
    if proc is None:
        info["elapsed_s"] = round(time.perf_counter()-start, 2); return info
    try: probe = probe_ports([BASE_PORT+i for i in range(len(valid))], workers, timeout)
    finally:
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill()
    info.update(probe); info["elapsed_s"] = round(time.perf_counter()-start, 2); info["status"] = "ok"; return info


def run_mihomo(uris: list[str], timeout: float) -> dict:
    import requests
    binary = resolve_binary(MIHOMO, "mihomo")
    if binary is None: return {"engine": "mihomo", "status": "unavailable", "reason": str(MIHOMO)}
    start = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="bench-mihomo-") as td:
        root = Path(td); proxies=[]; skipped=0
        for i, uri in enumerate(uris):
            try: proxies.append(mihomo_proxy(parse_uri(uri), f"p{i+1}"))
            except Exception: skipped += 1
        if not proxies: return {"engine":"mihomo","status":"config_rejected","config_proxies":0,"skipped":skipped}
        api_port = API_PORT; cfg = root/"config.yaml"
        cfg.write_text(yaml.safe_dump({"mixed-port": api_port+1, "allow-lan": False, "mode": "rule", "log-level": "silent", "external-controller": f"127.0.0.1:{api_port}", "proxies": proxies, "rules": [f"MATCH,{proxies[0]['name']}"]}, sort_keys=False), encoding="utf-8")
        check = safe_run([str(binary), "-t", "-f", str(cfg)], 30)
        if check.returncode != 0: return {"engine":"mihomo","status":"config_rejected","config_proxies":len(proxies),"skipped":skipped,"stderr":(check.stderr or check.stdout)[-1500:]}
        proc = subprocess.Popen([str(binary), "-f", str(cfg), "-d", str(root)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if not wait_port(api_port, 10):
            try: err=proc.stderr.read()[-2000:] if proc.stderr else ""
            except Exception: err=""
            proc.terminate(); return {"engine":"mihomo","status":"failed_to_start","config_proxies":len(proxies),"stderr":err}
        def one(i):
            name=f"p{i+1}"; url=f"http://127.0.0.1:{api_port}/proxies/{urllib.parse.quote(name,safe='')}/delay"; params={"url":f"http://{PROBES[0][1]}{PROBES[0][2]}","timeout":int(timeout*1000),"expected":str(PROBES[0][4])}; t=time.perf_counter()
            try:
                r=requests.get(url,params=params,timeout=timeout+3); obj=r.json(); ok=r.ok and int(obj.get("delay",-1))>=0; return i,ok,round((time.perf_counter()-t)*1000,1),r.text[:200]
            except Exception as exc: return i,False,-1,str(exc)[:160]
        rows=[]; w=max(1,min(80,max(8,(os.cpu_count() or 2)*8)))
        with ThreadPoolExecutor(max_workers=w) as ex:
            futs=[ex.submit(one,i) for i in range(len(proxies))]
            for f in as_completed(futs):
                i,ok,delay,detail=f.result(); rows.append({"index":i,"healthy":ok,"delay_ms":delay,"detail":detail})
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill()
        elapsed=time.perf_counter()-start
        return {"engine":"mihomo","status":"ok","candidates":len(uris),"config_proxies":len(proxies),"skipped":skipped,"healthy":sum(1 for r in rows if r["healthy"]),"nodes_per_sec":round(len(proxies)/max(elapsed,.001),2),"elapsed_s":round(elapsed,2),"results":rows}


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--limit",type=int,default=DEFAULT_NODES); ap.add_argument("--workers",type=int,default=DEFAULT_WORKERS); ap.add_argument("--timeout",type=float,default=DEFAULT_TIMEOUT); ap.add_argument("--out",default=str(OUT/"metadata"/"engine_benchmark.json")); args=ap.parse_args()
    uris, meta = load_sample(args.limit)
    if not uris: raise SystemExit("No eligible benchmark nodes found")
    report={"schema":2,"generated_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"sample_requested":args.limit,"sample_loaded":len(uris),"load":meta,"workers":args.workers,"timeout_s":args.timeout,"targets":{"primary":f"http://{PROBES[0][1]}{PROBES[0][2]}","secondary":f"http://{PROBES[1][1]}{PROBES[1][2]}"},"engines":[]}
    with tempfile.TemporaryDirectory(prefix="engine-benchmark-") as td:
        root=Path(td)
        for kind in ("xray","sing-box"): report["engines"].append(run_single_engine(kind,uris,args.workers,args.timeout,root))
        report["engines"].append(run_mihomo(uris,args.timeout))
    out=Path(args.out); out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    keys=("engine","status","candidates","config_nodes","config_proxies","skipped","healthy","msft_ok","google_204_ok","nodes_per_sec","probe_elapsed_s","elapsed_s")
    for e in report["engines"]: print(json.dumps({k:e.get(k) for k in keys},ensure_ascii=False))

if __name__=="__main__": main()
