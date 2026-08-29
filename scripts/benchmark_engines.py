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
MSFT_HOST = "www.msftconnecttest.com"
MSFT_PATH = "/connecttest.txt"
MSFT_EXPECTED = b"Microsoft Connect Test"
GOOGLE_HOST = "www.gstatic.com"
GOOGLE_PATH = "/generate_204"


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def q(uri: str) -> dict[str, list[str]]:
    return urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query, keep_blank_values=True)


def first(params, *keys, default=""):
    for key in keys:
        if params.get(key):
            return urllib.parse.unquote(params[key][0])
    return default


def scheme(uri: str) -> str:
    return urllib.parse.urlsplit(uri).scheme.lower()


def decode_vmess(uri: str) -> dict:
    raw = uri.split("vmess://", 1)[1].split("#", 1)[0]
    return json.loads(b64d(raw).decode())


def parse_uri(uri: str) -> dict:
    s = scheme(uri)
    p = urllib.parse.urlsplit(uri)
    params = q(uri)
    remark = urllib.parse.unquote(p.fragment or "")
    if s == "vmess":
        obj = decode_vmess(uri)
        return {"scheme": s, "remark": remark, "server": obj.get("add"), "port": int(obj.get("port")), "uuid": obj.get("id"), "network": (obj.get("net") or "tcp").lower(), "path": obj.get("path") or "/", "host": obj.get("host") or "", "tls": bool(obj.get("tls")), "reality": False, "sni": obj.get("sni") or obj.get("host") or obj.get("add"), "alter_id": int(obj.get("aid", 0) or 0), "cipher": obj.get("scy") or "auto"}
    if s == "vless":
        return {"scheme": s, "remark": remark, "server": p.hostname, "port": p.port or 443, "uuid": urllib.parse.unquote(p.username or ""), "network": first(params, "type", default="tcp"), "path": first(params, "path", default="/"), "host": first(params, "host"), "tls": first(params, "security") == "tls", "reality": first(params, "security") == "reality", "sni": first(params, "sni", "serverName", default=p.hostname), "fp": first(params, "fp", default="chrome"), "pbk": first(params, "pbk"), "sid": first(params, "sid"), "service_name": first(params, "serviceName")}
    if s == "trojan":
        return {"scheme": s, "remark": remark, "server": p.hostname, "port": p.port or 443, "password": urllib.parse.unquote(p.username or ""), "network": first(params, "type", default="tcp"), "path": first(params, "path", default="/"), "host": first(params, "host"), "tls": first(params, "security", default="tls") == "tls", "reality": False, "sni": first(params, "sni", default=p.hostname), "service_name": first(params, "serviceName")}
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
        host, port = hp.rsplit(":", 1)
        method, password = userinfo.split(":", 1)
        return {"scheme": s, "remark": remark, "server": host, "port": int(port), "method": method, "password": password}
    raise ValueError(f"unsupported scheme: {s}")


def sing_outbound(node: dict, tag: str) -> dict:
    s = node["scheme"]
    if s == "vless":
        out = {"type": "vless", "tag": tag, "server": node["server"], "server_port": node["port"], "uuid": node["uuid"], "network": node["network"]}
        if node.get("reality"):
            out["tls"] = {"enabled": True, "server_name": node["sni"], "reality": {"enabled": True, "public_key": node.get("pbk", ""), "short_id": node.get("sid", "")}, "utls": {"enabled": True, "fingerprint": node.get("fp", "chrome")}}
        elif node.get("tls"):
            out["tls"] = {"enabled": True, "server_name": node["sni"], "utls": {"enabled": True, "fingerprint": node.get("fp", "chrome")}}
        if node["network"] == "ws":
            out["transport"] = {"type": "ws", "path": node.get("path") or "/", "headers": {"Host": node.get("host") or ""}}
        elif node["network"] == "grpc":
            out["transport"] = {"type": "grpc", "service_name": node.get("service_name", "")}
        return out
    if s == "vmess":
        out = {"type": "vmess", "tag": tag, "server": node["server"], "server_port": node["port"], "uuid": node["uuid"], "security": node.get("cipher", "auto"), "alter_id": node.get("alter_id", 0), "network": node["network"]}
        if node.get("tls"): out["tls"] = {"enabled": True, "server_name": node["sni"]}
        if node["network"] == "ws": out["transport"] = {"type": "ws", "path": node.get("path") or "/", "headers": {"Host": node.get("host") or ""}}
        return out
    if s == "trojan":
        out = {"type": "trojan", "tag": tag, "server": node["server"], "server_port": node["port"], "password": node["password"]}
        if node.get("tls"): out["tls"] = {"enabled": True, "server_name": node["sni"]}
        if node["network"] == "ws": out["transport"] = {"type": "ws", "path": node.get("path") or "/", "headers": {"Host": node.get("host") or ""}}
        return out
    if s == "ss": return {"type": "shadowsocks", "tag": tag, "server": node["server"], "server_port": node["port"], "method": node["method"], "password": node["password"]}
    raise ValueError(s)


def mihomo_proxy(node: dict, name: str) -> dict:
    s = node["scheme"]
    if s == "vless":
        out = {"name": name, "type": "vless", "server": node["server"], "port": node["port"], "uuid": node["uuid"], "udp": False}
        if node.get("tls") or node.get("reality"):
            out["tls"] = True; out["servername"] = node["sni"]
        if node.get("fp"): out["client-fingerprint"] = node["fp"]
        if node.get("reality"): out["reality-opts"] = {"public-key": node.get("pbk", ""), "short-id": node.get("sid", "")}
        if node["network"] == "ws": out["network"] = "ws"; out["ws-opts"] = {"path": node.get("path") or "/", "headers": {"Host": node.get("host") or ""}}
        elif node["network"] == "grpc": out["network"] = "grpc"; out["grpc-opts"] = {"grpc-service-name": node.get("service_name", "")}
        return out
    if s == "vmess":
        out = {"name": name, "type": "vmess", "server": node["server"], "port": node["port"], "uuid": node["uuid"], "alterId": node.get("alter_id", 0), "cipher": node.get("cipher", "auto"), "udp": False, "tls": node.get("tls", False), "servername": node["sni"]}
        if node["network"] == "ws": out["network"] = "ws"; out["ws-opts"] = {"path": node.get("path") or "/", "headers": {"Host": node.get("host") or ""}}
        return out
    if s == "trojan":
        out = {"name": name, "type": "trojan", "server": node["server"], "port": node["port"], "password": node["password"], "udp": False, "sni": node["sni"]}
        if node["network"] == "ws": out["network"] = "ws"; out["ws-opts"] = {"path": node.get("path") or "/", "headers": {"Host": node.get("host") or ""}}
        return out
    if s == "ss": return {"name": name, "type": "ss", "server": node["server"], "port": node["port"], "cipher": node["method"], "password": node["password"], "udp": False}
    raise ValueError(s)


def load_sample(limit: int) -> list[str]:
    rows=[]; seen=set()
    for path in sorted((OUT/"countries").glob("*.txt")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            uri=line.strip()
            if not uri or uri in seen: continue
            try: node=parse_uri(uri)
            except Exception: continue
            if node.get("port") not in {80,443}: continue
            seen.add(uri); rows.append(uri)
            if len(rows)>=limit: return rows
    return rows


def wait_port(port:int, timeout:float=10.0)->bool:
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        try:
            with socket.create_connection(("127.0.0.1",port),timeout=.2): return True
        except OSError: time.sleep(.08)
    return False


def socks_http(port:int, host:str, path:str, timeout:float):
    start=time.perf_counter(); s=socket.create_connection(("127.0.0.1",port),timeout=timeout); s.settimeout(timeout)
    try:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2)!=b"\x05\x00": return False,-1,"socks_auth"
        hb=host.encode("idna"); s.sendall(b"\x05\x01\x00\x03"+bytes([len(hb)])+hb+(80).to_bytes(2,"big"))
        head=s.recv(4)
        if len(head)!=4 or head[1]!=0: return False,-1,"socks_connect"
        atyp=head[3]
        if atyp==1: s.recv(4)
        elif atyp==3: ln=s.recv(1)[0]; s.recv(ln)
        elif atyp==4: s.recv(16)
        s.recv(2)
        req=f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: AhmedVPN-Benchmark/1\r\n\r\n".encode(); s.sendall(req)
        data=b""
        while len(data)<8192:
            chunk=s.recv(2048)
            if not chunk: break
            data+=chunk
            if b"\r\n\r\n" in data: break
        if not data.startswith(b"HTTP/"): return False,-1,"no_http"
        status=data.split(b"\r\n",1)[0].decode("latin1","replace"); return True,round((time.perf_counter()-start)*1000,1),f"{status}|{data.split(b'\r\n\r\n',1)[1][:128]!r}"
    except Exception as exc: return False,-1,str(exc)[:120]
    finally: s.close()


def probe_port(port:int, timeout:float)->dict:
    ok1,d1,det1=socks_http(port,MSFT_HOST,MSFT_PATH,timeout); msft=ok1 and " 200 " in det1 and MSFT_EXPECTED.decode() in det1
    ok2,d2,det2=socks_http(port,GOOGLE_HOST,GOOGLE_PATH,timeout); google=ok2 and " 204 " in det2
    return {"msft_ok":msft,"google_204_ok":google,"internet_healthy":msft and google,"delay_ms":min([x for x in (d1,d2) if x>0], default=-1),"details":{"msft":det1,"google":det2}}


def probe_ports(uris, workers, timeout):
    start=time.perf_counter(); results=[]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs={ex.submit(probe_port,BASE_PORT+i,timeout):i for i in range(len(uris))}
        for f in as_completed(futs):
            i=futs[f]
            try:r=f.result()
            except Exception as exc:r={"msft_ok":False,"google_204_ok":False,"internet_healthy":False,"delay_ms":-1,"details":{"exception":str(exc)[:120]}}
            results.append({"index":i,**r})
    elapsed=time.perf_counter()-start
    return {"candidates":len(uris),"healthy":sum(r["internet_healthy"] for r in results),"msft_ok":sum(r["msft_ok"] for r in results),"google_204_ok":sum(r["google_204_ok"] for r in results),"nodes_per_sec":round(len(uris)/max(elapsed,.001),2),"probe_elapsed_s":round(elapsed,2),"results":results}


def run_multi_engine(kind, uris, workers, timeout):
    start=time.perf_counter()
    with tempfile.TemporaryDirectory(prefix=f"bench-{kind}-") as td:
        root=Path(td)
        if kind=="xray":
            if not XRAY.exists(): return {"engine":kind,"status":"unavailable","reason":str(XRAY)}
            from real_delay import outbound_for as xray_outbound_for
            outs=[]; ins=[]; rules=[]
            for i,uri in enumerate(uris):
                tag=f"p{i+1}"; itag=f"in{i+1}"; port=BASE_PORT+i
                o=xray_outbound_for(uri); o["tag"]=tag; outs.append(o)
                ins.append({"listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"udp":False},"tag":itag})
                rules.append({"type":"field","inboundTag":[itag],"outboundTag":tag})
            cfg=root/"config.json"; cfg.write_text(json.dumps({"log":{"loglevel":"error"},"inbounds":ins,"outbounds":outs,"routing":{"domainStrategy":"AsIs","rules":rules}}),encoding="utf-8")
            proc=subprocess.Popen([str(XRAY),"run","-c",str(cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            ok=all(wait_port(BASE_PORT+i) for i in range(min(10,len(uris))))
            if not ok:
                proc.terminate(); proc.wait(timeout=2); return {"engine":kind,"status":"failed_to_start"}
            res=probe_ports(uris,workers,timeout)
            proc.terminate()
            try:proc.wait(timeout=3)
            except subprocess.TimeoutExpired:proc.kill()
        elif kind=="sing-box":
            if not SING_BOX.exists(): return {"engine":kind,"status":"unavailable","reason":str(SING_BOX)}
            outs=[]; ins=[]; rules=[]
            for i,uri in enumerate(uris):
                node=parse_uri(uri); tag=f"p{i+1}"; itag=f"in{i+1}"; port=BASE_PORT+i
                outs.append(sing_outbound(node,tag)); ins.append({"type":"socks","tag":itag,"listen":"127.0.0.1","listen_port":port}); rules.append({"inbound":[itag],"action":"route","outbound":tag})
            cfg=root/"config.json"; cfg.write_text(json.dumps({"log":{"level":"error"},"inbounds":ins,"outbounds":outs,"route":{"rules":rules,"final":outs[0]["tag"] if outs else ""}}),encoding="utf-8")
            chk=subprocess.run([str(SING_BOX),"check","-c",str(cfg)],text=True,capture_output=True)
            if chk.returncode!=0: return {"engine":kind,"status":"config_rejected","stderr":chk.stderr[-1500:]}
            proc=subprocess.Popen([str(SING_BOX),"run","-c",str(cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            ok=all(wait_port(BASE_PORT+i) for i in range(min(10,len(uris))))
            if not ok:
                proc.terminate(); proc.wait(timeout=2); return {"engine":kind,"status":"failed_to_start"}
            res=probe_ports(uris,workers,timeout)
            proc.terminate()
            try:proc.wait(timeout=3)
            except subprocess.TimeoutExpired:proc.kill()
        else: raise ValueError(kind)
    res.update({"engine":kind,"status":"ok","elapsed_s":round(time.perf_counter()-start,2),"config_nodes":len(uris)})
    return res


def run_mihomo(uris, timeout):
    import requests
    start=time.perf_counter()
    if not MIHOMO.exists(): return {"engine":"mihomo","status":"unavailable","reason":str(MIHOMO)}
    with tempfile.TemporaryDirectory(prefix="bench-mihomo-") as td:
        root=Path(td); cfg=root/"config.yaml"; api_port=19090; proxies=[]; skipped=0
        for i,uri in enumerate(uris):
            try: proxies.append(mihomo_proxy(parse_uri(uri),f"p{i+1}"))
            except Exception: skipped+=1
        config={"mixed-port":18888,"allow-lan":False,"mode":"rule","log-level":"silent","external-controller":f"127.0.0.1:{api_port}","proxies":proxies,"rules":["MATCH,"+proxies[0]["name"]] if proxies else ["MATCH,DIRECT"]}
        cfg.write_text(yaml.safe_dump(config,sort_keys=False),encoding="utf-8")
        chk=subprocess.run([str(MIHOMO),"-t","-f",str(cfg)],text=True,capture_output=True)
        if chk.returncode!=0: return {"engine":"mihomo","status":"config_rejected","config_proxies":len(proxies),"skipped":skipped,"stderr":chk.stderr[-1500:]}
        proc=subprocess.Popen([str(MIHOMO),"-f",str(cfg),"-d",str(root)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if not wait_port(api_port,8):
            proc.terminate(); proc.wait(timeout=2); return {"engine":"mihomo","status":"failed_to_start","config_proxies":len(proxies)}
        def one(i):
            name=f"p{i+1}"; url=f"http://127.0.0.1:{api_port}/proxies/{urllib.parse.quote(name,safe='')}/delay"; params={"url":f"http://{MSFT_HOST}{MSFT_PATH}","timeout":int(timeout*1000),"expected":"200"}; t=time.perf_counter()
            try:
                r=requests.get(url,params=params,timeout=timeout+2); obj=r.json(); ok=r.ok and int(obj.get("delay",-1))>=0; return i,ok,round((time.perf_counter()-t)*1000,1),r.text[:200]
            except Exception as exc:return i,False,-1,str(exc)[:120]
        rows=[]; healthy=0
        with ThreadPoolExecutor(max_workers=min(80,max(8,(os.cpu_count() or 2)*8))) as ex:
            futs=[ex.submit(one,i) for i in range(len(proxies))]
            for f in as_completed(futs):
                i,ok,delay,detail=f.result(); rows.append({"index":i,"healthy":ok,"delay_ms":delay,"detail":detail}); healthy+=int(ok)
        proc.terminate()
        try:proc.wait(timeout=3)
        except subprocess.TimeoutExpired:proc.kill()
        elapsed=time.perf_counter()-start
        return {"engine":"mihomo","status":"ok","candidates":len(uris),"config_proxies":len(proxies),"skipped":skipped,"healthy":healthy,"nodes_per_sec":round(len(proxies)/max(elapsed,.001),2),"elapsed_s":round(elapsed,2),"results":rows}


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--limit",type=int,default=DEFAULT_NODES); ap.add_argument("--workers",type=int,default=DEFAULT_WORKERS); ap.add_argument("--timeout",type=float,default=DEFAULT_TIMEOUT); ap.add_argument("--out",default=str(OUT/"metadata"/"engine_benchmark.json")); args=ap.parse_args()
    uris=load_sample(args.limit)
    if not uris: raise SystemExit("No eligible benchmark nodes found")
    report={"generated_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"sample_requested":args.limit,"sample_loaded":len(uris),"workers":args.workers,"timeout_s":args.timeout,"targets":{"primary":f"http://{MSFT_HOST}{MSFT_PATH}","secondary":f"http://{GOOGLE_HOST}{GOOGLE_PATH}"},"engines":[]}
    for kind in ("xray","sing-box"): report["engines"].append(run_multi_engine(kind,uris,args.workers,args.timeout))
    report["engines"].append(run_mihomo(uris,args.timeout))
    Path(args.out).parent.mkdir(parents=True,exist_ok=True); Path(args.out).write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    for e in report["engines"]: print(json.dumps({k:e.get(k) for k in ("engine","status","candidates","config_nodes","config_proxies","skipped","healthy","msft_ok","google_204_ok","nodes_per_sec","probe_elapsed_s","elapsed_s")},ensure_ascii=False))

if __name__=="__main__": main()
