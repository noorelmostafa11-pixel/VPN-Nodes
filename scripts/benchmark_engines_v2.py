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

import requests
import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
XRAY = Path(os.environ.get("XRAY_BIN", "/opt/hostedtoolcache/xray/xray"))
SING = Path(os.environ.get("SING_BOX_BIN", "/opt/hostedtoolcache/sing-box/sing-box"))
MIHOMO = Path(os.environ.get("MIHOMO_BIN", "/opt/hostedtoolcache/mihomo/mihomo"))
BASE_PORT = 18000
API_PORT = 19090
MSFT = ("www.msftconnecttest.com", "/connecttest.txt", 200, b"Microsoft Connect Test")
GOOGLE = ("www.gstatic.com", "/generate_204", 204, None)


def b64d(v: str) -> bytes:
    return base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))


def params(uri: str):
    return urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query, keep_blank_values=True)


def first(p, *keys, default=""):
    for k in keys:
        if p.get(k):
            return urllib.parse.unquote(p[k][0])
    return default


def parse_uri(uri: str) -> dict:
    s = urllib.parse.urlsplit(uri)
    scheme = s.scheme.lower()
    p = params(uri)
    if scheme == "vmess":
        raw = uri.split("vmess://", 1)[1].split("#", 1)[0]
        o = json.loads(b64d(raw).decode())
        return {"scheme": "vmess", "server": o["add"], "port": int(o["port"]), "uuid": o["id"], "network": str(o.get("net") or "tcp").lower(), "path": o.get("path") or "/", "host": o.get("host") or "", "tls": str(o.get("tls") or "").lower() not in ("", "none", "false", "0"), "sni": o.get("sni") or o.get("host") or o["add"], "alter_id": int(o.get("aid", 0) or 0), "cipher": o.get("scy") or "auto"}
    if scheme == "vless":
        return {"scheme": "vless", "server": s.hostname, "port": s.port or 443, "uuid": urllib.parse.unquote(s.username or ""), "network": first(p, "type", default="tcp").lower(), "path": first(p, "path", default="/"), "host": first(p, "host"), "security": first(p, "security"), "tls": first(p, "security") == "tls", "reality": first(p, "security") == "reality", "sni": first(p, "sni", "serverName", default=s.hostname), "fp": first(p, "fp", default="chrome"), "pbk": first(p, "pbk"), "sid": first(p, "sid"), "service_name": first(p, "serviceName")}
    if scheme == "trojan":
        return {"scheme": "trojan", "server": s.hostname, "port": s.port or 443, "password": urllib.parse.unquote(s.username or ""), "network": first(p, "type", default="tcp").lower(), "path": first(p, "path", default="/"), "host": first(p, "host"), "tls": True, "sni": first(p, "sni", default=s.hostname), "service_name": first(p, "serviceName")}
    if scheme == "ss":
        raw = uri.split("ss://", 1)[1].split("#", 1)[0]
        if "@" in raw:
            ui, hp = raw.rsplit("@", 1)
            try: ui = b64d(ui).decode()
            except Exception: ui = urllib.parse.unquote(ui)
        else:
            decoded = b64d(raw).decode()
            ui, hp = decoded.rsplit("@", 1)
        if hp.startswith("["):
            host, port = hp.rsplit("]:", 1); host = host[1:]
        else:
            host, port = hp.rsplit(":", 1)
        method, password = urllib.parse.unquote(ui).split(":", 1)
        return {"scheme": "ss", "server": host, "port": int(port), "method": method, "password": password}
    raise ValueError(f"unsupported scheme {scheme}")


def load_same_sample(limit: int):
    rows=[]; seen=set()
    for path in sorted((OUT / "countries").glob("*.txt")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            uri=line.strip()
            if not uri or uri in seen or not uri.lower().startswith(("vless://","vmess://","trojan://","ss://")): continue
            seen.add(uri); rows.append(uri)
            if len(rows) == limit: return rows
    return rows


def wait_port(port, timeout=10):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2): return True
        except OSError: time.sleep(.05)
    return False


def socks_http(port, host, path, timeout):
    t=time.perf_counter(); s=socket.create_connection(("127.0.0.1", port), timeout=timeout); s.settimeout(timeout)
    try:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00": return False,-1,"socks-auth"
        hb=host.encode("idna"); s.sendall(b"\x05\x01\x00\x03"+bytes([len(hb)])+hb+(80).to_bytes(2,"big"))
        h=s.recv(4)
        if len(h)!=4 or h[1]!=0: return False,-1,"socks-connect"
        if h[3]==1: s.recv(4)
        elif h[3]==3: s.recv(s.recv(1)[0])
        elif h[3]==4: s.recv(16)
        s.recv(2); s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: AhmedVPN-Engine-Benchmark/4\r\n\r\n".encode())
        data=b""
        while len(data)<8192:
            c=s.recv(2048)
            if not c: break
            data+=c
            if b"\r\n\r\n" in data: break
        if not data.startswith(b"HTTP/"): return False,-1,"no-http"
        head,_,body=data.partition(b"\r\n\r\n")
        return True,round((time.perf_counter()-t)*1000,1),head.split(b"\r\n",1)[0].decode(errors="replace")+"|"+repr(body[:256])
    except Exception as e: return False,-1,str(e)[:160]
    finally: s.close()


def probe(port, timeout):
    a,da,xa=socks_http(port,MSFT[0],MSFT[1],timeout); msft=a and " 200 " in xa and MSFT[3].decode() in xa
    b,db,xb=socks_http(port,GOOGLE[0],GOOGLE[1],timeout); google=b and " 204 " in xb
    return {"msft_ok":msft,"google_204_ok":google,"internet_healthy":msft and google,"delay_ms":min([d for d in (da,db) if d>0],default=-1),"details":{"msft":xa,"google":xb}}


def xray_outbound(uri, tag):
    from real_delay import outbound_for
    o=outbound_for(uri); o["tag"]=tag; return o


def sing_out(node, tag):
    s=node["scheme"]
    if s=="vless":
        o={"type":"vless","tag":tag,"server":node["server"],"server_port":node["port"],"uuid":node["uuid"],"network":node["network"]}
        if node.get("tls") or node.get("reality"):
            o["tls"]={"enabled":True,"server_name":node["sni"]}
            if node.get("reality"): o["tls"]["reality"]={"enabled":True,"public_key":node.get("pbk",""),"short_id":node.get("sid","")}
            o["tls"]["utls"]={"enabled":True,"fingerprint":node.get("fp","chrome")}
        if node["network"]=="ws": o["transport"]={"type":"ws","path":node.get("path") or "/","headers":{"Host":node.get("host","")}}
        elif node["network"]=="grpc": o["transport"]={"type":"grpc","service_name":node.get("service_name","")}
        return o
    if s=="vmess":
        o={"type":"vmess","tag":tag,"server":node["server"],"server_port":node["port"],"uuid":node["uuid"],"security":node.get("cipher","auto"),"alter_id":node.get("alter_id",0),"network":node["network"]}
        if node.get("tls"): o["tls"]={"enabled":True,"server_name":node["sni"]}
        if node["network"]=="ws": o["transport"]={"type":"ws","path":node.get("path") or "/","headers":{"Host":node.get("host","")}}
        return o
    if s=="trojan":
        o={"type":"trojan","tag":tag,"server":node["server"],"server_port":node["port"],"password":node["password"],"tls":{"enabled":True,"server_name":node["sni"]},"network":node["network"]}
        if node["network"]=="ws": o["transport"]={"type":"ws","path":node.get("path") or "/","headers":{"Host":node.get("host","")}}
        elif node["network"]=="grpc": o["transport"]={"type":"grpc","service_name":node.get("service_name","")}
        return o
    if s=="ss": return {"type":"shadowsocks","tag":tag,"server":node["server"],"server_port":node["port"],"method":node["method"],"password":node["password"]}
    raise ValueError(s)


def mihomo_out(node,name):
    s=node["scheme"]
    if s=="vless":
        o={"name":name,"type":"vless","server":node["server"],"port":node["port"],"uuid":node["uuid"],"udp":False}
        if node.get("tls") or node.get("reality"): o.update({"tls":True,"servername":node["sni"]})
        if node.get("fp"): o["client-fingerprint"]=node["fp"]
        if node.get("reality"): o["reality-opts"]={"public-key":node.get("pbk",""),"short-id":node.get("sid","")}
        if node["network"]=="ws": o.update({"network":"ws","ws-opts":{"path":node.get("path") or "/","headers":{"Host":node.get("host","")}}})
        elif node["network"]=="grpc": o.update({"network":"grpc","grpc-opts":{"grpc-service-name":node.get("service_name","")}})
        return o
    if s=="vmess":
        o={"name":name,"type":"vmess","server":node["server"],"port":node["port"],"uuid":node["uuid"],"alterId":node.get("alter_id",0),"cipher":node.get("cipher","auto"),"udp":False,"tls":node.get("tls",False),"servername":node["sni"]}
        if node["network"]=="ws": o.update({"network":"ws","ws-opts":{"path":node.get("path") or "/","headers":{"Host":node.get("host","")}}})
        return o
    if s=="trojan":
        o={"name":name,"type":"trojan","server":node["server"],"port":node["port"],"password":node["password"],"udp":False,"sni":node["sni"],"tls":True}
        if node["network"]=="ws": o.update({"network":"ws","ws-opts":{"path":node.get("path") or "/","headers":{"Host":node.get("host","")}}})
        elif node["network"]=="grpc": o.update({"network":"grpc","grpc-opts":{"grpc-service-name":node.get("service_name","")}})
        return o
    if s=="ss": return {"name":name,"type":"ss","server":node["server"],"port":node["port"],"cipher":node["method"],"password":node["password"],"udp":False}
    raise ValueError(s)


def preflight(kind, uris, workers):
    ok=[]; failed=[]
    def one(i):
        with tempfile.TemporaryDirectory(prefix=f"pf-{kind}-") as td:
            try:
                node=parse_uri(uris[i])
                if kind=="sing-box":
                    out=sing_out(node,"probe"); cfg=Path(td)/"c.json"; cfg.write_text(json.dumps({"log":{"level":"error"},"outbounds":[out,{"type":"direct","tag":"direct"}],"route":{"final":"direct"}})); cmd=[str(SING),"check","-c",str(cfg)]
                else:
                    proxy=mihomo_out(node,"probe"); cfg=Path(td)/"c.yaml"; cfg.write_text(yaml.safe_dump({"mixed-port":18888,"allow-lan":False,"mode":"rule","log-level":"silent","proxies":[proxy],"rules":["MATCH,DIRECT"]},sort_keys=False)); cmd=[str(MIHOMO),"-t","-f",str(cfg)]
                r=subprocess.run(cmd,text=True,capture_output=True,timeout=15)
                return i, None if r.returncode==0 else (r.stderr or r.stdout or "config check failed")[-800:]
            except Exception as e: return i,str(e)[:800]
    with ThreadPoolExecutor(max_workers=min(workers,24)) as ex:
        fs=[ex.submit(one,i) for i in range(len(uris))]
        for f in as_completed(fs):
            i,reason=f.result()
            if reason is None: ok.append(i)
            else: failed.append({"index":i,"reason":reason})
    return sorted(ok),sorted(failed,key=lambda x:x["index"])


def run_xray(uris,workers,timeout):
    start=time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="bench-xray-") as td:
        ins=[]; outs=[]; rules=[]; accepted=[]; failed=[]
        for i,u in enumerate(uris):
            try:
                tag=f"p{i+1}"; it=f"in{i+1}"; outs.append(xray_outbound(u,tag)); ins.append({"listen":"127.0.0.1","port":BASE_PORT+len(accepted),"protocol":"socks","settings":{"udp":False},"tag":it}); rules.append({"type":"field","inboundTag":[it],"outboundTag":tag}); accepted.append(i)
            except Exception as e: failed.append({"index":i,"reason":str(e)[:200]})
        cfg=Path(td)/"c.json"; cfg.write_text(json.dumps({"log":{"loglevel":"error"},"inbounds":ins,"outbounds":outs,"routing":{"domainStrategy":"AsIs","rules":rules}}))
        p=subprocess.Popen([str(XRAY),"run","-c",str(cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if accepted and not wait_port(BASE_PORT,10): p.kill(); p.wait(); return {"engine":"xray","status":"failed_to_start","candidates":len(uris),"compatible":len(accepted),"tested":0,"healthy":0,"parse_or_config_failed":failed}
        r=probe_many(accepted,workers,timeout); p.terminate();
        try:p.wait(3)
        except subprocess.TimeoutExpired:p.kill()
    return {"engine":"xray","status":"ok","candidates":len(uris),"compatible":len(accepted),**r,"elapsed_s":round(time.perf_counter()-start,2),"parse_or_config_failed":failed}


def probe_many(indices,workers,timeout):
    start=time.perf_counter(); results=[]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        fs={ex.submit(probe,BASE_PORT+pos,timeout):idx for pos,idx in enumerate(indices)}
        for f in as_completed(fs):
            idx=fs[f]
            try: results.append({"index":idx,**f.result()})
            except Exception as e: results.append({"index":idx,"msft_ok":False,"google_204_ok":False,"internet_healthy":False,"delay_ms":-1,"details":{"exception":str(e)[:160]}})
    elapsed=time.perf_counter()-start
    return {"tested":len(indices),"healthy":sum(int(x["internet_healthy"]) for x in results),"msft_ok":sum(int(x["msft_ok"]) for x in results),"google_204_ok":sum(int(x["google_204_ok"]) for x in results),"nodes_per_sec":round(len(indices)/max(elapsed,.001),2),"probe_elapsed_s":round(elapsed,2),"results":results}


def run_sing(uris,workers,timeout):
    start=time.perf_counter(); compatible,failed=preflight("sing-box",uris,workers)
    with tempfile.TemporaryDirectory(prefix="bench-sing-") as td:
        ins=[]; outs=[]; rules=[]
        for pos,idx in enumerate(compatible):
            o=sing_out(parse_uri(uris[idx]),f"p{pos+1}"); outs.append(o); it=f"in{pos+1}"; ins.append({"type":"socks","tag":it,"listen":"127.0.0.1","listen_port":BASE_PORT+pos}); rules.append({"inbound":[it],"action":"route","outbound":o["tag"]})
        cfg=Path(td)/"c.json"; cfg.write_text(json.dumps({"log":{"level":"error"},"inbounds":ins,"outbounds":outs+[ {"type":"direct","tag":"direct"}],"route":{"rules":rules,"final":"direct"}}))
        chk=subprocess.run([str(SING),"check","-c",str(cfg)],text=True,capture_output=True,timeout=30)
        if chk.returncode!=0: return {"engine":"sing-box","status":"config_rejected","candidates":len(uris),"compatible":len(compatible),"tested":0,"healthy":0,"parse_or_config_failed":failed,"stderr":(chk.stderr or chk.stdout)[-1800:],"elapsed_s":round(time.perf_counter()-start,2)}
        p=subprocess.Popen([str(SING),"run","-c",str(cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if compatible and not wait_port(BASE_PORT,10): p.kill();p.wait(); return {"engine":"sing-box","status":"failed_to_start","candidates":len(uris),"compatible":len(compatible),"tested":0,"healthy":0,"parse_or_config_failed":failed}
        r=probe_many(compatible,workers,timeout); p.terminate();
        try:p.wait(3)
        except subprocess.TimeoutExpired:p.kill()
    return {"engine":"sing-box","status":"ok","candidates":len(uris),"compatible":len(compatible),**r,"elapsed_s":round(time.perf_counter()-start,2),"parse_or_config_failed":failed}


def run_mihomo(uris,workers,timeout):
    start=time.perf_counter(); compatible,failed=preflight("mihomo",uris,workers)
    with tempfile.TemporaryDirectory(prefix="bench-mihomo-") as td:
        proxies=[]
        for idx in compatible:
            try: proxies.append(mihomo_out(parse_uri(uris[idx]),f"p{idx+1}"))
            except Exception as e: failed.append({"index":idx,"reason":str(e)[:200]})
        cfg=Path(td)/"config.yaml"; cfg.write_text(yaml.safe_dump({"mixed-port":18888,"allow-lan":False,"mode":"rule","log-level":"silent","external-controller":f"127.0.0.1:{API_PORT}","proxies":proxies,"rules":["MATCH,DIRECT"]},sort_keys=False))
        chk=subprocess.run([str(MIHOMO),"-t","-f",str(cfg)],text=True,capture_output=True,timeout=30)
        if chk.returncode!=0: return {"engine":"mihomo","status":"config_rejected","candidates":len(uris),"compatible":len(proxies),"tested":0,"healthy":0,"parse_or_config_failed":failed,"stderr":(chk.stderr or chk.stdout)[-1800:],"elapsed_s":round(time.perf_counter()-start,2)}
        p=subprocess.Popen([str(MIHOMO),"-f",str(cfg),"-d",str(td)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if not wait_port(API_PORT,10): p.kill();p.wait(); return {"engine":"mihomo","status":"failed_to_start","candidates":len(uris),"compatible":len(proxies),"tested":0,"healthy":0,"parse_or_config_failed":failed}
        t=time.perf_counter(); results=[]
        def one(idx):
            name=f"p{idx+1}"; base=f"http://127.0.0.1:{API_PORT}/proxies/{urllib.parse.quote(name,safe='')}/delay"
            a=requests.get(base,params={"url":f"http://{MSFT[0]}{MSFT[1]}","timeout":int(timeout*1000),"expected":"200"},timeout=timeout+3)
            b=requests.get(base,params={"url":f"http://{GOOGLE[0]}{GOOGLE[1]}","timeout":int(timeout*1000),"expected":"204"},timeout=timeout+3)
            m=a.ok and int(a.json().get("delay",-1))>=0; g=b.ok and int(b.json().get("delay",-1))>=0
            return {"index":idx,"msft_ok":m,"google_204_ok":g,"internet_healthy":m and g,"details":{"msft":a.text[:180],"google":b.text[:180]}}
        with ThreadPoolExecutor(max_workers=workers) as ex:
            fs=[ex.submit(one,idx) for idx in compatible]
            for f in as_completed(fs):
                try:results.append(f.result())
                except Exception as e:results.append({"index":-1,"msft_ok":False,"google_204_ok":False,"internet_healthy":False,"details":{"exception":str(e)[:180]}})
        elapsed=time.perf_counter()-t; p.terminate()
        try:p.wait(3)
        except subprocess.TimeoutExpired:p.kill()
    return {"engine":"mihomo","status":"ok","candidates":len(uris),"compatible":len(compatible),"tested":len(compatible),"healthy":sum(int(x["internet_healthy"]) for x in results),"msft_ok":sum(int(x["msft_ok"]) for x in results),"google_204_ok":sum(int(x["google_204_ok"]) for x in results),"nodes_per_sec":round(len(compatible)/max(elapsed,.001),2),"probe_elapsed_s":round(elapsed,2),"elapsed_s":round(time.perf_counter()-start,2),"parse_or_config_failed":failed,"results":results}


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--limit",type=int,default=500); ap.add_argument("--workers",type=int,default=80); ap.add_argument("--timeout",type=float,default=5.0); ap.add_argument("--out",default=str(OUT/"metadata"/"engine_benchmark.json")); a=ap.parse_args()
    uris=load_same_sample(a.limit)
    if len(uris)<a.limit: raise SystemExit(f"same sample contains only {len(uris)} nodes")
    report={"generated_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"sample_requested":a.limit,"sample_loaded":len(uris),"same_sample_for_all_engines":True,"workers":a.workers,"timeout_s":a.timeout,"probes":{"primary":"http://www.msftconnecttest.com/connecttest.txt","secondary":"http://www.gstatic.com/generate_204"},"engines":[run_xray(uris,a.workers,a.timeout),run_sing(uris,a.workers,a.timeout),run_mihomo(uris,a.workers,a.timeout)]}
    out=Path(a.out); out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    for e in report["engines"]: print(json.dumps({k:e.get(k) for k in ("engine","status","candidates","compatible","tested","healthy","msft_ok","google_204_ok","nodes_per_sec","probe_elapsed_s","elapsed_s")},ensure_ascii=False))

if __name__=="__main__": main()
