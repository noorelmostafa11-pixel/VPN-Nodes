#!/usr/bin/env python3
"""Full-pool Internet health scan using one long-lived Xray process."""
from __future__ import annotations

import argparse, base64, hashlib, json, os, re, socket, ssl, subprocess, tempfile, time, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"output"
XRAY=Path(os.environ.get("XRAY_BIN","/opt/hostedtoolcache/xray/xray"))
DEFAULT_WORKERS=int(os.environ.get("REAL_DELAY_WORKERS","256"))
DEFAULT_TIMEOUT=float(os.environ.get("REAL_DELAY_NODE_TIMEOUT","5"))
BASE_PORT=int(os.environ.get("REAL_DELAY_SOCKS_BASE","21000"))
PROBES=(
 ("microsoft_connect_test","www.msftconnecttest.com","/connecttest.txt",False,200,b"Microsoft Connect Test"),
 ("google_generate_204","www.gstatic.com","/generate_204",True,204,None),
)

def b64d(v:str)->bytes:
    v=v.strip().replace("-","+").replace("_","/")
    return base64.b64decode(v+"="*(-len(v)%4))

def params(uri:str): return urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query,keep_blank_values=True)
def first(q,*keys,default=""):
    for k in keys:
        if q.get(k): return urllib.parse.unquote(q[k][0])
    return default
def scheme(uri:str)->str: return urllib.parse.urlsplit(uri).scheme.lower()

def parse_uri(uri:str)->dict:
    s=scheme(uri); p=urllib.parse.urlsplit(uri); q=params(uri)
    if s=="vless":
        sec=first(q,"security",default="none")
        node={"scheme":"vless","server":p.hostname,"port":p.port or 443,"uuid":urllib.parse.unquote(p.username or ""),"network":first(q,"type",default="tcp").lower(),"path":first(q,"path",default="/"),"host":first(q,"host"),"security":sec,"sni":first(q,"sni","serverName",default=p.hostname),"fp":first(q,"fp",default="chrome"),"pbk":first(q,"pbk","publicKey"),"sid":first(q,"sid","shortId"),"service_name":first(q,"serviceName"),"authority":first(q,"authority")}
        if not node["server"]: raise ValueError("invalid VLESS server")
        if not node["uuid"] or len(node["uuid"].strip()) < 10: raise ValueError("invalid or empty VLESS UUID")
        if sec=="reality" and (not node["pbk"] or len(node["pbk"].strip()) < 20): raise ValueError("REALITY requires a valid non-empty publicKey (pbk)")
        return node
    if s=="vmess":
        obj=json.loads(b64d(uri.split("vmess://",1)[1].split("#",1)[0]).decode("utf-8")); server=obj.get("add") or obj.get("address")
        if not obj.get("id") or len(str(obj.get("id")).strip())<10: raise ValueError("invalid or empty VMess UUID")
        return {"scheme":"vmess","server":server,"port":int(obj["port"]),"uuid":obj.get("id"),"network":str(obj.get("net") or "tcp").lower(),"path":obj.get("path") or "/","host":obj.get("host") or "","tls":str(obj.get("tls") or "").lower() not in ("","none","false","0"),"sni":obj.get("sni") or obj.get("host") or server,"alter_id":int(obj.get("aid",0) or 0),"cipher":obj.get("scy") or "auto"}
    if s=="trojan":
        password=urllib.parse.unquote(p.username or "")
        if not password: raise ValueError("invalid or empty Trojan password")
        return {"scheme":"trojan","server":p.hostname,"port":p.port or 443,"password":password,"network":first(q,"type",default="tcp").lower(),"path":first(q,"path",default="/"),"host":first(q,"host"),"sni":first(q,"sni",default=p.hostname),"service_name":first(q,"serviceName")}
    if s=="ss":
        raw=uri.split("ss://",1)[1].split("#",1)[0]
        if "@" in raw:
            ui,hp=raw.rsplit("@",1)
            try: ui=b64d(ui).decode("utf-8")
            except Exception: ui=urllib.parse.unquote(ui)
        else:
            dec=b64d(raw).decode("utf-8"); ui,hp=dec.rsplit("@",1)
        hp=hp.split("?",1)[0].split("/",1)[0]
        if hp.startswith("["): host,port=hp.rsplit("]:",1); host=host[1:]
        else: host,port=hp.rsplit(":",1)
        user=urllib.parse.unquote(ui)
        if ":" not in user: raise ValueError("invalid Shadowsocks method:password")
        method,password=user.split(":",1)
        if not method.strip() or not password: raise ValueError("invalid or empty Shadowsocks credentials")
        return {"scheme":"ss","server":host,"port":int(port),"method":method,"password":password}
    raise ValueError(f"unsupported scheme: {s}")

def xray_outbound(n:dict,tag:str)->dict:
    s=n["scheme"]
    if s=="vless":
        stream={"network":n["network"],"security":"none"}
        if n["network"]=="ws": stream["wsSettings"]={"path":n.get("path") or "/","headers":{"Host":n.get("host") or ""}}
        elif n["network"]=="grpc": stream["grpcSettings"]={"serviceName":n.get("service_name") or "","authority":n.get("authority") or ""}
        if n.get("security")=="tls":
            stream["security"]="tls"; stream["tlsSettings"]={"serverName":n.get("sni") or n["server"]}
            if n.get("fp"): stream["tlsSettings"]["fingerprint"]=n["fp"]
        elif n.get("security")=="reality":
            stream["security"]="reality"; stream["realitySettings"]={"serverName":n.get("sni") or n["server"],"fingerprint":n.get("fp") or "chrome","publicKey":n["pbk"].strip(),"shortId":n.get("sid") or "","spiderX":"/"}
        return {"protocol":"vless","tag":tag,"settings":{"vnext":[{"address":n["server"],"port":n["port"],"users":[{"id":n["uuid"],"encryption":"none"}]}]},"streamSettings":stream}
    if s=="vmess":
        stream={"network":n["network"],"security":"none"}
        if n["network"]=="ws": stream["wsSettings"]={"path":n.get("path") or "/","headers":{"Host":n.get("host") or ""}}
        if n.get("tls"): stream["security"]="tls"; stream["tlsSettings"]={"serverName":n.get("sni") or n["server"]}
        return {"protocol":"vmess","tag":tag,"settings":{"vnext":[{"address":n["server"],"port":n["port"],"users":[{"id":n["uuid"],"alterId":n.get("alter_id",0),"security":n.get("cipher","auto")}]}]},"streamSettings":stream}
    if s=="trojan":
        stream={"network":n["network"],"security":"tls","tlsSettings":{"serverName":n.get("sni") or n["server"]}}
        if n["network"]=="ws": stream["wsSettings"]={"path":n.get("path") or "/","headers":{"Host":n.get("host") or ""}}
        elif n["network"]=="grpc": stream["grpcSettings"]={"serviceName":n.get("service_name") or ""}
        return {"protocol":"trojan","tag":tag,"settings":{"servers":[{"address":n["server"],"port":n["port"],"password":n["password"]}]},"streamSettings":stream}
    if s=="ss": return {"protocol":"shadowsocks","tag":tag,"settings":{"servers":[{"address":n["server"],"port":n["port"],"method":n["method"],"password":n["password"]}]}}
    raise ValueError(s)

def load_pool():
    rows={}
    for path in sorted((OUT/"countries").glob("*.txt")):
        country=path.stem.upper()
        for line in path.read_text(encoding="utf-8",errors="replace").splitlines():
            uri=line.strip()
            if not uri or not uri.lower().startswith(("vless://","vmess://","trojan://","ss://")): continue
            try:
                node=parse_uri(uri)
                if node.get("port") not in {80,443}: continue
            except Exception: continue
            rows.setdefault(hashlib.sha256(uri.encode()).hexdigest(),{"uri":uri,"country":country,"protocol":"shadowsocks" if scheme(uri)=="ss" else scheme(uri),"node":node})
    return list(rows.values())

def wait_port(port,timeout=20):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        try:
            with socket.create_connection(("127.0.0.1",port),timeout=.2): return True
        except OSError: time.sleep(.05)
    return False

def socks_http(port,host,path,use_tls,status,body,timeout):
    started=time.perf_counter(); s=socket.create_connection(("127.0.0.1",port),timeout=timeout); s.settimeout(timeout)
    try:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2)!=b"\x05\x00": return False,-1,"socks-auth"
        hb=host.encode("idna"); rp=443 if use_tls else 80
        s.sendall(b"\x05\x01\x00\x03"+bytes([len(hb)])+hb+rp.to_bytes(2,"big")); h=s.recv(4)
        if len(h)!=4 or h[1]!=0: return False,-1,"socks-connect"
        if h[3]==1: s.recv(4)
        elif h[3]==3: s.recv(s.recv(1)[0])
        elif h[3]==4: s.recv(16)
        s.recv(2); conn=s
        if use_tls: conn=ssl.create_default_context().wrap_socket(s,server_hostname=host)
        conn.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: AhmedVPN-RealDelay/6\r\n\r\n".encode())
        data=bytearray()
        while len(data)<16384:
            c=conn.recv(min(4096,16384-len(data)))
            if not c: break
            data.extend(c)
        raw=bytes(data); first_line=raw.split(b"\r\n",1)[0]; m=re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})",first_line)
        if not m: return False,-1,"no-http"
        if int(m.group(1))!=status: return False,-1,f"unexpected-status-{int(m.group(1))}"
        if body is not None and body not in raw: return False,-1,"expected-body-missing"
        return True,round((time.perf_counter()-started)*1000,1),f"HTTP {status}"
    finally:
        try:s.close()
        except Exception:pass

def probe(item,timeout):
    details={}; delays=[]
    for name,host,path,tls,status,body in PROBES:
        try: ok,lat,detail=socks_http(item["port"],host,path,tls,status,body,timeout)
        except Exception as exc: ok,lat,detail=False,-1,str(exc)[:180]
        details[name]={"ok":ok,"latency_ms":lat if ok else -1,"detail":detail}
        if ok: delays.append(lat)
    ms=details["microsoft_connect_test"]["ok"]; gg=details["google_generate_204"]["ok"]
    return {"index":item["index"],"msft_ok":ms,"google_204_ok":gg,"internet_healthy":ms and gg,"delay_ms":min(delays) if delays else -1,"details":details}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--workers",type=int,default=DEFAULT_WORKERS); ap.add_argument("--timeout",type=float,default=DEFAULT_TIMEOUT); args=ap.parse_args()
    workers=max(1,args.workers); timeout=max(.5,args.timeout)
    if not XRAY.exists(): raise SystemExit(f"Xray binary not found: {XRAY}")
    pool=load_pool()
    if not pool: raise SystemExit("No reachable nodes available")
    print(f"INFO real_delay_pool={len(pool)} selected={len(pool)} workers={workers} mode=single_long_lived_xray")
    start=time.perf_counter(); included=[]; failures=[]; results=[]
    with tempfile.TemporaryDirectory(prefix="real-delay-") as td:
        root=Path(td); ins=[]; outs=[]; rules=[]
        for idx,item in enumerate(pool):
            try:
                tag=f"node-{idx+1}"; itag=f"in-{idx+1}"; port=BASE_PORT+idx
                outs.append(xray_outbound(item["node"],tag)); ins.append({"listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"udp":False},"tag":itag}); rules.append({"type":"field","inboundTag":[itag],"outboundTag":tag}); included.append({**item,"index":idx,"port":port})
            except Exception as exc: failures.append({"index":idx,"uri":item["uri"],"reason":str(exc)[:500],"classification":"config_conversion_failed"})
        cfg=root/"config.json"; cfg.write_text(json.dumps({"log":{"loglevel":"error"},"inbounds":ins,"outbounds":outs,"routing":{"domainStrategy":"AsIs","rules":rules}},ensure_ascii=False),encoding="utf-8")
        check=subprocess.run([str(XRAY),"-test","-config",str(cfg)],text=True,capture_output=True,timeout=max(120,len(included)//4))
        if check.returncode!=0:
            print("WARN Xray full config rejected; isolating invalid outbounds with divide-and-conquer")
            valid=[]; bad=[]
            def build_test(chunk):
                ib=[]; ob=[]; rr=[]
                for item in chunk:
                    tag=f"node-{item['index']+1}"; itag=f"in-{item['index']+1}"
                    ob.append(xray_outbound(item["node"],tag)); ib.append({"listen":"127.0.0.1","port":item["port"],"protocol":"socks","settings":{"udp":False},"tag":itag}); rr.append({"type":"field","inboundTag":[itag],"outboundTag":tag})
                p=root/f"test-{len(list(root.glob('test-*.json')))}.json"; p.write_text(json.dumps({"log":{"loglevel":"error"},"inbounds":ib,"outbounds":ob,"routing":{"domainStrategy":"AsIs","rules":rr}}),encoding="utf-8")
                r=subprocess.run([str(XRAY),"-test","-config",str(p)],text=True,capture_output=True,timeout=max(30,len(chunk)//4+30))
                return r.returncode==0
            stack=[included]
            while stack:
                chunk=stack.pop()
                if not chunk: continue
                if build_test(chunk): valid.extend(chunk); continue
                if len(chunk)==1: bad.extend(chunk); continue
                mid=len(chunk)//2; stack.append(chunk[:mid]); stack.append(chunk[mid:])
            bad_idx={x["index"] for x in bad}
            failures.extend({"index":x["index"],"uri":x["uri"],"reason":"Xray config validation failed after isolation","classification":"config_conversion_failed"} for x in bad)
            included=[x for x in included if x["index"] not in bad_idx]
            ins=[]; outs=[]; rules=[]
            for item in included:
                tag=f"node-{item['index']+1}"; itag=f"in-{item['index']+1}"; ins.append({"listen":"127.0.0.1","port":item["port"],"protocol":"socks","settings":{"udp":False},"tag":itag}); outs.append(xray_outbound(item["node"],tag)); rules.append({"type":"field","inboundTag":[itag],"outboundTag":tag})
            cfg.write_text(json.dumps({"log":{"loglevel":"error"},"inbounds":ins,"outbounds":outs,"routing":{"domainStrategy":"AsIs","rules":rules}},ensure_ascii=False),encoding="utf-8")
            check=subprocess.run([str(XRAY),"-test","-config",str(cfg)],text=True,capture_output=True,timeout=max(120,len(included)//4))
            if check.returncode!=0: raise SystemExit("Xray config still rejected after isolation: "+(check.stderr or check.stdout)[-4000:])
        proc=subprocess.Popen([str(XRAY),"run","-c",str(cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            if included and not wait_port(included[0]["port"]): raise SystemExit("Xray process did not open first inbound")
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futures={ex.submit(probe,item,timeout):item for item in included}
                for n,f in enumerate(as_completed(futures),1):
                    item=futures[f]
                    try: results.append(f.result())
                    except Exception as exc: results.append({"index":item["index"],"msft_ok":False,"google_204_ok":False,"internet_healthy":False,"delay_ms":-1,"details":{"exception":str(exc)[:180]}})
                    if n%500==0 or n==len(included): print(f"INFO real_delay_progress={n}/{len(included)} alive={sum(1 for r in results if r['msft_ok'] or r['google_204_ok'])} healthy={sum(1 for r in results if r['internet_healthy'])}")
        finally:
            proc.terminate()
            try: proc.wait(5)
            except subprocess.TimeoutExpired: proc.kill()
    by_index={r["index"]:r for r in results}; final=[]; failmap={x["index"]:x for x in failures}
    for idx,item in enumerate(pool):
        r=by_index.get(idx)
        if r is None:
            final.append({**item,"msft_ok":False,"google_204_ok":False,"internet_healthy":False,"delay_ms":-1,"details":{"config_conversion_failed":failmap.get(idx,{}).get("reason","not-tested")}})
        else: final.append({k:v for k,v in {**item,**r}.items() if k!="node"})
    final.sort(key=lambda r:(r["country"],0 if r["internet_healthy"] else 1,0 if r["msft_ok"] or r["google_204_ok"] else 1,r["delay_ms"] if r["delay_ms"]>0 else 10**9,r["protocol"],r["uri"]))
    meta=OUT/"metadata"; meta.mkdir(parents=True,exist_ok=True)
    alive=sum(1 for r in final if r["msft_ok"] or r["google_204_ok"]); healthy=sum(1 for r in final if r["internet_healthy"])
    (meta/"real_delay.json").write_text(json.dumps({"generated_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"pool_total":len(pool),"included_in_xray":len(included),"config_conversion_failed":len(failures),"alive":alive,"healthy":healthy,"workers":workers,"timeout_s":timeout,"mode":"single_long_lived_xray","nodes":final},ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(f"INFO real_delay_done pool={len(pool)} included={len(included)} config_conversion_failed={len(failures)} alive={alive} healthy={healthy} elapsed_s={time.perf_counter()-start:.1f}")

if __name__=="__main__": main()
