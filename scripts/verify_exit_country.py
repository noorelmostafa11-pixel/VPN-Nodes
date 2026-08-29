#!/usr/bin/env python3
"""Verify a bounded sample of ambiguous nodes by observing the public exit IP through Xray."""
from __future__ import annotations
import base64, ipaddress, json, os, shutil, subprocess, tempfile, time, urllib.request, zipfile, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse
import requests

ROOT = Path(__file__).resolve().parents[1]
XRAY_DIR = ROOT / ".xray-bin"
MAX_NODES = int(os.getenv("EXIT_VERIFY_MAX", "128"))
WORKERS = int(os.getenv("EXIT_VERIFY_WORKERS", "8"))
TIMEOUT = float(os.getenv("EXIT_VERIFY_TIMEOUT", "18"))
SOCKS_BASE = int(os.getenv("EXIT_VERIFY_SOCKS_BASE", "21080"))

def _download_xray() -> Path:
    XRAY_DIR.mkdir(parents=True, exist_ok=True)
    binary = XRAY_DIR / "xray"
    if binary.exists(): return binary
    req = urllib.request.Request("https://api.github.com/repos/XTLS/Xray-core/releases/latest", headers={"User-Agent":"VPN-Nodes-exit-verifier"})
    with urllib.request.urlopen(req, timeout=20) as r: release = json.loads(r.read().decode())
    asset = next((a for a in release.get("assets", []) if "linux-64.zip" in a.get("name", "").lower()), None)
    if not asset: raise RuntimeError("Xray Linux x64 release asset not found")
    archive = XRAY_DIR / "xray.zip"
    urllib.request.urlretrieve(asset["browser_download_url"], archive)
    with zipfile.ZipFile(archive) as zf:
        member = next((m for m in zf.namelist() if m == "xray" or m.endswith("/xray")), None)
        if not member: raise RuntimeError("xray binary missing from release archive")
        with zf.open(member) as src, binary.open("wb") as dst: shutil.copyfileobj(src, dst)
    binary.chmod(0o755); archive.unlink(missing_ok=True)
    return binary

def _b64(value: str) -> str:
    value = unquote(value).replace("-", "+").replace("_", "/")
    value += "=" * (-len(value) % 4)
    return base64.b64decode(value).decode("utf-8", errors="strict")

def _stream(q: dict[str,list[str]], vmess=False) -> dict:
    network = q.get("type", ["tcp"])[0].lower(); security = q.get("security", q.get("tls", [""]))[0].lower()
    out = {"network": "tcp" if network == "raw" else network}
    if security in {"tls","reality"}:
        out["security"] = security
        if security == "tls":
            sni = q.get("sni", q.get("serverName", [""]))[0]
            out["tlsSettings"] = {"serverName": sni, "allowInsecure": True} if sni else {"allowInsecure": True}
        else:
            r = {}
            for src,dst in (("sni","serverName"),("pbk","publicKey"),("sid","shortId"),("spx","spiderX")):
                if q.get(src): r[dst] = q[src][0]
            out["realitySettings"] = r
    if network == "ws":
        ws={};
        if q.get("path"): ws["path"] = q["path"][0]
        if q.get("host"): ws["headers"] = {"Host": q["host"][0]}
        out["wsSettings"] = ws
    elif network == "grpc":
        out["grpcSettings"] = {"serviceName": q.get("serviceName", q.get("service", [""]))[0]}
    return out

def _outbound(uri: str) -> dict | None:
    scheme = uri.split(":",1)[0].lower()
    if scheme == "vmess":
        try: obj = json.loads(_b64(uri.split("://",1)[1].split("#",1)[0]))
        except Exception: return None
        host = str(obj.get("add") or obj.get("address") or "").strip(); uid = str(obj.get("id") or "").strip()
        try: port=int(obj.get("port"))
        except Exception: return None
        if not host or not uid: return None
        q={"type":[str(obj.get("net") or "tcp")],"security":[str(obj.get("tls") or "")],"sni":[str(obj.get("sni") or "")],"host":[str(obj.get("host") or "")],"path":[str(obj.get("path") or "")],"serviceName":[str(obj.get("path") or "")]}
        return {"protocol":"vmess","settings":{"vnext":[{"address":host,"port":port,"users":[{"id":uid,"alterId":int(obj.get("aid",0) or 0),"security":str(obj.get("scy") or "auto")}]}]},"streamSettings":_stream(q,True)}
    p=urlparse(uri); host=p.hostname; port=p.port; q=parse_qs(p.query)
    if not host or not port: return None
    if scheme == "vless":
        uid=unquote(p.username or "");
        if not uid: return None
        user={"id":uid,"encryption":q.get("encryption",["none"])[0]};
        if q.get("flow"): user["flow"]=q["flow"][0]
        return {"protocol":"vless","settings":{"vnext":[{"address":host,"port":port,"users":[user]}]},"streamSettings":_stream(q)}
    if scheme == "trojan":
        pw=unquote(p.username or "");
        if not pw: return None
        return {"protocol":"trojan","settings":{"servers":[{"address":host,"port":port,"password":pw}]},"streamSettings":_stream(q)}
    if scheme == "ss":
        # URI forms seen in the pool: ss://base64(method:password@host:port)
        try:
            decoded=_b64(uri.split("://",1)[1].split("#",1)[0]); left,endpoint=decoded.rsplit("@",1); method,pw=left.split(":",1); host,ps=endpoint.rsplit(":",1); port=int(ps)
        except Exception: return None
        return {"protocol":"shadowsocks","settings":{"servers":[{"address":host,"port":port,"method":method,"password":pw}]}}
    return None

def _country(ip: str) -> str | None:
    for url in (f"https://ipinfo.io/{ip}/json", f"http://ip-api.com/json/{ip}?fields=status,countryCode"):
        try:
            r=requests.get(url, timeout=8); d=r.json()
            c=str(d.get("country") or d.get("countryCode") or "").upper()
            if re.fullmatch(r"[A-Z]{2}",c) and ("country" in d or d.get("status")=="success"): return c
        except Exception: pass
    return None

def verify_one(item: dict, xray: Path, idx: int) -> tuple[dict,str]:
    out=_outbound(item["uri"])
    if not out: return item,"invalid_uri"
    port=SOCKS_BASE+idx
    with tempfile.TemporaryDirectory(prefix="vpn-exit-") as td:
        cfg={"log":{"loglevel":"error"},"inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"udp":True}}],"outbounds":[out,{"protocol":"freedom","tag":"direct"}]}
        cp=Path(td)/"config.json"; cp.write_text(json.dumps(cfg),encoding="utf-8")
        proc=subprocess.Popen([str(xray),"run","-c",str(cp)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            deadline=time.time()+TIMEOUT
            while time.time()<deadline:
                try:
                    ip=subprocess.check_output(["curl","--silent","--show-error","--fail","--max-time","7","--socks5-hostname",f"127.0.0.1:{port}","https://api.ipify.org"],stderr=subprocess.DEVNULL,timeout=9).decode().strip()
                    ipaddress.ip_address(ip); c=_country(ip)
                    if c:
                        item.update({"verified_exit_ip":ip,"verified_exit_country":c,"country":c,"country_resolution":"exit_verification","country_resolution_confidence":"high"}); return item,"verified"
                except Exception: time.sleep(0.7)
            return item,"timeout"
        finally:
            proc.terminate()
            try: proc.wait(timeout=2)
            except Exception: proc.kill()

def verify_ambiguous(rows: list[dict]) -> dict[str,int]:
    candidates=[r for r in rows if r.get("country")=="UNKNOWN" or r.get("country_resolution_confidence") in {"low","none"}]
    candidates.sort(key=lambda r:(0 if r.get("country")=="UNKNOWN" else 1, r.get("source_priority",0)))
    candidates=candidates[:MAX_NODES]
    if not candidates: return {"candidates":0,"verified":0,"failed":0}
    xray=_download_xray(); verified=failed=0
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures={pool.submit(verify_one,row,xray,i):row for i,row in enumerate(candidates)}
        for f in as_completed(futures):
            row,status=f.result()
            if status=="verified": verified+=1
            else: failed+=1
    return {"candidates":len(candidates),"verified":verified,"failed":failed}
