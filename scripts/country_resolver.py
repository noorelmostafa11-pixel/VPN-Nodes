from __future__ import annotations
import ipaddress,json,re,socket,urllib.request
from concurrent.futures import ThreadPoolExecutor,as_completed
from functools import lru_cache

COUNTRY_TOKENS={"uk":"GB","gb":"GB","england":"GB","greatbritain":"GB","britain":"GB","us":"US","usa":"US","america":"US","unitedstates":"US","ca":"CA","canada":"CA","de":"DE","germany":"DE","fr":"FR","france":"FR","nl":"NL","netherlands":"NL","sg":"SG","singapore":"SG","jp":"JP","japan":"JP","kr":"KR","korea":"KR","southkorea":"KR","au":"AU","australia":"AU","at":"AT","austria":"AT","fi":"FI","finland":"FI","se":"SE","sweden":"SE","dk":"DK","denmark":"DK","pl":"PL","poland":"PL","cz":"CZ","czechia":"CZ","ch":"CH","switzerland":"CH","it":"IT","italy":"IT","es":"ES","spain":"ES","pt":"PT","portugal":"PT","no":"NO","norway":"NO","ru":"RU","russia":"RU","ua":"UA","ukraine":"UA","tr":"TR","turkey":"TR","turkiye":"TR","ir":"IR","iran":"IR","ae":"AE","uae":"AE","sa":"SA","saudiarabia":"SA","in":"IN","india":"IN","id":"ID","indonesia":"ID","my":"MY","malaysia":"MY","th":"TH","thailand":"TH","vn":"VN","vietnam":"VN","br":"BR","brazil":"BR","za":"ZA","southafrica":"ZA","nz":"NZ","newzealand":"NZ","hk":"HK","hongkong":"HK","tw":"TW","taiwan":"TW","az":"AZ","azerbaijan":"AZ","bg":"BG","bulgaria":"BG","ee":"EE","estonia":"EE","lt":"LT","lithuania":"LT","lv":"LV","latvia":"LV","hu":"HU","hungary":"HU","kz":"KZ","kazakhstan":"KZ","si":"SI","slovenia":"SI","sc":"SC","seychelles":"SC","cn":"CN","china":"CN","tm":"TM","turkmenistan":"TM"}

IP2LOCATION_DAILY_LIMIT=1000
TIMEOUT=8

def norm(code):
    v=str(code or "").strip().upper(); return v if re.fullmatch(r"[A-Z]{2}",v) else None

@lru_cache(maxsize=8192)
def resolve_host(host):
    if not host:return None
    v=str(host).strip().lower().rstrip('.')
    try: ipaddress.ip_address(v); return None
    except ValueError: pass
    labels=[x for x in re.split(r"[.\-_]+",v) if x]
    for x in labels:
        if x in COUNTRY_TOKENS and len(x)==2:return COUNTRY_TOKENS[x]
    for x in labels:
        if x in COUNTRY_TOKENS:return COUNTRY_TOKENS[x]
    for x in labels:
        m=re.fullmatch(r"([a-z]{2})(?:\d{1,4}|[-_]\d{1,4})",x)
        if m and m.group(1) in COUNTRY_TOKENS:return COUNTRY_TOKENS[m.group(1)]
    return None

def resolve_ip(host):
    try: ipaddress.ip_address(host); return host
    except ValueError: pass
    try:
        for info in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM):
            ip=info[4][0]
            try:
                a=ipaddress.ip_address(ip)
                if not(a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast):return ip
            except ValueError: pass
    except Exception: pass
    return None

def geo_ip_api(ips):
    out={}
    for i in range(0,len(ips),100):
        batch=ips[i:i+100]
        try:
            req=urllib.request.Request("http://ip-api.com/batch?fields=status,countryCode,query",data=json.dumps([{"query":x} for x in batch]).encode(),headers={"Content-Type":"application/json","User-Agent":"VPN-Nodes-CountryResolver/6"},method="POST")
            with urllib.request.urlopen(req,timeout=20) as r:data=json.loads(r.read().decode())
            for x in data if isinstance(data,list) else []:
                c=norm(x.get("countryCode")); q=str(x.get("query") or "")
                if x.get("status")=="success" and c and q:out[q]=c
        except Exception: pass
    return out

def geo_ip2location(ips):
    out={}; limited=ips[:IP2LOCATION_DAILY_LIMIT]
    def one(ip):
        try:
            u="https://api.ip2location.io/?ip="+urllib.parse.quote(ip)+"&format=json"
            req=urllib.request.Request(u,headers={"User-Agent":"VPN-Nodes-CountryResolver/6"})
            with urllib.request.urlopen(req,timeout=TIMEOUT) as r:p=json.loads(r.read().decode())
            c=norm(p.get("country_code")) if isinstance(p,dict) else None
            return ip,c
        except Exception:return ip,None
    with ThreadPoolExecutor(max_workers=24) as ex:
        for f in as_completed([ex.submit(one,ip) for ip in limited]):
            ip,c=f.result()
            if c:out[ip]=c
    return out

def geo_countries_dev(ips):
    out={}
    for i in range(0,len(ips),100):
        batch=ips[i:i+100]
        try:
            req=urllib.request.Request("https://countries.dev/ip",data=json.dumps(batch).encode(),headers={"Content-Type":"application/json","Accept":"application/json","User-Agent":"VPN-Nodes-CountryResolver/6"},method="POST")
            with urllib.request.urlopen(req,timeout=TIMEOUT) as r:data=json.loads(r.read().decode())
            for x in data if isinstance(data,list) else []:
                ip=str(x.get("ip") or ""); c=norm(x.get("countryCode") or x.get("country_code"))
                if ip and c:out[ip]=c
        except Exception: pass
    return out

def resolve_rows(rows):
    hostname=0
    for row in rows:
        if row.get("country")!="UNKNOWN":continue
        c=resolve_host(str(row.get("host") or ""))
        if c:row.update(country=c,country_resolution="hostname",country_resolution_confidence="medium");hostname+=1
    unresolved=[r for r in rows if r.get("country")=="UNKNOWN"]
    host_ip={}
    with ThreadPoolExecutor(max_workers=64) as ex:
        fut={ex.submit(resolve_ip,str(r.get("host") or "")):r for r in unresolved}
        for f in as_completed(fut):
            ip=f.result()
            if ip:host_ip[str(fut[f].get("host") or "")]=ip
    ips=sorted(set(host_ip.values()))
    ip2=geo_ip2location(ips); api=geo_ip_api(ips); cd=geo_countries_dev(ips)
    triple=pair=single=conflicts=0
    for row in unresolved:
        ip=host_ip.get(str(row.get("host") or ""))
        if not ip:continue
        vals=[x for x in (ip2.get(ip),api.get(ip),cd.get(ip)) if x]
        counts={}
        for c in vals:counts[c]=counts.get(c,0)+1
        chosen=None
        if len(vals)==3 and len(counts)==1:chosen=vals[0];row["country_resolution"]="geo_triple_consensus";row["country_resolution_confidence"]="high";triple+=1
        elif counts:
            code,n=max(counts.items(),key=lambda z:z[1])
            if n>=2:chosen=code;row["country_resolution"]="geo_pair_consensus";row["country_resolution_confidence"]="medium";pair+=1
            elif len(counts)==1:chosen=code;row["country_resolution"]="geo_single";row["country_resolution_confidence"]="low";single+=1
        if chosen:row["country"]=chosen
        elif len(counts)>1:
            row["country_resolution"]="geo_conflict";row["country_resolution_confidence"]="none";row["geo_conflict"]={"ip2location":ip2.get(ip),"ip_api":api.get(ip),"countries_dev":cd.get(ip)};conflicts+=1
    unknown=sum(1 for r in rows if r.get("country")=="UNKNOWN")
    return {"hostname":hostname,"ip2location":sum(1 for r in unresolved if r.get("country_resolution")=="geo_single" and host_ip.get(str(r.get("host") or "")) in ip2),"geo_pair_consensus":pair,"geo_triple_consensus":triple,"ip_geolocation":single+pair+triple,"geo_conflicts":conflicts,"unknown":unknown}
