#!/usr/bin/env python3
"""Core-driven real-traffic catalog scan."""
from __future__ import annotations
import json, os, subprocess, tempfile, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import country_resolver
import real_delay
import real_delay_google_batch as publisher
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"output"
XRAY=Path(os.environ.get("XRAY_BIN","/opt/hostedtoolcache/xray/xray"))
WORKERS=max(1,int(os.environ.get("REAL_DELAY_WORKERS","250")))
TIMEOUT=max(.5,float(os.environ.get("REAL_DELAY_NODE_TIMEOUT","10")))
BASE_PORT=int(os.environ.get("REAL_DELAY_SOCKS_BASE","21000"))
BATCH_SIZE=max(50,min(int(os.environ.get("REAL_DELAY_XRAY_BATCH_SIZE","500")),1000))
def validate_batch(root,items):
    failures=[]
    def check(chunk):
        p=root/f"check-{time.monotonic_ns()}.json"; real_delay.write_cfg(p,chunk)
        try:return subprocess.run([str(XRAY),"-test","-config",str(p)],capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=max(30,len(chunk)//4+30)).returncode==0
        except subprocess.TimeoutExpired:return False
    if check(items):return items,failures
    good=[];stack=[items]
    while stack:
        c=stack.pop()
        if not c:continue
        if check(c):good.extend(c);continue
        if len(c)==1:
            x=c[0];failures.append({"index":x["index"],"uri":x["uri"],"reason":"Xray config validation failed after isolation","classification":"config_conversion_failed"});continue
        m=len(c)//2;stack.extend((c[:m],c[m:]))
    return good,failures
def scan_batch(root,batch,batch_no,total_batches,results,failures):
    local=[{**x,"port":BASE_PORT+i} for i,x in enumerate(batch)]
    included,bf=validate_batch(root,local);failures.extend(bf)
    if not included:return
    cfg=root/f"batch-{batch_no}.json";log=root/f"batch-{batch_no}.log";real_delay.write_cfg(cfg,included)
    with log.open("w",encoding="utf-8",errors="replace") as lf:
        proc=subprocess.Popen([str(XRAY),"run","-c",str(cfg)],stdout=lf,stderr=subprocess.STDOUT,text=True)
        try:
            if not real_delay.wait_port(included[0]["port"],timeout=20):raise RuntimeError(f"Xray batch {batch_no} did not open SOCKS")
            done=0
            with ThreadPoolExecutor(max_workers=WORKERS) as ex:
                fm={ex.submit(real_delay.probe,x,TIMEOUT):x for x in included}
                for f in as_completed(fm):
                    x=fm[f]
                    try:r=f.result()
                    except Exception as e:r={"index":x["index"],"probe_passed":0,"internet_healthy":False,"alive":False,"classification":"failed","delay_ms":-1,"details":{"exception":str(e)[:300]}}
                    results.append(r);done+=1
                    if done%100==0 or done==len(included):print(f"INFO core_batch_progress={batch_no}/{total_batches} nodes={done}/{len(included)}")
        finally:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill()
def resolve_countries(items):
    if not items:return {"hostname":0,"geoip_local":0,"unknown":0,"database_loaded":False}
    rows=[{k:v for k,v in x.items() if k not in {"node","result"}} for x in items]
    res=country_resolver.resolve_rows(rows)
    for x,row in zip(items,rows):x["country"]=row.get("country") or "UNKNOWN";x["country_resolution"]=row.get("country_resolution") or "unknown";x["country_resolution_confidence"]=row.get("country_resolution_confidence")
    return res
def main():
    if not XRAY.exists():raise SystemExit(f"Xray binary not found: {XRAY}")
    pool=real_delay.load_pool()
    if not pool:raise SystemExit("No TCP-reachable nodes available")
    candidates=[]
    for i,item in enumerate(pool):
        item={**item,"index":i}
        if item.get("node",{}).get("port") in {80,443}:candidates.append(item)
    total_batches=(len(candidates)+BATCH_SIZE-1)//BATCH_SIZE
    print(f"INFO tcp_candidates={len(candidates)} workers={WORKERS} batch_size={BATCH_SIZE} timeout_s={TIMEOUT} batches={total_batches}")
    print("INFO health_path=parse->tcp->xray_config->xray->socks5->real_https")
    results=[];config_failures=[]
    with tempfile.TemporaryDirectory(prefix="core-real-traffic-") as td:
        root=Path(td)
        for off in range(0,len(candidates),BATCH_SIZE):scan_batch(root,candidates[off:off+BATCH_SIZE],off//BATCH_SIZE+1,total_batches,results,config_failures)
    by={r["index"]:r for r in results};active=[];backup=[]
    for x in candidates:
        r=by.get(x["index"])
        if not r:continue
        z={**x,"result":r}
        if r.get("classification")=="active":active.append(z)
        elif r.get("classification")=="backup":backup.append(z)
    resolution=resolve_countries(active+backup)
    stats={"pool_total":len(pool),"included":len(results),"config_conversion_failed":len(config_failures),"failed":sum(1 for r in results if r.get("classification")=="failed"),"workers":WORKERS,"timeout_s":TIMEOUT,"batch_size":BATCH_SIZE}
    print(f"INFO core_real_traffic_done pool={len(pool)} deep_checked={len(results)} active={len(active)} backup={len(backup)} failed={stats['failed']} config_failed={len(config_failures)} published={len(active)+len(backup)}")
    publisher.publish(active,backup,resolution,stats)
    m=OUT/"metadata";m.mkdir(parents=True,exist_ok=True)
    (m/"core_driven_health.json").write_text(json.dumps({"schema":11,"generated_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"mode":"core_driven_real_traffic","tcp_candidates":len(candidates),"deep_checked":len(results),"active":len(active),"backup":len(backup),"failed_after_core":stats["failed"],"config_conversion_failed":len(config_failures),"published_total":len(active)+len(backup),"workers":WORKERS,"batch_size":BATCH_SIZE,"node_timeout_s":TIMEOUT,"allowed_ports":[80,443],"health_policy":"Xray Core + local SOCKS5 + three real HTTP probes: Microsoft Connect Test 200, Google 204, Firefox 200. 3/3=ACTIVE, 1-2/3=BACKUP, 0/3=FAILED.","country_policy":"Automatic country resolution from successful nodes only; no fixed country allowlist.","tls_policy":"Direct TLS is not used as a pre-filter; node health is determined by the Xray-driven real-traffic path.","country_resolution":resolution},ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
if __name__=="__main__":main()
