#!/usr/bin/env python3
"""Production runner using the exact locally validated node_debug_batch_v2 path."""
from __future__ import annotations
import base64, importlib.util, json, os, tempfile, time, urllib.parse, zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POOL_FILE = ROOT / "output" / "metadata" / "tcp_reachable.json"
WORKERS = max(1, min(int(os.environ.get("REAL_DELAY_WORKERS", "250")), 250))
SOCKS_BASE = int(os.environ.get("REAL_DELAY_SOCKS_BASE", "21080"))
TCP_TIMEOUT = float(os.environ.get("REAL_DELAY_TCP_TIMEOUT", "8"))
TRAFFIC_TIMEOUT = float(os.environ.get("REAL_DELAY_NODE_TIMEOUT", "10"))

# Exact source used by the successful 1000-node laptop run, embedded verbatim
# (compressed only to keep this production launcher compact).
_SOURCE_B64 = "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
"


def load_tester():
    source = zlib.decompress(base64.b64decode(_SOURCE_B64)).decode("utf-8")
    temp = Path(tempfile.gettempdir()) / "node_debug_batch_v2_exact.py"
    temp.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("node_debug_batch_v2_exact", temp)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load validated tester")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.SOCKS_BASE_PORT = SOCKS_BASE
    mod.TCP_TIMEOUT = TCP_TIMEOUT
    mod.TRAFFIC_TIMEOUT = TRAFFIC_TIMEOUT
    return mod


def main() -> int:
    if not POOL_FILE.is_file():
        raise SystemExit(f"TCP pool not found: {POOL_FILE}")
    xray = str(Path(os.environ.get("XRAY_BIN", "/opt/hostedtoolcache/xray/xray")).resolve())
    if not Path(xray).is_file():
        raise SystemExit(f"Xray not found: {xray}")

    payload = json.loads(POOL_FILE.read_text(encoding="utf-8"))
    uris, seen = [], set()
    for row in payload.get("nodes", []):
        uri = str(row.get("uri") or "").strip()
        if not uri or uri in seen:
            continue
        seen.add(uri)
        uris.append(uri)

    tester = load_tester()
    usable = []
    for uri in uris:
        try:
            node = tester.parse_node(uri)
        except Exception:
            continue
        if int(node.get("port", 0)) in (80, 443):
            usable.append(uri)
    if not usable:
        raise SystemExit("No usable TCP-reachable nodes available")

    print(f"INFO tcp_candidates={len(usable)} workers={WORKERS}")
    print("INFO health_path=parse->dns->tcp->xray_config_validation->xray_start->local_socks5->real_xray_tunnel->strict_https->diagnostic_https")

    results=[]
    counters={"PASS":0,"WORKS_BUT_CERT_INVALID":0,"REAL_TRAFFIC_FAILED":0,"OTHER_FAILED":0}
    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures={executor.submit(tester.test_one,i,uri,xray,SOCKS_BASE+i-1):(i,uri) for i,uri in enumerate(usable,1)}
        done=0
        for future in as_completed(futures):
            idx,uri=futures[future]
            try:r=future.result()
            except Exception as exc:r={"index":idx,"protocol":"","address":"","port":None,"tcp_ms":-1.0,"status":"OTHER_FAILED","reason":f"worker exception: {exc}"}
            r["uri"]=uri; results.append(r)
            status=r.get("status","OTHER_FAILED"); counters[status]=counters.get(status,0)+1; done+=1
            if done%100==0 or done==len(usable):
                print(f"INFO real_progress={done}/{len(usable)} PASS={counters['PASS']} CERT={counters['WORKS_BUT_CERT_INVALID']} FAIL={counters['REAL_TRAFFIC_FAILED']} OTHER={counters['OTHER_FAILED']}")

    publishable=[r for r in results if r.get("status") in {"PASS","WORKS_BUT_CERT_INVALID"}]
    try:
        import country_resolver
        import pycountry
        rows=[]
        for r in publishable:
            try:n=tester.parse_node(r["uri"])
            except Exception:n={}
            rows.append({"uri":r["uri"],"server":n.get("server") or r.get("address") or "","address":n.get("server") or r.get("address") or "","port":n.get("port") or r.get("port"),"remark":urllib.parse.unquote(urllib.parse.urlsplit(r["uri"]).fragment or ""),"country":"UNKNOWN"})
        resolution=country_resolver.resolve_rows(rows) if rows else {"hostname":0,"geoip_local":0,"unknown":0,"database_loaded":False}
        for r,row in zip(publishable,rows):r["country"]=row.get("country") or "UNKNOWN";r["country_resolution"]=row.get("country_resolution") or "unknown"
    except Exception as exc:
        resolution={"error":str(exc)}
        for r in publishable:r["country"]="UNKNOWN"

    out=ROOT/"output"; dirs={k:out/k for k in ("countries","active","backup","protocols","metadata")}
    for d in dirs.values():d.mkdir(parents=True,exist_ok=True)
    for k in ("countries","active","backup","protocols"):
        for p in dirs[k].glob("*.txt"):p.unlink()
    groups={"active":{},"backup":{}}
    for r in publishable:
        kind="active" if r.get("status")=="PASS" else "backup"
        groups[kind].setdefault(str(r.get("country") or "UNKNOWN").upper(),[]).append(r)
    codes=sorted(set(groups["active"])|set(groups["backup"]))
    for code in codes:
        a=groups["active"].get(code,[]); b=groups["backup"].get(code,[])
        (dirs["countries"]/f"{code}.txt").write_text("\n".join(x["uri"] for x in a+b)+("\n" if a or b else ""),encoding="utf-8")
        (dirs["active"]/f"{code}.txt").write_text("\n".join(x["uri"] for x in a)+("\n" if a else ""),encoding="utf-8")
        (dirs["backup"]/f"{code}.txt").write_text("\n".join(x["uri"] for x in b)+("\n" if b else ""),encoding="utf-8")
    protocols={}
    for r in publishable:
        try:n=tester.parse_node(r["uri"]); protocols.setdefault(str(n.get("protocol") or "unknown"),[]).append(r["uri"])
        except Exception:pass
    for name,lines in protocols.items():(dirs["protocols"]/f"{name}.txt").write_text("\n".join(lines)+"\n",encoding="utf-8")

    meta={"schema":15,"generated_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"mode":"exact_local_node_debug_batch_v2","tcp_candidates":len(usable),"deep_checked":len(results),"pass":counters["PASS"],"works_but_cert_invalid":counters["WORKS_BUT_CERT_INVALID"],"real_traffic_failed":counters["REAL_TRAFFIC_FAILED"],"other_failed":counters["OTHER_FAILED"],"published_total":len(publishable),"workers":WORKERS,"allowed_ports":[80,443],"health_path":"parse->dns->tcp->xray_config_validation->xray_start->local_socks5->real_xray_tunnel->strict_https->diagnostic_https","country_policy":"Automatic country resolution from successful nodes only; no fixed country allowlist.","country_resolution":resolution}
    (dirs["metadata"] / "core_driven_health.json").write_text(json.dumps(meta,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(f"INFO FINAL PASS={counters['PASS']} CERT={counters['WORKS_BUT_CERT_INVALID']} FAILED={counters['REAL_TRAFFIC_FAILED']} OTHER={counters['OTHER_FAILED']} TOTAL={len(results)} PUBLISHED={len(publishable)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
