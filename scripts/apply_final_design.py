from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def remove_priority() -> None:
    p = ROOT / "sources/sources.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    for src in data.get("sources", []):
        src.pop("priority", None)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    p = ROOT / "scripts/update_catalog.py"
    s = p.read_text(encoding="utf-8")
    s = re.sub(r"LEGACY_SOURCE_PRIORITY = \{.*?\n\}\nALIASES =", "ALIASES =", s, flags=re.S)
    s = s.replace(
        'def parse_lines(text: str, source_name: str, source_hint_country: str | None = None, source_priority: int = 0):',
        'def parse_lines(text: str, source_name: str, source_hint_country: str | None = None):',
    )
    s = re.sub(r"\n\s*priority = LEGACY_SOURCE_PRIORITY\.get\(source_name, source_priority\)", "", s)
    s = s.replace(', "source": source_name, "source_priority": priority', ', "source": source_name')
    s = s.replace(', item.get("priority", 0)', "")
    s = s.replace(", item.get('priority', 0)", "")
    s = re.sub(
        r'for item in sorted\(cfg\["sources"\], key=lambda source: -source\.get\("priority", 0\)\):',
        'for item in cfg["sources"]:',
        s,
    )
    p.write_text(s, encoding="utf-8")

    p = ROOT / "scripts/telegram_build_tcp_pool.py"
    s = p.read_text(encoding="utf-8")
    start = s.index("def _apply_metadata_first")
    end = s.index("\n\n# Patch the shared parser", start)
    replacement = '''def _apply_metadata_first(rows: list[dict]) -> list[dict]:\n    """Keep country unresolved until after the Xray Internet-health pass."""\n    for row in rows:\n        row["country"] = "UNKNOWN"\n        row["country_resolution"] = "pending_xray"\n        row["country_resolution_confidence"] = "none"\n    return rows\n'''
    s = s[:start] + replacement + s[end:]
    s = s.replace(
        'def parse_lines_metadata_first(text, source_name, source_hint_country=None, source_priority=0):',
        'def parse_lines_metadata_first(text, source_name, source_hint_country=None):',
    )
    s = s.replace(
        'return _original_parse_lines(text, source_name, source_hint_country, source_priority)',
        'return _original_parse_lines(text, source_name, source_hint_country)',
    )
    s = re.sub(r'\n\s*priority = int\(item\.get\("priority", 0\)\)', '', s)
    s = s.replace(',\n                priority,\n            )', '\n            )')
    s = re.sub(r'\n\s*priority = int\(item\.get\("priority", 270\)\)', '', s)
    s = s.replace('"priority": priority,\n', '')
    p.write_text(s, encoding="utf-8")


def rewrite_build_tcp_pool() -> None:
    p = ROOT / "scripts/build_tcp_pool.py"
    p.write_text(r'''#!/usr/bin/env python3
"""Build the TCP-reachable candidate pool; country resolution happens after Xray health."""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import update_catalog as catalog

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
SOURCES = ROOT / "sources" / "sources.json"
TCP_TIMEOUT = float(catalog.CONNECT_TIMEOUT)
TCP_WORKERS = 512

async def tcp_probe(item: dict, semaphore: asyncio.Semaphore) -> tuple[dict, float | None]:
    started = time.perf_counter()
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(item["host"], item["port"]), timeout=TCP_TIMEOUT
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return item, round((time.perf_counter() - started) * 1000, 1)
        except Exception:
            return item, None

async def run_tcp_checks(rows: list[dict]) -> list[dict]:
    semaphore = asyncio.Semaphore(TCP_WORKERS)
    results: list[dict] = []
    total = len(rows)
    completed = 0

    async def one(item: dict):
        nonlocal completed
        row, latency = await tcp_probe(item, semaphore)
        completed += 1
        if latency is not None:
            results.append({**row, "latency_ms": latency, "country": "UNKNOWN", "country_resolution": "pending_xray"})
        if completed % 1000 == 0 or completed == total:
            print(f"INFO tcp_progress={completed}/{total} reachable={len(results)}")

    await asyncio.gather(*(one(item) for item in rows))
    return results

def main() -> None:
    cfg = json.loads(SOURCES.read_text(encoding="utf-8"))
    all_rows: list[dict] = []
    source_health: list[dict] = []
    successful_sources = 0

    for item in cfg["sources"]:
        started = time.perf_counter()
        try:
            rows = catalog.collect_source(item)
            all_rows.extend(rows)
            successful_sources += 1
            source_health.append({"name": item["name"], "ok": True, "nodes": len(rows), "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)})
            print(f"OK {item['name']}: {len(rows)}")
        except Exception as exc:
            source_health.append({"name": item["name"], "ok": False, "nodes": 0, "error": str(exc), "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)})
            print(f"WARN {item['name']}: {exc}")

    if successful_sources == 0 and not all_rows:
        raise RuntimeError("All upstream sources failed")

    unique: dict[str, dict] = {}
    for row in all_rows:
        unique.setdefault(catalog.dedup_key(row["uri"]), row)
    rows = list(unique.values())
    for row in rows:
        row["country"] = "UNKNOWN"
        row["country_resolution"] = "pending_xray"

    print(f"INFO parsed={len(rows)} tcp_candidates={len(rows)} async_tcp=true workers={TCP_WORKERS}")
    checked = asyncio.run(run_tcp_checks(rows))
    print(f"INFO tcp_reachable={len(checked)} tcp_dead={len(rows) - len(checked)}")

    meta = OUT / "metadata"
    meta.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_parsed": len(rows),
        "tcp_reachable": len(checked),
        "tcp_workers": TCP_WORKERS,
        "allowed_ports": [80, 443],
        "source_failures": sum(1 for s in source_health if not s["ok"]),
        "sources": source_health,
        "nodes": [{k: v for k, v in item.items() if k != "node"} for item in checked],
    }
    (meta / "tcp_reachable.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"INFO tcp_pool_saved={len(checked)} path=output/metadata/tcp_reachable.json")

if __name__ == "__main__": main()
''', encoding="utf-8")


def rewrite_real_delay() -> None:
    p = ROOT / "scripts/real_delay.py"
    s = p.read_text(encoding="utf-8")
    if "import country_resolver" not in s:
        s = s.replace("from pathlib import Path\n", "from pathlib import Path\n\nimport country_resolver\n")
    s = re.sub(
        r"PROBES=\(.*?\n\)",
        '''PROBES=(\n ("microsoft_connect_test","www.msftconnecttest.com","/connecttest.txt",False,200,b"Microsoft Connect Test"),\n ("google_generate_204","www.gstatic.com","/generate_204",True,204,None),\n ("firefox_success","detectportal.firefox.com","/success.txt",False,200,b"success"),\n)''',
        s,
        flags=re.S,
    )
    ls = s.index("def load_pool():")
    le = s.index("\ndef wait_port", ls)
    new_load = '''def load_pool():\n    path = OUT / "metadata" / "tcp_reachable.json"\n    if not path.is_file():\n        raise SystemExit(f"TCP candidate pool not found: {path}")\n    payload = json.loads(path.read_text(encoding="utf-8"))\n    pool = []\n    for item in payload.get("nodes", []):\n        uri = str(item.get("uri") or "").strip()\n        if not uri:\n            continue\n        try:\n            node = parse_uri(uri)\n            if node.get("port") not in {80, 443}:\n                continue\n        except Exception:\n            continue\n        pool.append({**item, "uri": uri, "node": node, "country": "UNKNOWN"})\n    return pool\n'''
    s = s[:ls] + new_load + s[le:]
    main_pos = s.index("def main():")
    s = s[:main_pos] + r'''def _write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")

def _country_name(code: str) -> str:
    import pycountry
    c = pycountry.countries.get(alpha_2=code)
    return c.name if c else code

def publish_healthy(healthy_items: list[dict], resolution: dict, stats: dict) -> None:
    import pycountry
    countries_dir = OUT / "countries"
    protocols_dir = OUT / "protocols"
    global_dir = OUT / "global"
    meta_dir = OUT / "metadata"
    for d in (countries_dir, protocols_dir, global_dir, meta_dir):
        d.mkdir(parents=True, exist_ok=True)
    for path in countries_dir.glob("*.txt"):
        path.unlink()
    for path in protocols_dir.glob("*.txt"):
        path.unlink()
    for path in global_dir.glob("server-*.txt"):
        path.unlink()

    ordered = []
    for item in healthy_items:
        r = item.get("result", {})
        row = {k: v for k, v in item.items() if k not in {"node", "result"}}
        row.update(r)
        ordered.append(row)
    ordered.sort(key=lambda r: (r.get("delay_ms", 10**9) if r.get("delay_ms", -1) >= 0 else 10**9, r.get("protocol", ""), r.get("uri", "")))

    iso_codes = {c.alpha_2.upper() for c in pycountry.countries}
    grouped: dict[str, list[dict]] = {}
    unknown: list[dict] = []
    for row in ordered:
        code = row.get("country")
        if code in iso_codes:
            grouped.setdefault(code, []).append(row)
        else:
            unknown.append(row)
    targets = sorted(grouped)

    if unknown and targets:
        base, remainder = divmod(len(unknown), len(targets))
        cursor = 0
        for idx, code in enumerate(targets):
            take = base + (1 if idx < remainder else 0)
            grouped[code].extend(unknown[cursor:cursor + take])
            cursor += take
    elif unknown:
        _write_lines(global_dir / "verified-unknown.txt", [r["uri"] for r in unknown])

    for code in targets:
        _write_lines(countries_dir / f"{code}.txt", [r["uri"] for r in grouped[code]])

    protocol_rows: dict[str, list[str]] = {}
    for code in targets:
        for row in grouped[code]:
            protocol = str(row.get("protocol") or "")
            if protocol:
                protocol_rows.setdefault(protocol, []).append(row["uri"])
    for protocol, lines in protocol_rows.items():
        _write_lines(protocols_dir / f"{protocol}.txt", lines)

    counts = {c: len(grouped[c]) for c in targets}
    index = {
        "schema": 8,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tcp_reachable_total": stats.get("pool_total", 0),
        "xray_included": stats.get("included", 0),
        "config_conversion_failed": stats.get("config_conversion_failed", 0),
        "alive": stats.get("alive", 0),
        "healthy": stats.get("healthy", 0),
        "healthy_published_total": sum(counts.values()),
        "published_by_country": counts,
        "countries": len(targets),
        "country_names": {c: _country_name(c) for c in targets},
        "allowed_ports": [80, 443],
        "health_policy": "Xray triple HTTP probes: Microsoft 200 + Google 204 + Firefox 200; country resolution occurs only after triple-pass health",
        "ranking_policy": "healthy only; fastest delay first; country files preserve this order",
        "country_policy": "resolve only successful nodes; explicit metadata then DNS/GeoLite2; verified UNKNOWN nodes append after detected nodes",
        "country_resolution": resolution,
    }
    (meta_dir / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (meta_dir / "health.json").write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (meta_dir / "countries.json").write_text(json.dumps({"countries": [{"code": c, "name": _country_name(c), "nodes": counts[c], "reachable": counts[c], "cap_rejected": 0} for c in targets]}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--workers",type=int,default=DEFAULT_WORKERS); ap.add_argument("--timeout",type=float,default=DEFAULT_TIMEOUT); args=ap.parse_args()
    workers=max(1,args.workers); timeout=max(.5,args.timeout)
    if not XRAY.exists(): raise SystemExit(f"Xray binary not found: {XRAY}")
    pool=load_pool()
    if not pool: raise SystemExit("No TCP-reachable nodes available")
    print(f"INFO real_delay_pool={len(pool)} selected={len(pool)} workers={workers} mode=single_long_lived_xray probes=3")
    start=time.perf_counter(); included=[]; failures=[]; results=[]
    with tempfile.TemporaryDirectory(prefix="real-delay-") as td:
        root=Path(td); ins=[]; outs=[]; rules=[]
        for idx,item in enumerate(pool):
            try:
                tag=f"node-{idx+1}"; itag=f"in-{idx+1}"; port=BASE_PORT+idx
                outs.append(xray_outbound(item["node"],tag)); ins.append({"listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"udp":False},"tag":itag}); rules.append({"type":"field","inboundTag":[itag],"outboundTag":tag}); included.append({**item,"index":idx,"port":port})
            except Exception as exc: failures.append({"index":idx,"uri":item["uri"],"reason":str(exc)[:500],"classification":"config_conversion_failed"})
        def write_cfg(path: Path, items: list[dict]) -> None:
            ib=[]; ob=[]; rr=[]
            for item in items:
                tag=f"node-{item['index']+1}"; itag=f"in-{item['index']+1}"
                ob.append(xray_outbound(item["node"],tag)); ib.append({"listen":"127.0.0.1","port":item["port"],"protocol":"socks","settings":{"udp":False},"tag":itag}); rr.append({"type":"field","inboundTag":[itag],"outboundTag":tag})
            path.write_text(json.dumps({"log":{"loglevel":"error"},"inbounds":ib,"outbounds":ob,"routing":{"domainStrategy":"AsIs","rules":rr}},ensure_ascii=False),encoding="utf-8")
        cfg=root/"config.json"; write_cfg(cfg,included)
        check=subprocess.run([str(XRAY),"-test","-config",str(cfg)],text=True,capture_output=True,timeout=max(120,len(included)//4))
        if check.returncode!=0:
            print("WARN Xray full config rejected; isolating invalid outbounds with divide-and-conquer")
            bad=[]
            def build_test(chunk):
                if not chunk: return True
                p=root/f"test-{time.monotonic_ns()}.json"; write_cfg(p,chunk)
                try: r=subprocess.run([str(XRAY),"-test","-config",str(p)],text=True,capture_output=True,timeout=max(30,len(chunk)//4+30))
                except subprocess.TimeoutExpired: return False
                return r.returncode==0
            stack=[included]
            while stack:
                chunk=stack.pop()
                if not chunk: continue
                if build_test(chunk): continue
                if len(chunk)==1: bad.extend(chunk); continue
                mid=len(chunk)//2; stack.append(chunk[:mid]); stack.append(chunk[mid:])
            bad_idx={x["index"] for x in bad}
            failures.extend({"index":x["index"],"uri":x["uri"],"reason":"Xray config validation failed after isolation","classification":"config_conversion_failed"} for x in bad)
            included=[x for x in included if x["index"] not in bad_idx]
            write_cfg(cfg,included)
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
                    except Exception as exc: results.append({"index":item["index"],"msft_ok":False,"google_204_ok":False,"firefox_ok":False,"internet_healthy":False,"delay_ms":-1,"details":{"exception":str(exc)[:180]}})
                    if n%500==0 or n==len(included): print(f"INFO real_delay_progress={n}/{len(included)} alive={sum(1 for r in results if r.get('msft_ok') or r.get('google_204_ok') or r.get('firefox_ok'))} healthy={sum(1 for r in results if r.get('internet_healthy'))}")
        finally:
            proc.terminate()
            try: proc.wait(5)
            except subprocess.TimeoutExpired: proc.kill()
    by_index={r["index"]:r for r in results}
    healthy=[]
    for idx,item in enumerate(pool):
        r=by_index.get(idx)
        if r and r.get("internet_healthy"):
            healthy.append({**item,"result":r})
    healthy.sort(key=lambda x:(x["result"].get("delay_ms",10**9),x["result"].get("index",10**9),x.get("uri","")))
    resolution={"hostname":0,"geoip_local":0,"unknown":0,"database_loaded":False}
    if healthy:
        rows_for_resolution=[]
        for item in healthy:
            row={k:v for k,v in item.items() if k not in {"node","result"}}
            rows_for_resolution.append(row)
        resolution=country_resolver.resolve_rows(rows_for_resolution)
        for item,row in zip(healthy,rows_for_resolution):
            item["country"]=row.get("country") or "UNKNOWN"
            item["country_resolution"]=row.get("country_resolution") or "unknown"
            item["country_resolution_confidence"]=row.get("country_resolution_confidence")
    alive=sum(1 for r in results if r.get("msft_ok") or r.get("google_204_ok") or r.get("firefox_ok"))
    final_stats={"pool_total":len(pool),"included":len(included),"config_conversion_failed":len(failures),"alive":alive,"healthy":len(healthy),"workers":workers,"timeout_s":timeout}
    print(f"INFO real_delay_done pool={len(pool)} included={len(included)} config_conversion_failed={len(failures)} alive={alive} healthy={len(healthy)} elapsed_s={time.perf_counter()-start:.1f}")
    publish_healthy(healthy,resolution,final_stats)
    meta=OUT/"metadata"
    report={"generated_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),**final_stats,"probes":{"microsoft":{"url":"http://www.msftconnecttest.com/connecttest.txt","status":200},"google":{"url":"https://www.gstatic.com/generate_204","status":204},"firefox":{"url":"http://detectportal.firefox.com/success.txt","status":200,"body":"success"}},"nodes":[{**{k:v for k,v in item.items() if k not in {"node"}},"result":item["result"]} for item in healthy]}
    (meta/"real_delay.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")

if __name__=="__main__": main()
'''
    p.write_text(s, encoding="utf-8")


def main() -> None:
    remove_priority()
    rewrite_build_tcp_pool()
    rewrite_real_delay()
    workflow = ROOT / ".github/workflows/update.yml"
    s = workflow.read_text(encoding="utf-8")
    s = re.sub(r"\n\s*- name: Distribute unresolved nodes into discovered countries\n\s*run: python scripts/distribute_unknown.py\n", "\n", s)
    workflow.write_text(s, encoding="utf-8")
    obsolete = ROOT / "scripts/distribute_unknown.py"
    if obsolete.exists():
        obsolete.unlink()
    print("FINAL_DESIGN_APPLIED")

if __name__ == "__main__":
    main()
