from __future__ import annotations
import base64, json, os, re, socket, time
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote, urlparse, parse_qs
import requests

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
MAX_SOURCE_BYTES = 2_000_000
MAX_GENERATED_PER_COUNTRY = 250
CONNECT_TIMEOUT = 2.5
HEALTH_WORKERS = 24
ALLOWED_PORTS = {80, 443}
PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks"}
COUNTRY_RE = re.compile(r"(?<![A-Za-z])([A-Za-z]{2})(?:[_-]part\d+)?(?:\.txt|\.yaml)?$", re.I)
TOKEN_TO_COUNTRY = {
    "uk":"GB", "gb":"GB", "england":"GB", "unitedkingdom":"GB",
    "uae":"AE", "emirates":"AE", "unitedarabemirates":"AE",
    "usa":"US", "unitedstates":"US", "us":"US",
    "southkorea":"KR", "korea":"KR", "northkorea":"KP",
    "russia":"RU", "iran":"IR", "taiwan":"TW", "japan":"JP",
    "singapore":"SG", "seychelles":"SC", "germany":"DE", "france":"FR",
    "canada":"CA", "australia":"AU", "austria":"AT", "netherlands":"NL",
    "poland":"PL", "slovenia":"SI", "turkey":"TR", "turkiye":"TR",
    "hongkong":"HK", "finland":"FI", "sweden":"SE", "denmark":"DK",
    "bulgaria":"BG", "azerbaijan":"AZ", "china":"CN", "estonia":"EE"
}

session = requests.Session()
session.headers.update({"User-Agent":"Ahmed-VPN-Nodes/1.0 (+public-aggregator)"})
if os.getenv("GITHUB_TOKEN"):
    session.headers.update({"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"})


def fetch(url: str) -> bytes:
    r = session.get(url, timeout=(CONNECT_TIMEOUT, 5), stream=True)
    r.raise_for_status()
    data = bytearray()
    for chunk in r.iter_content(8192):
        data.extend(chunk)
        if len(data) > MAX_SOURCE_BYTES:
            break
    return bytes(data[:MAX_SOURCE_BYTES])


def maybe_decode(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    compact = re.sub(r"\s+", "", text)
    if len(compact) > 100 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        try:
            decoded = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=False)
            candidate = decoded.decode("utf-8", errors="replace")
            if "vless://" in candidate or "vmess://" in candidate or "trojan://" in candidate or "ss://" in candidate:
                return candidate
        except Exception:
            pass
    return text


def country_from_text(value: str) -> str | None:
    if not value:
        return None
    raw = unquote(value)
    lower = re.sub(r"[^a-z0-9]+", "", raw.lower())
    for token, code in TOKEN_TO_COUNTRY.items():
        if token in lower:
            return code
    m = re.search(r"(?:^|[^A-Za-z])([A-Za-z]{2})(?:$|[^A-Za-z])", raw)
    if m:
        code = m.group(1).upper()
        if code.isalpha() and len(code) == 2:
            return code
    return None


def protocol_from_uri(uri: str) -> str | None:
    scheme = uri.split(":",1)[0].lower()
    if scheme == "ss": return "shadowsocks"
    if scheme in PROTOCOLS: return scheme
    return None


def endpoint_from_uri(uri: str):
    scheme = uri.split(":",1)[0].lower()
    try:
        if scheme in {"vless", "vmess", "trojan"}:
            p = urlparse(uri)
            host = p.hostname
            port = p.port
            remark = unquote(p.fragment or "")
            q = parse_qs(p.query)
            return host, port, remark, q
        if scheme == "ss":
            p = urlparse(uri)
            host = p.hostname
            port = p.port
            remark = unquote(p.fragment or "")
            return host, port, remark, {}
    except Exception:
        return None, None, "", {}
    return None, None, "", {}


def normalize_uri(uri: str) -> str:
    return uri.strip()


def dedup_key(uri: str) -> str:
    host, port, remark, q = endpoint_from_uri(uri)
    scheme = protocol_from_uri(uri) or ""
    if not host or not port:
        return uri
    identity = [scheme, host.lower(), str(port)]
    for key in ("uuid", "sid", "sni", "serverName", "path", "type", "security", "encryption", "method"):
        val = q.get(key, [""])[0]
        if val:
            identity.append(f"{key}={val}")
    return "|".join(identity)


def parse_lines(text: str, source_name: str, source_hint_country: str | None = None):
    out = []
    text = maybe_decode(text.encode("utf-8", errors="ignore"))
    for line in text.splitlines():
        line = line.strip().strip('"')
        if not line or line.startswith(("#", "//", "proxies:", "proxy-groups:")):
            continue
        m = re.search(r"(?:^|['\"\s])((?:vless|vmess|trojan|ss)://[^'\"\s,]+)", line, re.I)
        uri = m.group(1) if m else (line if re.match(r"^(?:vless|vmess|trojan|ss)://", line, re.I) else None)
        if not uri:
            continue
        uri = normalize_uri(uri)
        proto = protocol_from_uri(uri)
        if proto is None:
            continue
        host, port, remark, q = endpoint_from_uri(uri)
        if not host or port not in ALLOWED_PORTS:
            continue
        c = country_from_text(remark) or country_from_text(uri) or source_hint_country
        out.append({"uri": uri, "protocol": proto, "host": host, "port": port, "remark": remark, "country": c, "source": source_name})
    return out


def source_hint_from_url(url: str) -> str | None:
    name = url.rsplit("/",1)[-1].split("?",1)[0]
    m = COUNTRY_RE.search(name)
    if m:
        return m.group(1).upper()
    return country_from_text(name)


def github_index(url: str):
    data = session.get(url, timeout=(CONNECT_TIMEOUT,5)).json()
    if not isinstance(data, list):
        return []
    return [x for x in data if x.get("type") == "file" and x.get("download_url")]


def collect_source(item):
    name = item["name"]
    url = item["url"]
    rows=[]
    if item["format"] == "github_api":
        for ent in github_index(url):
            fname = ent.get("name", "")
            hint = source_hint_from_url(fname)
            try:
                raw = fetch(ent["download_url"])
                rows.extend(parse_lines(raw.decode("utf-8", errors="replace"), name+":"+fname, hint))
            except Exception as e:
                print(f"WARN {name}/{fname}: {e}")
        return rows
    if item["kind"] == "country_template":
        return rows
    try:
        raw = fetch(url)
        return parse_lines(raw.decode("utf-8", errors="replace"), name, source_hint_from_url(url))
    except Exception as e:
        print(f"WARN {name}: {e}")
        return rows


def tcp_check(item):
    host, port = item["host"], item["port"]
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=1.5):
            return True, round((time.perf_counter()-t0)*1000,1)
    except Exception:
        return False, None


def iso_name(code: str) -> str:
    names = {
      "AE":"United Arab Emirates","AT":"Austria","AU":"Australia","AZ":"Azerbaijan","BG":"Bulgaria","CA":"Canada","CN":"China","DE":"Germany","DK":"Denmark","EE":"Estonia","FI":"Finland","FR":"France","GB":"United Kingdom","HK":"Hong Kong","ID":"Indonesia","IE":"Ireland","IN":"India","IR":"Iran","IT":"Italy","JP":"Japan","KR":"South Korea","NL":"Netherlands","PL":"Poland","RU":"Russia","SC":"Seychelles","SE":"Sweden","SG":"Singapore","SI":"Slovenia","TR":"Türkiye","TW":"Taiwan","US":"United States"
    }
    return names.get(code, code)


def main():
    cfg = json.loads((ROOT/"sources/sources.json").read_text())
    all_rows=[]
    source_health=[]
    for item in sorted(cfg["sources"], key=lambda x: -x.get("priority",0)):
        t0=time.perf_counter()
        try:
            rows=collect_source(item)
            all_rows.extend(rows)
            source_health.append({"name":item["name"],"ok":True,"nodes":len(rows),"elapsed_ms":round((time.perf_counter()-t0)*1000,1)})
            print(f"OK {item['name']}: {len(rows)}")
        except Exception as e:
            source_health.append({"name":item["name"],"ok":False,"nodes":0,"error":str(e)})
            print(f"WARN {item['name']}: {e}")

    uniq={}
    for row in all_rows:
        uniq.setdefault(dedup_key(row["uri"]), row)
    rows=list(uniq.values())
    for row in rows:
        row["country"] = row.get("country") or "UNKNOWN"

    from concurrent.futures import ThreadPoolExecutor, as_completed
    checked=[]
    with ThreadPoolExecutor(max_workers=HEALTH_WORKERS) as ex:
        futures={ex.submit(tcp_check,r): r for r in rows}
        for f in as_completed(futures):
            r=futures[f]
            try:
                ok, latency=f.result()
            except Exception:
                ok, latency=False, None
            if ok:
                r["latency_ms"]=latency
                checked.append(r)

    by_country=defaultdict(list); by_proto=defaultdict(list)
    for r in checked:
        by_country[r["country"]].append(r); by_proto[r["protocol"]].append(r)
    for key in by_country:
        by_country[key].sort(key=lambda r:(r.get("latency_ms",999999), r["protocol"], r["host"]))
        by_country[key]=by_country[key][:MAX_GENERATED_PER_COUNTRY]
    for key in by_proto:
        by_proto[key].sort(key=lambda r:(r.get("latency_ms",999999), r["host"]))

    for d in (OUT/"countries", OUT/"protocols", OUT/"metadata"):
        d.mkdir(parents=True,exist_ok=True)
    for p in (OUT/"countries").glob("*.txt"): p.unlink()
    for p in (OUT/"protocols").glob("*.txt"): p.unlink()
    for country, arr in sorted(by_country.items()):
        (OUT/"countries"/f"{country}.txt").write_text("\n".join(r["uri"] for r in arr)+"\n", encoding="utf-8")
    for proto, arr in sorted(by_proto.items()):
        (OUT/"protocols"/f"{proto}.txt").write_text("\n".join(r["uri"] for r in arr)+"\n", encoding="utf-8")

    index={
      "schema":1,
      "generated_at":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
      "total_fetched":len(all_rows),
      "unique_parsed":len(rows),
      "healthy_published":len(checked),
      "allowed_ports":[80,443],
      "protocols":{p:len(by_proto.get(p,[])) for p in sorted(PROTOCOLS)},
      "countries":len(by_country),
      "country_names":{c:iso_name(c) for c in sorted(by_country)},
      "files":{"countries":"countries/","protocols":"protocols/"}
    }
    (OUT/"metadata/index.json").write_text(json.dumps(index,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    (OUT/"metadata/countries.json").write_text(json.dumps({"countries":[{"code":c,"name":iso_name(c),"nodes":len(a)} for c,a in sorted(by_country.items())]},ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    (OUT/"metadata/health.json").write_text(json.dumps({"generated_at":index["generated_at"],"sources":source_health},ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(index,indent=2))

if __name__ == "__main__":
    main()
