from __future__ import annotations

import base64
import json
import os
import re
import socket
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import unquote, urlparse, parse_qs

import pycountry
import requests

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"

MAX_SOURCE_BYTES = 2_000_000
MAX_GENERATED_PER_COUNTRY = 250

CONNECT_TIMEOUT = 1.5
READ_TIMEOUT = 5.0
HEALTH_WORKERS = 128
FREE_HEALTH_DELAY_MS = 200
ALLOWED_PORTS = {80, 443}
PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks"}

ISO_CODES = {c.alpha_2.upper() for c in pycountry.countries}

# Legacy source order preserved from the Android 1.5.1 generation path.
# Higher numeric priority wins BEFORE latency, so proven source families are
# not displaced merely because a lower-priority endpoint answered TCP faster.
LEGACY_SOURCE_PRIORITY = {
    "au1rxx_countries": 200,
    "openray_countries": 190,
    "solispirit_countries": 180,
    "fastnodes_countries_index": 170,
    "fastnodes_everything": 160,
    "radikal_top100": 135,
    "radikal_verified": 130,
    "alirewa_main": 125,
    "baarcuda_vless": 120,
    "baarcuda_vmess": 120,
    "baarcuda_trojan": 120,
    "baarcuda_ss": 120,
    "zengfr_vless": 115,
    "zengfr_vmess": 115,
    "zengfr_trojan": 115,
    "zengfr_ss": 115,
    "epodonios_vless": 110,
}

ALIASES = {
    "uk": "GB", "england": "GB", "greatbritain": "GB", "unitedkingdom": "GB",
    "uae": "AE", "emirates": "AE", "unitedarabemirates": "AE",
    "usa": "US", "america": "US", "unitedstates": "US",
    "southkorea": "KR", "korea": "KR", "northkorea": "KP",
    "russia": "RU", "iran": "IR", "taiwan": "TW", "japan": "JP",
    "singapore": "SG", "seychelles": "SC", "germany": "DE", "france": "FR",
    "canada": "CA", "australia": "AU", "austria": "AT", "netherlands": "NL",
    "poland": "PL", "slovenia": "SI", "turkey": "TR", "turkiye": "TR",
    "hongkong": "HK", "finland": "FI", "sweden": "SE", "denmark": "DK",
    "bulgaria": "BG", "azerbaijan": "AZ", "china": "CN", "estonia": "EE",
    "czechrepublic": "CZ", "czechia": "CZ", "southafrica": "ZA",
    "newzealand": "NZ", "saudiarabia": "SA",
}

TECHNICAL_TOKENS = {
    "ws", "tls", "tcp", "raw", "grpc", "reality", "http", "https", "udp",
    "auto", "none", "vless", "vmess", "trojan", "shadowsocks",
}

COUNTRY_NAME_TO_CODE = {}
for country in pycountry.countries:
    COUNTRY_NAME_TO_CODE[re.sub(r"[^a-z0-9]+", "", country.name.lower())] = country.alpha_2.upper()
    if hasattr(country, "official_name"):
        COUNTRY_NAME_TO_CODE[
            re.sub(r"[^a-z0-9]+", "", country.official_name.lower())
        ] = country.alpha_2.upper()

session = requests.Session()
session.headers.update({"User-Agent": "Ahmed-VPN-Nodes/2.0 (+public-aggregator)"})
if os.getenv("GITHUB_TOKEN"):
    session.headers.update({"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"})


def fetch(url: str) -> bytes:
    response = session.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), stream=True)
    response.raise_for_status()
    data = bytearray()
    for chunk in response.iter_content(8192):
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
            if any(marker in candidate for marker in ("vless://", "vmess://", "trojan://", "ss://")):
                return candidate
        except Exception:
            pass
    return text


def normalize_country_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", unquote(value).lower())


def country_from_text(value: str, allow_iso: bool = True) -> str | None:
    if not value:
        return None
    raw = unquote(value)
    compact = normalize_country_token(raw)

    for token, code in ALIASES.items():
        if token in compact:
            return code

    for token, code in COUNTRY_NAME_TO_CODE.items():
        if token and token in compact:
            return code

    if allow_iso:
        for match in re.finditer(
            r"(?<![A-Za-z0-9._/\\])([A-Za-z]{2})(?![A-Za-z0-9._/\\])", raw
        ):
            token = match.group(1).lower()
            if token in TECHNICAL_TOKENS:
                continue
            code = token.upper()
            if code in ISO_CODES:
                return code
    return None


def protocol_from_uri(uri: str) -> str | None:
    scheme = uri.split(":", 1)[0].lower()
    if scheme == "ss":
        return "shadowsocks"
    if scheme in PROTOCOLS:
        return scheme
    return None


def endpoint_from_uri(uri: str):
    scheme = uri.split(":", 1)[0].lower()
    try:
        if scheme in {"vless", "vmess", "trojan"}:
            parsed = urlparse(uri)
            return parsed.hostname, parsed.port, unquote(parsed.fragment or ""), parse_qs(parsed.query)
        if scheme == "ss":
            parsed = urlparse(uri)
            return parsed.hostname, parsed.port, unquote(parsed.fragment or ""), {}
    except Exception:
        return None, None, "", {}
    return None, None, "", {}


def dedup_key(uri: str) -> str:
    host, port, _, query = endpoint_from_uri(uri)
    scheme = protocol_from_uri(uri) or ""
    if not host or not port:
        return uri
    identity = [scheme, host.lower(), str(port)]
    for key in ("uuid", "sid", "sni", "serverName", "path", "type", "security", "encryption", "method"):
        value = query.get(key, [""])[0]
        if value:
            identity.append(f"{key}={value}")
    return "|".join(identity)


def parse_lines(text: str, source_name: str, source_hint_country: str | None = None, source_priority: int = 0):
    rows = []
    text = maybe_decode(text.encode("utf-8", errors="ignore"))
    for line in text.splitlines():
        line = line.strip().strip('"')
        if not line or line.startswith(("#", "//", "proxies:", "proxy-groups:")):
            continue
        match = re.search(r'''(?:^|['"\s])((?:vless|vmess|trojan|ss)://[^'"\s,]+)''', line, re.I)
        uri = match.group(1) if match else (line if re.match(r"^(?:vless|vmess|trojan|ss)://", line, re.I) else None)
        if not uri:
            continue
        protocol = protocol_from_uri(uri)
        if protocol is None:
            continue
        host, port, remark, query = endpoint_from_uri(uri)
        if not host or port not in ALLOWED_PORTS:
            continue

        country = country_from_text(remark)
        if country is None:
            for key in ("country", "cc", "region", "geo"):
                country = country_from_text(query.get(key, [""])[0])
                if country:
                    break
        if country is None:
            country = source_hint_country

        priority = source_priority
        if source_name in LEGACY_SOURCE_PRIORITY:
            priority = LEGACY_SOURCE_PRIORITY[source_name]

        rows.append({
            "uri": uri,
            "protocol": protocol,
            "host": host,
            "port": port,
            "remark": remark,
            "country": country or "UNKNOWN",
            "source": source_name,
            "source_priority": priority,
        })
    return rows


def source_hint_from_url(url: str) -> str | None:
    path = url.split("?", 1)[0].rstrip("/")
    name = path.rsplit("/", 1)[-1]
    match = re.fullmatch(r"([A-Za-z]{2})(?:[_-]part\d+)?(?:\.txt|\.yaml)?", name, re.I)
    if match:
        code = match.group(1).upper()
        if code in ISO_CODES:
            return code
    return country_from_text(name, allow_iso=False)


def github_api_json(url: str):
    response = session.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
    response.raise_for_status()
    return response.json()


def github_index(url: str):
    payload = github_api_json(url)
    return payload if isinstance(payload, list) else []


def github_tree_entries(url: str):
    payload = github_api_json(url)
    return [entry for entry in payload.get("tree", []) if entry.get("type") == "blob"] if isinstance(payload, dict) else []


def collect_github_api_source(item):
    rows = []
    for entry in github_index(item["url"]):
        if entry.get("type") != "file" or not entry.get("download_url"):
            continue
        name = entry.get("name", "")
        hint = source_hint_from_url(name)
        try:
            raw = fetch(entry["download_url"])
            rows.extend(parse_lines(raw.decode("utf-8", errors="replace"), f"{item['name']}:{name}", hint, item.get("priority", 0)))
        except Exception as exc:
            print(f"WARN {item['name']}/{name}: {exc}")
    return rows


def collect_github_tree_source(item):
    rows = []
    for entry in github_tree_entries(item["url"]):
        path = entry.get("path", "")
        if item.get("path_regex") and not re.search(item["path_regex"], path, re.I):
            continue
        raw_url = f"https://raw.githubusercontent.com/{item['owner']}/{item['repo']}/{item.get('ref', 'main')}/{path}"
        try:
            hint = source_hint_from_url(path)
            raw = fetch(raw_url)
            rows.extend(parse_lines(raw.decode("utf-8", errors="replace"), f"{item['name']}:{path}", hint, item.get("priority", 0)))
        except Exception as exc:
            print(f"WARN {item['name']}/{path}: {exc}")
    return rows


def collect_source(item):
    if item.get("format") == "github_api":
        return collect_github_api_source(item)
    if item.get("format") == "github_tree":
        return collect_github_tree_source(item)
    if item.get("kind") == "country_template":
        return []
    raw = fetch(item["url"])
    return parse_lines(raw.decode("utf-8", errors="replace"), item["name"], source_hint_from_url(item["url"]), item.get("priority", 0))


def load_previous_snapshot():
    rows = []
    countries_dir = OUT / "countries"
    if not countries_dir.exists():
        return rows
    for path in countries_dir.glob("*.txt"):
        code = path.stem.upper()
        if code != "UNKNOWN" and code not in ISO_CODES:
            continue
        try:
            rows.extend(parse_lines(path.read_text(encoding="utf-8", errors="replace"), f"snapshot:{code}", code if code in ISO_CODES else None, -100))
        except Exception as exc:
            print(f"WARN snapshot {path.name}: {exc}")
    return rows


def tcp_check(item):
    started = time.perf_counter()
    try:
        with socket.create_connection((item["host"], item["port"]), timeout=CONNECT_TIMEOUT):
            return True, round((time.perf_counter() - started) * 1000, 1)
    except Exception:
        return False, None


def select_health_candidates(rows):
    # Full-pool screening: never cap by country/protocol before health check.
    return list(rows)


def iso_name(code: str) -> str:
    if code == "UNKNOWN":
        return "Unknown"
    country = pycountry.countries.get(alpha_2=code)
    return country.name if country else code


def main():
    cfg = json.loads((ROOT / "sources/sources.json").read_text(encoding="utf-8"))
    all_rows = []
    source_health = []
    successful_sources = 0

    for item in sorted(cfg["sources"], key=lambda source: -source.get("priority", 0)):
        started = time.perf_counter()
        try:
            rows = collect_source(item)
            all_rows.extend(rows)
            successful_sources += 1
            source_health.append({"name": item["name"], "ok": True, "nodes": len(rows), "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)})
            print(f"OK {item['name']}: {len(rows)}")
        except Exception as exc:
            source_health.append({"name": item["name"], "ok": False, "nodes": 0, "error": str(exc), "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)})
            print(f"WARN {item['name']}: {exc}")

    failed_sources = [source for source in source_health if not source["ok"]]
    if failed_sources:
        fallback = load_previous_snapshot()
        all_rows.extend(fallback)
        print(f"INFO source failures={len(failed_sources)}; loaded snapshot fallback={len(fallback)}")

    if successful_sources == 0 and not all_rows:
        raise RuntimeError("All upstream sources failed and no previous snapshot exists")

    unique = {}
    for row in all_rows:
        unique.setdefault(dedup_key(row["uri"]), row)
    rows = list(unique.values())

    for row in rows:
        if row["country"] not in ISO_CODES:
            row["country"] = "UNKNOWN"

    candidates = select_health_candidates(rows)
    print(f"INFO parsed={len(rows)} health_candidates={len(candidates)} full_pool_health_check=true")

    checked = []
    if candidates:
        with ThreadPoolExecutor(max_workers=HEALTH_WORKERS) as executor:
            futures = {executor.submit(tcp_check, row): row for row in candidates}
            for future in as_completed(futures):
                row = futures[future]
                try:
                    ok, latency = future.result()
                except Exception:
                    ok, latency = False, None
                if ok:
                    row["latency_ms"] = latency
                    checked.append(row)

    by_country = defaultdict(list)
    by_protocol = defaultdict(list)
    for row in checked:
        by_country[row["country"]].append(row)
        by_protocol[row["protocol"]].append(row)

    for country in by_country:
        # Legacy ranking: source quality first, measured TCP latency second.
        by_country[country].sort(key=lambda r: (-r.get("source_priority", 0), r.get("latency_ms", 999999), r["protocol"], r["host"]))
        by_country[country] = by_country[country][:MAX_GENERATED_PER_COUNTRY]
    for protocol in by_protocol:
        by_protocol[protocol].sort(key=lambda r: (-r.get("source_priority", 0), r.get("latency_ms", 999999), r["host"]))

    for directory in (OUT / "countries", OUT / "protocols", OUT / "metadata"):
        directory.mkdir(parents=True, exist_ok=True)
    for path in (OUT / "countries").glob("*.txt"):
        path.unlink()
    for path in (OUT / "protocols").glob("*.txt"):
        path.unlink()

    for country, items in sorted(by_country.items()):
        (OUT / "countries" / f"{country}.txt").write_text("\n".join(item["uri"] for item in items) + "\n", encoding="utf-8")
    for protocol, items in sorted(by_protocol.items()):
        (OUT / "protocols" / f"{protocol}.txt").write_text("\n".join(item["uri"] for item in items) + "\n", encoding="utf-8")

    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    index = {
        "schema": 2,
        "generated_at": generated_at,
        "total_fetched": len(all_rows),
        "unique_parsed": len(rows),
        "health_candidates": len(candidates),
        "reachable_published": len(checked),
        "allowed_ports": [80, 443],
        "protocols": {protocol: len(by_protocol.get(protocol, [])) for protocol in sorted(PROTOCOLS)},
        "countries": len(by_country),
        "country_names": {country: iso_name(country) for country in sorted(by_country)},
        "country_policy": "ISO-3166 alpha-2 only; explicit node metadata wins over feed hint; unresolved nodes go to UNKNOWN",
        "health_policy": "Every parsed node is TCP-screened on ports 80/443; legacy source priority precedes latency; Android performs authoritative Xray end-to-end Internet verification",
        "source_failures": len(failed_sources),
        "files": {"countries": "countries/", "protocols": "protocols/"},
    }
    (OUT / "metadata/index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (OUT / "metadata/countries.json").write_text(json.dumps({"countries": [{"code": c, "name": iso_name(c), "nodes": len(a)} for c, a in sorted(by_country.items())]}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (OUT / "metadata/health.json").write_text(json.dumps({"generated_at": generated_at, "sources": source_health, "reachable_published": len(checked), "health_candidates": len(candidates)}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(index, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
