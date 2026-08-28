from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

COUNTRY_TOKENS = {
    "uk":"GB", "gb":"GB", "england":"GB", "greatbritain":"GB", "britain":"GB", "us":"US", "usa":"US", "america":"US", "unitedstates":"US",
    "ca":"CA", "canada":"CA", "de":"DE", "germany":"DE", "fr":"FR", "france":"FR", "nl":"NL", "netherlands":"NL", "sg":"SG", "singapore":"SG", "jp":"JP", "japan":"JP",
    "kr":"KR", "korea":"KR", "southkorea":"KR", "au":"AU", "australia":"AU", "at":"AT", "austria":"AT", "fi":"FI", "finland":"FI", "se":"SE", "sweden":"SE",
    "dk":"DK", "denmark":"DK", "pl":"PL", "poland":"PL", "cz":"CZ", "czechia":"CZ", "ch":"CH", "switzerland":"CH", "it":"IT", "italy":"IT", "es":"ES", "spain":"ES",
    "pt":"PT", "portugal":"PT", "no":"NO", "norway":"NO", "ru":"RU", "russia":"RU", "ua":"UA", "ukraine":"UA", "tr":"TR", "turkey":"TR", "turkiye":"TR",
    "ir":"IR", "iran":"IR", "ae":"AE", "uae":"AE", "sa":"SA", "saudiarabia":"SA", "in":"IN", "india":"IN", "id":"ID", "indonesia":"ID", "my":"MY", "malaysia":"MY",
    "th":"TH", "thailand":"TH", "vn":"VN", "vietnam":"VN", "br":"BR", "brazil":"BR", "za":"ZA", "southafrica":"ZA", "nz":"NZ", "newzealand":"NZ", "hk":"HK", "hongkong":"HK",
    "tw":"TW", "taiwan":"TW", "az":"AZ", "azerbaijan":"AZ", "bg":"BG", "bulgaria":"BG", "ee":"EE", "estonia":"EE", "lt":"LT", "lithuania":"LT", "lv":"LV", "latvia":"LV",
    "hu":"HU", "hungary":"HU", "kz":"KZ", "kazakhstan":"KZ", "si":"SI", "slovenia":"SI", "sc":"SC", "seychelles":"SC", "cn":"CN", "china":"CN", "tm":"TM", "turkmenistan":"TM",
}

@lru_cache(maxsize=8192)
def resolve_host(host: str) -> str | None:
    if not host: return None
    value = host.strip().lower().rstrip('.')
    try:
        ipaddress.ip_address(value); return None
    except ValueError: pass
    labels = [x for x in re.split(r"[.\-_]+", value) if x]
    for label in labels:
        code = COUNTRY_TOKENS.get(label)
        if code and len(label) == 2: return code
    for label in labels:
        code = COUNTRY_TOKENS.get(label)
        if code and len(label) > 2: return code
    for label in labels:
        m = re.fullmatch(r"([a-z]{2})(?:\d{1,4}|[-_](?:\d{1,4}))", label)
        if m and m.group(1) in COUNTRY_TOKENS: return COUNTRY_TOKENS[m.group(1)]
    return None


def _resolve_ip(host: str) -> str | None:
    try:
        ipaddress.ip_address(host); return host
    except ValueError: pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        for info in infos:
            candidate = info[4][0]
            try:
                ip = ipaddress.ip_address(candidate)
                if not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast): return candidate
            except ValueError: continue
    except Exception: return None
    return None


def _geo_batch(ips: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for start in range(0, len(ips), 100):
        batch = ips[start:start + 100]
        payload = json.dumps([{"query": ip} for ip in batch]).encode("utf-8")
        req = urllib.request.Request("http://ip-api.com/batch?fields=status,countryCode,query", data=payload, headers={"Content-Type":"application/json", "User-Agent":"VPN-Nodes-CountryResolver/1"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=20) as response: data = json.loads(response.read().decode("utf-8"))
            for item in data if isinstance(data, list) else []:
                code = str(item.get("countryCode", ""))
                if item.get("status") == "success" and re.fullmatch(r"[A-Z]{2}", code): result[str(item.get("query"))] = code
        except Exception: continue
    return result


def resolve_rows(rows: list[dict]) -> dict[str, int]:
    hostname_resolved = 0
    for row in rows:
        if row.get("country") != "UNKNOWN": continue
        code = resolve_host(str(row.get("host") or ""))
        if code:
            row["country"] = code; row["country_resolution"] = "hostname"; hostname_resolved += 1
    unresolved = [r for r in rows if r.get("country") == "UNKNOWN"]
    host_ip: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = {pool.submit(_resolve_ip, str(r.get("host") or "")): r for r in unresolved}
        for future in as_completed(futures):
            row = futures[future]
            try: ip = future.result()
            except Exception: ip = None
            if ip: host_ip[str(row.get("host") or "")] = ip
    geo = _geo_batch(sorted(set(host_ip.values())))
    ip_resolved = 0
    for row in unresolved:
        ip = host_ip.get(str(row.get("host") or "")); code = geo.get(ip or "")
        if code:
            row["country"] = code; row["country_resolution"] = "ip_geolocation"; ip_resolved += 1
    return {"hostname": hostname_resolved, "ip_geolocation": ip_resolved, "unknown": sum(1 for r in rows if r.get("country") == "UNKNOWN")}
