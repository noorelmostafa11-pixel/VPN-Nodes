from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from urllib.parse import urlencode

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

IP2LOCATION_DAILY_LIMIT = 1000
IP2LOCATION_TIMEOUT = 8
GEO_MAX_WORKERS = 24
KNOWN_ANYCAST_ASNS = {
    "13335",  # Cloudflare
}
KNOWN_CDN_HOST_PATTERNS = (
    "cloudflare.com", "fastly.net", "akamai.net", "akamaihd.net", "cloudfront.net",
)

@lru_cache(maxsize=8192)
def resolve_host(host: str) -> str | None:
    if not host:
        return None
    value = host.strip().lower().rstrip('.')
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    labels = [x for x in re.split(r"[.\-_]+", value) if x]
    for label in labels:
        code = COUNTRY_TOKENS.get(label)
        if code and len(label) == 2:
            return code
    for label in labels:
        code = COUNTRY_TOKENS.get(label)
        if code and len(label) > 2:
            return code
    for label in labels:
        m = re.fullmatch(r"([a-z]{2})(?:\d{1,4}|[-_](?:\d{1,4}))", label)
        if m and m.group(1) in COUNTRY_TOKENS:
            return COUNTRY_TOKENS[m.group(1)]
    return None


def _resolve_ip(host: str) -> str | None:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        for info in infos:
            candidate = info[4][0]
            try:
                ip = ipaddress.ip_address(candidate)
                if not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast):
                    return candidate
            except ValueError:
                continue
    except Exception:
        return None
    return None


def _normalize_country(code: object) -> str | None:
    value = str(code or "").strip().upper()
    return value if re.fullmatch(r"[A-Z]{2}", value) else None


def _geo_batch_ip_api(ips: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for start in range(0, len(ips), 100):
        batch = ips[start:start + 100]
        payload = json.dumps([{"query": ip} for ip in batch]).encode("utf-8")
        req = urllib.request.Request(
            "http://ip-api.com/batch?fields=status,countryCode,proxy,hosting,query",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "VPN-Nodes-CountryResolver/4"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                data = json.loads(response.read().decode("utf-8"))
            for item in data if isinstance(data, list) else []:
                code = _normalize_country(item.get("countryCode"))
                query_ip = str(item.get("query") or "")
                if item.get("status") == "success" and code and query_ip:
                    result[query_ip] = code
        except Exception:
            continue
    return result


def _ip2location_lookup(ip: str) -> tuple[str, str] | None:
    url = "https://api.ip2location.io/?" + urlencode({"ip": ip, "format": "json"})
    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "VPN-Nodes-CountryResolver/4 (IP2Location)"},
            method="GET",
        )
        with urllib.request.urlopen(request, timeout=IP2LOCATION_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))
        code = _normalize_country(payload.get("country_code")) if isinstance(payload, dict) else None
        if code:
            return ip, code
    except Exception:
        return None
    return None


def _geo_ip2location(ips: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    limited = ips[:IP2LOCATION_DAILY_LIMIT]
    if not limited:
        return result
    with ThreadPoolExecutor(max_workers=GEO_MAX_WORKERS) as pool:
        futures = {pool.submit(_ip2location_lookup, ip): ip for ip in limited}
        for future in as_completed(futures):
            try:
                item = future.result()
            except Exception:
                item = None
            if item:
                result[item[0]] = item[1]
    return result


def _hostname_has_cdn_signal(host: str) -> bool:
    value = str(host or "").lower().rstrip('.')
    return any(pattern in value for pattern in KNOWN_CDN_HOST_PATTERNS)


def _provider_disagreement(ip2: str | None, api: str | None) -> bool:
    return bool(ip2 and api and ip2 != api)


def resolve_rows(rows: list[dict]) -> dict[str, int]:
    """Resolve country while preserving every parsed/reachable node.

    Strong signals are never overwritten. IP geolocation is only a fallback for rows
    that remain UNKNOWN. Two independent providers are compared; disagreement leaves
    UNKNOWN. Known CDN/Anycast IPs are never assigned a country from GeoIP alone because
    the advertised IP can identify the network edge rather than the VPN endpoint.
    """
    hostname_resolved = 0
    for row in rows:
        if row.get("country") != "UNKNOWN":
            continue
        code = resolve_host(str(row.get("host") or ""))
        if code:
            row["country"] = code
            row["country_resolution"] = "hostname"
            row["country_resolution_confidence"] = "medium"
            hostname_resolved += 1

    unresolved = [r for r in rows if r.get("country") == "UNKNOWN"]
    host_ip: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = {pool.submit(_resolve_ip, str(r.get("host") or "")): r for r in unresolved}
        for future in as_completed(futures):
            row = futures[future]
            try:
                ip = future.result()
            except Exception:
                ip = None
            if ip:
                host_ip.setdefault(str(row.get("host") or ""), ip)

    ips = sorted(set(host_ip.values()))
    ip2location = _geo_ip2location(ips)
    ip_api = _geo_batch_ip_api(ips)

    consensus = 0
    ip2location_only = 0
    ip_api_only = 0
    conflicts = 0
    cdn_anycast_unknown = 0

    for row in unresolved:
        host = str(row.get("host") or "")
        ip = host_ip.get(host)
        if not ip:
            continue
        ip2 = ip2location.get(ip)
        api = ip_api.get(ip)
        is_cdn = _hostname_has_cdn_signal(host)
        is_known_anycast = False
        asn = str(row.get("asn") or "").strip()
        if asn:
            asn_digits = re.sub(r"^AS", "", asn, flags=re.IGNORECASE)
            is_known_anycast = asn_digits in KNOWN_ANYCAST_ASNS

        if is_cdn or is_known_anycast:
            row["country_resolution"] = "cdn_anycast_guard"
            row["country_resolution_confidence"] = "none"
            row["geo_conflict"] = {
                "ip2location": ip2,
                "ip_api": api,
                "reason": "cdn_or_anycast_endpoint",
            }
            cdn_anycast_unknown += 1
            continue

        if ip2 and api and ip2 == api:
            row["country"] = ip2
            row["country_resolution"] = "geo_consensus"
            row["country_resolution_confidence"] = "medium"
            consensus += 1
        elif ip2 and not api:
            row["country"] = ip2
            row["country_resolution"] = "ip2location"
            row["country_resolution_confidence"] = "low"
            ip2location_only += 1
        elif api and not ip2:
            row["country"] = api
            row["country_resolution"] = "ip_geolocation"
            row["country_resolution_confidence"] = "low"
            ip_api_only += 1
        elif _provider_disagreement(ip2, api):
            row["country_resolution"] = "geo_conflict"
            row["country_resolution_confidence"] = "none"
            row["geo_conflict"] = {"ip2location": ip2, "ip_api": api}
            conflicts += 1

    unknown = sum(1 for r in rows if r.get("country") == "UNKNOWN")
    return {
        "hostname": hostname_resolved,
        "ip2location": ip2location_only,
        "geo_consensus": consensus,
        "ip_geolocation": ip2location_only + consensus + ip_api_only,
        "geo_conflicts": conflicts,
        "cdn_anycast_unknown": cdn_anycast_unknown,
        "unknown": unknown,
    }
