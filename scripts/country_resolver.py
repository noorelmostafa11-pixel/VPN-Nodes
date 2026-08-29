from __future__ import annotations

import ipaddress
import os
import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path

import geoip2.database
from geoip2.errors import AddressNotFoundError
import pycountry

ROOT = Path(__file__).resolve().parents[1]
GEOIP_DB_PATH = Path(os.getenv("GEOIP_DB_PATH", str(ROOT / "data" / "GeoLite2-Country.mmdb")))
DNS_WORKERS = 64

_DB_LOCK = threading.Lock()
_db_reader = None
_db_error = None
FAILURE_LOCK = threading.Lock()
FAILURE_STATS = {
    "address_not_found": 0,
    "invalid_database": 0,
    "invalid_ip": 0,
    "other": 0,
    "dns_failure": 0,
    "lookups": 0,
}

# High-signal country aliases used only for explicit node metadata.
ALIASES = {
    "uk": "GB", "gb": "GB", "england": "GB", "greatbritain": "GB", "britain": "GB",
    "us": "US", "usa": "US", "america": "US", "unitedstates": "US",
    "ca": "CA", "canada": "CA", "de": "DE", "germany": "DE", "fr": "FR", "france": "FR",
    "nl": "NL", "netherlands": "NL", "sg": "SG", "singapore": "SG", "jp": "JP", "japan": "JP",
    "kr": "KR", "korea": "KR", "southkorea": "KR", "au": "AU", "australia": "AU",
    "at": "AT", "austria": "AT", "fi": "FI", "finland": "FI", "se": "SE", "sweden": "SE",
    "dk": "DK", "denmark": "DK", "pl": "PL", "poland": "PL", "cz": "CZ", "czechia": "CZ",
    "ch": "CH", "switzerland": "CH", "it": "IT", "italy": "IT", "es": "ES", "spain": "ES",
    "pt": "PT", "portugal": "PT", "no": "NO", "norway": "NO", "ru": "RU", "russia": "RU",
    "ua": "UA", "ukraine": "UA", "tr": "TR", "turkey": "TR", "turkiye": "TR",
    "ir": "IR", "iran": "IR", "ae": "AE", "uae": "AE", "emirates": "AE",
    "sa": "SA", "saudiarabia": "SA", "in": "IN", "india": "IN", "id": "ID", "indonesia": "ID",
    "my": "MY", "malaysia": "MY", "th": "TH", "thailand": "TH", "vn": "VN", "vietnam": "VN",
    "br": "BR", "brazil": "BR", "za": "ZA", "southafrica": "ZA", "nz": "NZ", "newzealand": "NZ",
    "hk": "HK", "hongkong": "HK", "tw": "TW", "taiwan": "TW", "az": "AZ", "azerbaijan": "AZ",
    "bg": "BG", "bulgaria": "BG", "ee": "EE", "estonia": "EE", "lt": "LT", "lithuania": "LT",
    "lv": "LV", "latvia": "LV", "hu": "HU", "hungary": "HU", "kz": "KZ", "kazakhstan": "KZ",
    "si": "SI", "slovenia": "SI", "sc": "SC", "seychelles": "SC", "cn": "CN", "china": "CN",
    "tm": "TM", "turkmenistan": "TM", "sk": "SK", "slovakia": "SK", "ro": "RO", "romania": "RO",
    "rs": "RS", "serbia": "RS", "ie": "IE", "ireland": "IE", "il": "IL", "israel": "IL",
    "ph": "PH", "philippines": "PH", "ge": "GE", "georgia": "GE", "cr": "CR", "costarica": "CR",
    "cy": "CY", "cyprus": "CY", "al": "AL", "albania": "AL", "am": "AM", "armenia": "AM",
    "by": "BY", "belarus": "BY", "bz": "BZ", "belize": "BZ", "cf": "CF", "centralafricanrepublic": "CF",
    "md": "MD", "moldova": "MD", "ph": "PH", "vi": "VI", "virginislands": "VI",
    "mh": "MH", "marshallislands": "MH",
}
ISO_CODES = {c.alpha_2.upper() for c in pycountry.countries}
TECHNICAL_TOKENS = {"ws", "tls", "tcp", "raw", "grpc", "reality", "http", "https", "udp", "auto", "none", "vless", "vmess", "trojan", "ss"}

# Exact ISO-style metadata patterns only; avoid treating arbitrary two-letter words as countries.
EXPLICIT_CODE_RE = re.compile(r"(?<![A-Za-z0-9])(?:\[|\(|_|-)?([A-Z]{2})(?:\]|\)|_|-|$)(?![A-Za-z0-9])")

def _reader():
    global _db_reader, _db_error
    if _db_reader is not None or _db_error is not None:
        return _db_reader
    with _DB_LOCK:
        if _db_reader is None and _db_error is None:
            try:
                if not GEOIP_DB_PATH.is_file() or GEOIP_DB_PATH.stat().st_size == 0:
                    raise FileNotFoundError(f"GeoLite2 database not found: {GEOIP_DB_PATH}")
                _db_reader = geoip2.database.Reader(str(GEOIP_DB_PATH))
            except Exception as exc:
                _db_error = exc
        return _db_reader


def _normalize(code: object) -> str | None:
    value = str(code or "").strip().upper()
    return value if len(value) == 2 and value.isalpha() else None


def _inc_failure(key: str) -> None:
    with FAILURE_LOCK:
        FAILURE_STATS[key] = FAILURE_STATS.get(key, 0) + 1


def _flag_to_country_code(text: str) -> str | None:
    for i in range(len(text) - 1):
        a, b = text[i], text[i + 1]
        if "\U0001F1E6" <= a <= "\U0001F1FF" and "\U0001F1E6" <= b <= "\U0001F1FF":
            return chr(ord(a) - 0x1F1E6 + ord("A")) + chr(ord(b) - 0x1F1E6 + ord("A"))
    return None


def extract_country_from_text(text: str) -> str | None:
    """Extract only high-signal explicit country metadata from a node remark/name."""
    if not text:
        return None
    flag = _flag_to_country_code(text)
    if flag in ISO_CODES:
        return flag

    raw = text.lower()
    compact = re.sub(r"[^a-z0-9]+", "", raw)
    # Prefer longer country names before short codes such as 'in' or 'us'.
    for token, code in sorted(ALIASES.items(), key=lambda item: len(item[0]), reverse=True):
        if len(token) > 2 and token in compact:
            return code

    # ISO code only when delimited or surrounded by common node-label punctuation.
    upper = text.upper()
    for match in re.finditer(r"(?<![A-Z0-9])([A-Z]{2})(?![A-Z0-9])", upper):
        code = match.group(1)
        if code in ISO_CODES and code.lower() not in TECHNICAL_TOKENS:
            return code
    return None


def _clean_host(value: str) -> str:
    text = str(value or "").strip()
    if text.startswith("[") and "]" in text:
        return text[1:text.index("]")]
    # Only strip host:port for a single-colon endpoint; preserve IPv6 literals.
    if text.count(":") == 1:
        host, maybe_port = text.rsplit(":", 1)
        if maybe_port.isdigit():
            return host
    return text


@lru_cache(maxsize=16384)
def resolve_ip(address: str) -> str | None:
    value = _clean_host(address)
    if not value:
        _inc_failure("dns_failure")
        return None
    try:
        parsed = ipaddress.ip_address(value)
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved or parsed.is_multicast:
            _inc_failure("invalid_ip")
            return None
        return value
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        _inc_failure("dns_failure")
        return None

    candidates: list[str] = []
    for info in infos:
        candidate = str(info[4][0])
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            _inc_failure("invalid_ip")
            continue
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved or parsed.is_multicast:
            continue
        candidates.append(candidate)
    candidates.sort(key=lambda item: (0 if "." in item else 1, item))
    if not candidates:
        _inc_failure("dns_failure")
        return None
    return candidates[0]


def country_from_ip(ip: str) -> str | None:
    reader = _reader()
    if reader is None:
        return None
    with FAILURE_LOCK:
        FAILURE_STATS["lookups"] += 1
    try:
        response = reader.country(ip)
        code = _normalize(response.country.iso_code)
        if code:
            return code
        code = _normalize(response.registered_country.iso_code)
        if code:
            return code
        code = _normalize(response.represented_country.iso_code)
        if code:
            return code
        return None
    except AddressNotFoundError:
        _inc_failure("address_not_found")
        return None
    except ValueError:
        _inc_failure("invalid_ip")
        return None
    except Exception:
        _inc_failure("other")
        return None


def resolve_rows(rows: list[dict]) -> dict[str, int | str | bool | dict]:
    """Resolve UNKNOWN rows with explicit node metadata first, then local GeoLite2.

    Metadata from the node's remark/name/ps fields wins because it can describe the
    intended VPN exit country even when the endpoint IP belongs to a CDN/Anycast edge.
    GeoLite2 is used only when no explicit country metadata is present. No online
    geolocation API is used during catalog generation.
    """
    with FAILURE_LOCK:
        for key in FAILURE_STATS:
            FAILURE_STATS[key] = 0

    unresolved = [row for row in rows if row.get("country") == "UNKNOWN"]
    if not unresolved:
        return {
            "hostname": 0,
            "geoip_local": 0,
            "metadata_fallback": 0,
            "unknown": 0,
            "database": str(GEOIP_DB_PATH),
            "database_loaded": _reader() is not None,
            "failure_stats": dict(FAILURE_STATS),
        }

    reader = _reader()

    # Resolve DNS/IP once for diagnostics and for GeoLite fallback. Metadata is still
    # evaluated before using the GeoIP answer.
    hosts_to_resolve: set[str] = set()
    for row in unresolved:
        for key in ("host", "server", "address"):
            value = str(row.get(key) or "").strip()
            if value:
                hosts_to_resolve.add(value)

    address_to_ip: dict[str, str | None] = {}
    if hosts_to_resolve:
        with ThreadPoolExecutor(max_workers=DNS_WORKERS) as pool:
            futures = {pool.submit(resolve_ip, host): host for host in hosts_to_resolve}
            for future in as_completed(futures):
                host = futures[future]
                try:
                    address_to_ip[host] = future.result()
                except Exception:
                    _inc_failure("other")
                    address_to_ip[host] = None

    resolved_geoip = 0
    resolved_metadata = 0
    dns_resolved = 0

    for row in unresolved:
        remark_text = " ".join(
            str(row.get(key) or "") for key in ("remark", "name", "ps", "remarks", "title")
        )
        meta_country = extract_country_from_text(remark_text)

        if meta_country:
            row["country"] = meta_country
            row["country_resolution"] = "metadata_remark"
            row["country_resolution_confidence"] = "high"
            resolved_metadata += 1
            for key in ("host", "server", "address"):
                raw_target = str(row.get(key) or "").strip()
                ip = address_to_ip.get(raw_target)
                if ip:
                    if _clean_host(raw_target) != ip:
                        dns_resolved += 1
                    row["resolved_ip"] = ip
                    break
            continue

        if reader is None:
            row["country_resolution"] = "geolite2_unavailable"
            row["country_resolution_confidence"] = "none"
            continue

        country = None
        for key in ("host", "server", "address"):
            raw_target = str(row.get(key) or "").strip()
            if not raw_target:
                continue
            ip = address_to_ip.get(raw_target)
            if not ip:
                continue
            if _clean_host(raw_target) != ip:
                dns_resolved += 1
            country = country_from_ip(ip)
            if country:
                row["country"] = country
                row["resolved_ip"] = ip
                row["country_resolution"] = "geolite2_local"
                row["country_resolution_confidence"] = "medium"
                resolved_geoip += 1
                break

        if not country:
            row["country_resolution"] = "geolite2_unknown"
            row["country_resolution_confidence"] = "none"

    unknown = sum(1 for row in rows if row.get("country") == "UNKNOWN")
    stats = dict(FAILURE_STATS)
    print(
        "INFO country_resolution_failures="
        f"address_not_found:{stats['address_not_found']} "
        f"dns_failure:{stats['dns_failure']} "
        f"invalid_ip:{stats['invalid_ip']} "
        f"other:{stats['other']} "
        f"lookups:{stats['lookups']}"
    )
    return {
        "hostname": dns_resolved,
        "geoip_local": resolved_geoip,
        "ip_geolocation": resolved_geoip,
        "metadata_fallback": resolved_metadata,
        "unknown": unknown,
        "database": str(GEOIP_DB_PATH),
        "database_loaded": reader is not None,
        "failure_stats": stats,
    }
