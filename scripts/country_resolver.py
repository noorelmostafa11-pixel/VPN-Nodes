from __future__ import annotations

import ipaddress
import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path

import geoip2.database
from geoip2.errors import AddressNotFoundError

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


@lru_cache(maxsize=16384)
def resolve_ip(address: str) -> str | None:
    value = str(address or "").strip()
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
        # Keep diagnostics for cases where GeoLite2 has the address but country is
        # represented by a fallback record instead of the primary country field.
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
    """Resolve UNKNOWN rows through the local GeoLite2 Country database only.

    Existing explicit country metadata is never overwritten. Hostnames are resolved
    to public IPs with a cached DNS lookup, then looked up locally in GeoLite2.
    Failure categories are counted instead of being swallowed so the workflow can
    distinguish missing GeoIP coverage from real errors.
    """
    with FAILURE_LOCK:
        for key in FAILURE_STATS:
            FAILURE_STATS[key] = 0

    unresolved = [row for row in rows if row.get("country") == "UNKNOWN"]
    if not unresolved:
        return {
            "hostname": 0,
            "geoip_local": 0,
            "unknown": 0,
            "database": str(GEOIP_DB_PATH),
            "database_loaded": _reader() is not None,
            "failure_stats": dict(FAILURE_STATS),
        }

    reader = _reader()
    if reader is None:
        reason = str(_db_error) if _db_error else "GeoLite2 database unavailable"
        print(f"WARN country_resolver: {reason}")
        return {
            "hostname": 0,
            "geoip_local": 0,
            "unknown": len(unresolved),
            "database": str(GEOIP_DB_PATH),
            "database_loaded": False,
            "failure_stats": dict(FAILURE_STATS),
        }

    address_to_ip: dict[str, str | None] = {}
    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as pool:
        futures = {pool.submit(resolve_ip, str(row.get("host") or "")): str(row.get("host") or "") for row in unresolved}
        for future in as_completed(futures):
            host = futures[future]
            try:
                address_to_ip[host] = future.result()
            except Exception:
                _inc_failure("other")
                address_to_ip[host] = None

    resolved = 0
    dns_resolved = 0
    for row in unresolved:
        host = str(row.get("host") or "")
        ip = address_to_ip.get(host)
        if not ip:
            row["country_resolution"] = "unresolved"
            row["country_resolution_confidence"] = "none"
            continue
        if ip != host:
            dns_resolved += 1
            row["resolved_ip"] = ip
        country = country_from_ip(ip)
        if country:
            row["country"] = country
            row["country_resolution"] = "geolite2_local"
            row["country_resolution_confidence"] = "medium"
            resolved += 1
        else:
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
        "geoip_local": resolved,
        "ip_geolocation": resolved,
        "unknown": unknown,
        "database": str(GEOIP_DB_PATH),
        "database_loaded": True,
        "failure_stats": stats,
    }
