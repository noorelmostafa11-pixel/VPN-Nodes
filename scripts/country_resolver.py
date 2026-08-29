from __future__ import annotations

import ipaddress
import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path

import geoip2.database

ROOT = Path(__file__).resolve().parents[1]
GEOIP_DB_PATH = Path(os.getenv("GEOIP_DB_PATH", str(ROOT / "data" / "GeoLite2-Country.mmdb")))
DNS_WORKERS = 64

_DB_LOCK = threading.Lock()
_db_reader = None
_db_error = None


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


@lru_cache(maxsize=16384)
def resolve_ip(address: str) -> str | None:
    value = str(address or "").strip()
    try:
        parsed = ipaddress.ip_address(value)
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved or parsed.is_multicast:
            return None
        return value
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return None

    # Prefer public IPv4 first, then public IPv6.
    candidates: list[str] = []
    for info in infos:
        candidate = str(info[4][0])
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved or parsed.is_multicast:
            continue
        candidates.append(candidate)
    candidates.sort(key=lambda item: (0 if "." in item else 1, item))
    return candidates[0] if candidates else None


def country_from_ip(ip: str) -> str | None:
    reader = _reader()
    if reader is None:
        return None
    try:
        return _normalize(reader.country(ip).country.iso_code)
    except Exception:
        return None


def resolve_rows(rows: list[dict]) -> dict[str, int | str]:
    """Resolve only UNKNOWN rows through a local GeoLite2 Country database.

    Explicit metadata already present on a row is never overwritten. Hostnames are
    resolved to an IP first, with DNS results cached. GeoIP lookup is entirely local;
    no external geolocation API is called during catalog generation.
    """
    unresolved = [row for row in rows if row.get("country") == "UNKNOWN"]
    if not unresolved:
        return {"hostname": 0, "geoip_local": 0, "unknown": 0, "database": str(GEOIP_DB_PATH), "database_loaded": _reader() is not None}

    reader = _reader()
    if reader is None:
        reason = str(_db_error) if _db_error else "GeoLite2 database unavailable"
        print(f"WARN country_resolver: {reason}")
        return {"hostname": 0, "geoip_local": 0, "unknown": len(unresolved), "database": str(GEOIP_DB_PATH), "database_loaded": False}

    address_to_ip: dict[str, str | None] = {}
    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as pool:
        futures = {pool.submit(resolve_ip, str(row.get("host") or "")): str(row.get("host") or "") for row in unresolved}
        for future in as_completed(futures):
            address_to_ip[futures[future]] = future.result()

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
    return {
        "hostname": dns_resolved,
        "geoip_local": resolved,
        "ip_geolocation": resolved,
        "unknown": unknown,
        "database": str(GEOIP_DB_PATH),
        "database_loaded": True,
    }
