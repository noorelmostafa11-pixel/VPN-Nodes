#!/usr/bin/env python3
"""Preserve unresolved/Cloudflare nodes and distribute them across known countries.

Country files are kept in two logical tiers: nodes with explicit country metadata
remain exactly where discovered and stay first; confirmed Cloudflare endpoints that
lack explicit node metadata are quarantined as unresolved; unresolved nodes are then
round-robin appended across already-discovered country feeds. No new country is made.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote, urlparse

import pycountry

import cloudflare_detector
import country_resolver

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
COUNTRIES_DIR = OUT / "countries"
PROTOCOLS_DIR = OUT / "protocols"
GLOBAL_DIR = OUT / "global"
META_DIR = OUT / "metadata"

ISO_CODES = {c.alpha_2.upper() for c in pycountry.countries}
SCHEME_TO_PROTOCOL = {
    "vless": "vless",
    "vmess": "vmess",
    "trojan": "trojan",
    "ss": "shadowsocks",
}


def _read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    ]


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")


def _protocol_of(uri: str) -> str | None:
    match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://", uri)
    if not match:
        return None
    return SCHEME_TO_PROTOCOL.get(match.group(1).lower())


def _explicit_metadata(uri: str) -> str | None:
    """Use only the URI remark/fragment as node-owned explicit metadata."""
    try:
        parsed = urlparse(uri)
        fragment = unquote(parsed.fragment or "")
        return country_resolver.extract_country_from_text(fragment)
    except Exception:
        return None


def _endpoint_host(uri: str) -> str | None:
    try:
        return urlparse(uri).hostname
    except Exception:
        return None


def _is_confirmed_cloudflare(uri: str) -> bool:
    host = _endpoint_host(uri)
    if not host:
        return False
    if cloudflare_detector.is_cloudflare_host(host):
        return True
    try:
        resolved_ip = country_resolver.resolve_ip(host)
    except Exception:
        resolved_ip = None
    return cloudflare_detector.is_confirmed_cloudflare(host, resolved_ip)


def _collect_existing_unknown() -> list[str]:
    nodes: list[str] = []
    seen: set[str] = set()
    for path in sorted(GLOBAL_DIR.glob("server-*.txt")):
        for line in _read_lines(path):
            if line not in seen:
                seen.add(line)
                nodes.append(line)
    return nodes


def _quarantine_confirmed_cloudflare() -> tuple[list[str], int]:
    """Move CF endpoints without explicit metadata out of country buckets.

    Nodes with explicit country metadata in their URI remark are protected. Nodes
    with no explicit metadata and a confirmed Cloudflare hostname/IP become UNKNOWN.
    """
    unknown: list[str] = []
    seen: set[str] = set()
    quarantined = 0

    for path in sorted(COUNTRIES_DIR.glob("*.txt")):
        if path.stem.upper() not in ISO_CODES:
            continue
        original = _read_lines(path)
        kept: list[str] = []
        changed = False
        for uri in original:
            if _explicit_metadata(uri):
                kept.append(uri)
                continue
            if _is_confirmed_cloudflare(uri):
                changed = True
                quarantined += 1
                if uri not in seen:
                    seen.add(uri)
                    unknown.append(uri)
            else:
                kept.append(uri)
        if changed:
            _write_lines(path, kept)

    return unknown, quarantined


def _append_unique(path: Path, uri: str) -> bool:
    existing = _read_lines(path)
    if uri in set(existing):
        return False
    existing.append(uri)
    _write_lines(path, existing)
    return True


def _redistribute(unknown: list[str], countries: list[str]) -> dict[str, int]:
    added_by_country = {country: 0 for country in countries}
    if not unknown or not countries:
        return added_by_country

    for index, uri in enumerate(unknown):
        country = countries[index % len(countries)]
        path = COUNTRIES_DIR / f"{country}.txt"
        if _append_unique(path, uri):
            added_by_country[country] += 1

    return added_by_country


def _refresh_protocols(unknown: list[str]) -> None:
    for uri in unknown:
        protocol = _protocol_of(uri)
        if not protocol:
            continue
        path = PROTOCOLS_DIR / f"{protocol}.txt"
        _append_unique(path, uri)


def _delete_global_shards() -> None:
    for path in GLOBAL_DIR.glob("server-*.txt"):
        path.unlink()


def _refresh_metadata(
    countries: list[str],
    added_by_country: dict[str, int],
    eligible_unknown: int,
    quarantined_cloudflare: int,
    remaining_unknown: int,
) -> None:
    redistribution = {
        "source": "UNKNOWN/global + confirmed_cloudflare_without_metadata",
        "eligible_unknown": eligible_unknown,
        "cloudflare_quarantined": quarantined_cloudflare,
        "redistributed_total": sum(added_by_country.values()),
        "remaining_unknown": remaining_unknown,
        "countries_used": countries,
        "by_country": added_by_country,
        "strategy": "round_robin_equal_append_after_discovered_nodes",
        "new_countries_created": [],
    }

    for path in (META_DIR / "index.json", META_DIR / "health.json"):
        if not path.is_file():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for field in ("published_by_country", "reachable_by_country"):
            values = data.get(field)
            if isinstance(values, dict):
                for country, added in added_by_country.items():
                    if added:
                        values[country] = int(values.get(country, 0)) + added
        data["redistribution"] = redistribution
        data["global_unknown"] = {
            "total": remaining_unknown,
            "server_size": 500,
            "servers": (remaining_unknown + 499) // 500,
            "files": "global/server-N.txt",
        }
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    countries_path = META_DIR / "countries.json"
    if countries_path.is_file():
        data = json.loads(countries_path.read_text(encoding="utf-8"))
        for item in data.get("countries", []):
            country = item.get("code")
            if country in added_by_country and added_by_country[country]:
                added = added_by_country[country]
                item["nodes"] = int(item.get("nodes", 0)) + added
                item["reachable"] = int(item.get("reachable", 0)) + added
        data["redistribution"] = redistribution
        countries_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    existing_unknown = _collect_existing_unknown()
    seen = set(existing_unknown)

    quarantined_unknown, quarantined_cloudflare = _quarantine_confirmed_cloudflare()
    for uri in quarantined_unknown:
        if uri not in seen:
            existing_unknown.append(uri)
            seen.add(uri)

    country_files = {
        path.stem.upper(): path
        for path in COUNTRIES_DIR.glob("*.txt")
        if path.stem.upper() in ISO_CODES and path.is_file()
    }
    countries = sorted(country_files)

    added_by_country = _redistribute(existing_unknown, countries)
    redistributed_total = sum(added_by_country.values())
    remaining_unknown = len(existing_unknown) - redistributed_total

    _refresh_protocols(existing_unknown[:redistributed_total] if redistributed_total else [])
    if remaining_unknown == 0:
        _delete_global_shards()

    _refresh_metadata(
        countries,
        added_by_country,
        len(existing_unknown),
        quarantined_cloudflare,
        remaining_unknown,
    )

    print(
        f"INFO unknown_redistribution eligible={len(existing_unknown)} "
        f"cloudflare_quarantined={quarantined_cloudflare} "
        f"redistributed={redistributed_total} remaining={remaining_unknown} "
        f"countries={len(countries)}"
    )
    print(
        "INFO unknown_redistribution_by_country="
        + json.dumps(added_by_country, sort_keys=True)
    )


if __name__ == "__main__":
    main()
