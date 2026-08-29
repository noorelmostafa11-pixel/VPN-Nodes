#!/usr/bin/env python3
"""Preserve confirmed nodes and evenly distribute unresolved nodes.

Each country feed is treated as two logical tiers:
1) nodes already assigned to the country by trusted metadata or GeoLite2 remain
   first and keep their existing order;
2) unresolved/Cloudflare nodes are appended after the confirmed tier.

The unresolved pool is divided as evenly as possible across countries that still
contain confirmed nodes after quarantine. No new country is created.
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
    """Use only node-owned URI fragment metadata."""
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


def _collect_global_unknown() -> list[str]:
    nodes: list[str] = []
    seen: set[str] = set()
    for path in sorted(GLOBAL_DIR.glob("server-*.txt")):
        for line in _read_lines(path):
            if line not in seen:
                seen.add(line)
                nodes.append(line)
    return nodes


def _quarantine_confirmed_cloudflare() -> tuple[list[str], int]:
    """Remove confirmed Cloudflare endpoints without node metadata from country feeds."""
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


def _discovered_country_files() -> dict[str, Path]:
    """Countries that still have confirmed nodes after CF quarantine."""
    return {
        path.stem.upper(): path
        for path in COUNTRIES_DIR.glob("*.txt")
        if path.stem.upper() in ISO_CODES and _read_lines(path)
    }


def _redistribute_equal(unknown: list[str], country_files: dict[str, Path]) -> dict[str, int]:
    """Split the complete unresolved pool equally, then append after confirmed nodes."""
    countries = sorted(country_files)
    added = {country: 0 for country in countries}
    if not unknown or not countries:
        return added

    total = len(unknown)
    base, remainder = divmod(total, len(countries))
    cursor = 0

    for index, country in enumerate(countries):
        take = base + (1 if index < remainder else 0)
        if take <= 0:
            continue
        path = country_files[country]
        existing = _read_lines(path)
        existing_set = set(existing)
        batch = [uri for uri in unknown[cursor:cursor + take] if uri not in existing_set]
        if batch:
            existing.extend(batch)
            _write_lines(path, existing)
            added[country] += len(batch)
        cursor += take

    return added


def _refresh_protocols(nodes: list[str]) -> None:
    """Keep protocol feeds synchronized with every redistributed node."""
    for uri in nodes:
        protocol = _protocol_of(uri)
        if not protocol:
            continue
        path = PROTOCOLS_DIR / f"{protocol}.txt"
        existing = _read_lines(path)
        if uri not in set(existing):
            existing.append(uri)
            _write_lines(path, existing)


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
        "strategy": "equal_quotient_remainder_append_after_confirmed_nodes",
        "new_countries_created": [],
    }

    for path in (META_DIR / "index.json", META_DIR / "health.json"):
        if not path.is_file():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for field in ("published_by_country", "reachable_by_country"):
            values = data.get(field)
            if isinstance(values, dict):
                for country, add_count in added_by_country.items():
                    if add_count:
                        values[country] = int(values.get(country, 0)) + add_count
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
                add_count = added_by_country[country]
                item["nodes"] = int(item.get("nodes", 0)) + add_count
                item["reachable"] = int(item.get("reachable", 0)) + add_count
        data["redistribution"] = redistribution
        countries_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    unknown = _collect_global_unknown()
    seen = set(unknown)

    quarantined_unknown, quarantined_cloudflare = _quarantine_confirmed_cloudflare()
    for uri in quarantined_unknown:
        if uri not in seen:
            unknown.append(uri)
            seen.add(uri)

    country_files = _discovered_country_files()
    countries = sorted(country_files)

    # IMPORTANT: confirmed nodes remain exactly as they are; unresolved nodes are
    # appended only after them. The entire unknown pool is divided across countries.
    added_by_country = _redistribute_equal(unknown, country_files)
    redistributed_total = sum(added_by_country.values())
    remaining_unknown = len(unknown) - redistributed_total

    _refresh_protocols(unknown)
    if remaining_unknown == 0:
        _delete_global_shards()

    _refresh_metadata(
        countries,
        added_by_country,
        len(unknown),
        quarantined_cloudflare,
        remaining_unknown,
    )

    # Explicit observability for the exact policy being applied.
    confirmed_total = sum(len(_read_lines(path)) for path in country_files.values()) - redistributed_total
    print(
        f"INFO unknown_redistribution eligible={len(unknown)} "
        f"cloudflare_quarantined={quarantined_cloudflare} "
        f"redistributed={redistributed_total} remaining={remaining_unknown} "
        f"countries={len(countries)} confirmed_kept_first={confirmed_total}"
    )
    print(
        "INFO unknown_redistribution_by_country="
        + json.dumps(added_by_country, sort_keys=True)
    )
    print(
        "INFO unknown_distribution_rule="
        f"total={len(unknown)} countries={len(countries)} "
        f"base={len(unknown) // len(countries) if countries else 0} "
        f"remainder={len(unknown) % len(countries) if countries else 0}"
    )


if __name__ == "__main__":
    main()
