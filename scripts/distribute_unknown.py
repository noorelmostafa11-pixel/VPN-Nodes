#!/usr/bin/env python3
"""Preserve confirmed nodes and evenly distribute unresolved nodes.

Country files remain two-tier feeds: confirmed nodes first, redistributed unknown
nodes second. Redistribution targets are the explicit country anchors recorded by
this run, not every ISO file produced by GeoIP.
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
ANCHORS_FILE = META_DIR / "confirmed_country_anchors.json"

ISO_CODES = {c.alpha_2.upper() for c in pycountry.countries}
SCHEME_TO_PROTOCOL = {"vless": "vless", "vmess": "vmess", "trojan": "trojan", "ss": "shadowsocks"}


def _read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")


def _protocol_of(uri: str) -> str | None:
    match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://", uri)
    return SCHEME_TO_PROTOCOL.get(match.group(1).lower()) if match else None


def _explicit_metadata(uri: str) -> str | None:
    try:
        return country_resolver.extract_country_from_text(unquote(urlparse(uri).fragment or ""))
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
        ip = country_resolver.resolve_ip(host)
    except Exception:
        ip = None
    return cloudflare_detector.is_confirmed_cloudflare(host, ip)


def _collect_global_unknown() -> list[str]:
    nodes: list[str] = []
    seen: set[str] = set()
    for path in sorted(GLOBAL_DIR.glob("server-*.txt")):
        for uri in _read_lines(path):
            if uri not in seen:
                seen.add(uri)
                nodes.append(uri)
    return nodes


def _quarantine_confirmed_cloudflare() -> tuple[list[str], int]:
    unknown: list[str] = []
    seen: set[str] = set()
    quarantined = 0
    for path in sorted(COUNTRIES_DIR.glob("*.txt")):
        code = path.stem.upper()
        if code not in ISO_CODES:
            continue
        kept: list[str] = []
        for uri in _read_lines(path):
            # Explicit node metadata always protects the node from CF quarantine.
            if _explicit_metadata(uri):
                kept.append(uri)
                continue
            if _is_confirmed_cloudflare(uri):
                quarantined += 1
                if uri not in seen:
                    seen.add(uri)
                    unknown.append(uri)
            else:
                kept.append(uri)
        _write_lines(path, kept)
    return unknown, quarantined


def _load_anchor_countries() -> dict[str, Path]:
    """Load only countries that had >=1 reachable explicit-metadata anchor this run."""
    if not ANCHORS_FILE.is_file():
        raise RuntimeError("Missing confirmed country anchors produced by build_tcp_pool")
    data = json.loads(ANCHORS_FILE.read_text(encoding="utf-8"))
    codes = data.get("countries", [])
    if not isinstance(codes, list):
        raise RuntimeError("Invalid confirmed_country_anchors.json")

    anchors: dict[str, Path] = {}
    for raw in codes:
        code = str(raw).upper()
        if code not in ISO_CODES or code == "UNKNOWN":
            continue
        path = COUNTRIES_DIR / f"{code}.txt"
        # Anchor must still contain at least one confirmed node after CF quarantine.
        if _read_lines(path):
            anchors[code] = path
    return anchors


def _redistribute_equal(unknown: list[str], country_files: dict[str, Path]) -> dict[str, int]:
    """Split the complete unresolved pool equally across explicit country anchors."""
    countries = sorted(country_files)
    added = {code: 0 for code in countries}
    if not unknown or not countries:
        return added

    base, remainder = divmod(len(unknown), len(countries))
    cursor = 0
    for index, code in enumerate(countries):
        take = base + (1 if index < remainder else 0)
        if take <= 0:
            continue
        path = country_files[code]
        existing = _read_lines(path)
        existing_set = set(existing)
        batch = unknown[cursor:cursor + take]
        fresh = [uri for uri in batch if uri not in existing_set]
        if fresh:
            # Existing confirmed nodes stay first; redistributed nodes are appended.
            existing.extend(fresh)
            _write_lines(path, existing)
            added[code] = len(fresh)
        cursor += take
    return added


def _refresh_protocols(nodes: list[str]) -> None:
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


def _country_name(code: str) -> str:
    country = pycountry.countries.get(alpha_2=code)
    return country.name if country else code


def _actual_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in sorted(COUNTRIES_DIR.glob("*.txt")):
        code = path.stem.upper()
        if code in ISO_CODES:
            lines = _read_lines(path)
            if lines:
                counts[code] = len(lines)
            elif path.exists():
                path.unlink()
    return counts


def _rebuild_metadata(
    added_by_country: dict[str, int],
    eligible_unknown: int,
    quarantined: int,
    remaining_unknown: int,
    anchor_countries: list[str],
) -> None:
    counts = _actual_counts()
    countries = sorted(counts)
    total = sum(counts.values())

    redistribution = {
        "source": "UNKNOWN/global + confirmed_cloudflare_without_metadata",
        "eligible_unknown": eligible_unknown,
        "cloudflare_quarantined": quarantined,
        "redistributed_total": sum(added_by_country.values()),
        "remaining_unknown": remaining_unknown,
        "countries_used": anchor_countries,
        "by_country": {code: added_by_country.get(code, 0) for code in anchor_countries},
        "strategy": "equal_quotient_remainder_append_after_confirmed_nodes",
        "new_countries_created": [],
        "confirmed_kept_first": True,
    }

    for path in (META_DIR / "index.json", META_DIR / "health.json"):
        if not path.is_file():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        data["reachable_by_country"] = dict(counts)
        data["published_by_country"] = dict(counts)
        data["countries"] = len(countries)
        data["country_names"] = {code: _country_name(code) for code in countries}
        data["global_unknown"] = {
            "total": remaining_unknown,
            "server_size": 500,
            "servers": (remaining_unknown + 499) // 500,
            "files": "global/server-N.txt",
        }
        data["redistribution"] = redistribution
        data["published_total"] = total
        data["reachable_total"] = total
        data["reachable_published"] = total
        data["publication_rejected_total"] = 0
        data["publication_rejection_reasons"] = {"country_cap": 0}
        data["confirmed_country_anchors"] = {
            "countries": anchor_countries,
            "count": len(anchor_countries),
        }
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    countries_path = META_DIR / "countries.json"
    if countries_path.is_file():
        old = json.loads(countries_path.read_text(encoding="utf-8"))
        old_items = {item.get("code"): item for item in old.get("countries", [])}
        rebuilt = []
        for code in countries:
            old_item = old_items.get(code, {})
            rebuilt.append({
                "code": code,
                "name": _country_name(code),
                "nodes": counts[code],
                "reachable": counts[code],
                "cap_rejected": int(old_item.get("cap_rejected", 0)),
            })
        old["countries"] = rebuilt
        old["redistribution"] = redistribution
        old["confirmed_country_anchors"] = {"countries": anchor_countries, "count": len(anchor_countries)}
        countries_path.write_text(json.dumps(old, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"INFO catalog_reconciled countries={len(countries)} nodes={total} empty_files_removed=true")
    print("INFO catalog_reconciled_counts=" + json.dumps(counts, sort_keys=True))


def main() -> None:
    # The generated global pool is the unresolved pool from the current build.
    unknown = _collect_global_unknown()
    seen = set(unknown)

    quarantined_unknown, quarantined = _quarantine_confirmed_cloudflare()
    for uri in quarantined_unknown:
        if uri not in seen:
            seen.add(uri)
            unknown.append(uri)

    country_files = _load_anchor_countries()
    anchor_countries = sorted(country_files)
    added_by_country = _redistribute_equal(unknown, country_files)
    redistributed_total = sum(added_by_country.values())
    remaining_unknown = len(unknown) - redistributed_total

    _refresh_protocols(unknown)
    if remaining_unknown == 0:
        _delete_global_shards()

    _rebuild_metadata(
        added_by_country,
        len(unknown),
        quarantined,
        remaining_unknown,
        anchor_countries,
    )

    print(
        f"INFO unknown_distribution_rule total={len(unknown)} countries={len(anchor_countries)} "
        f"base={len(unknown) // len(anchor_countries) if anchor_countries else 0} "
        f"remainder={len(unknown) % len(anchor_countries) if anchor_countries else 0} "
        f"redistributed={redistributed_total} confirmed_kept_first=true explicit_anchor_only=true"
    )
    print("INFO unknown_distribution_by_country=" + json.dumps(added_by_country, sort_keys=True))


if __name__ == "__main__":
    main()
