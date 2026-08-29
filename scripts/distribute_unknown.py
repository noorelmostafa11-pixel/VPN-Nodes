#!/usr/bin/env python3
"""Preserve confirmed nodes and evenly distribute unresolved nodes.

Each country feed has two tiers: confirmed nodes first, redistributed unresolved
nodes second. Empty country files are never distribution targets, and metadata is
rebuilt from the final files so counters cannot drift from actual content.
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


def _nonempty_country_files() -> dict[str, Path]:
    files: dict[str, Path] = {}
    for path in sorted(COUNTRIES_DIR.glob("*.txt")):
        code = path.stem.upper()
        if code in ISO_CODES and _read_lines(path):
            files[code] = path
    return files


def _redistribute_equal(unknown: list[str], country_files: dict[str, Path]) -> dict[str, int]:
    countries = sorted(country_files)
    added = {code: 0 for code in countries}
    if not unknown or not countries:
        return added
    base, remainder = divmod(len(unknown), len(countries))
    cursor = 0
    for index, code in enumerate(countries):
        take = base + (1 if index < remainder else 0)
        batch = unknown[cursor:cursor + take]
        if batch:
            path = country_files[code]
            existing = _read_lines(path)
            existing_set = set(existing)
            fresh = [uri for uri in batch if uri not in existing_set]
            if fresh:
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


def _rebuild_metadata(added_by_country: dict[str, int], eligible_unknown: int, quarantined: int, remaining_unknown: int) -> None:
    counts = _actual_counts()
    countries = sorted(counts)
    total = sum(counts.values())

    redistribution = {
        "source": "UNKNOWN/global + confirmed_cloudflare_without_metadata",
        "eligible_unknown": eligible_unknown,
        "cloudflare_quarantined": quarantined,
        "redistributed_total": sum(added_by_country.values()),
        "remaining_unknown": remaining_unknown,
        "countries_used": countries,
        "by_country": {code: added_by_country.get(code, 0) for code in countries},
        "strategy": "equal_quotient_remainder_append_after_confirmed_nodes",
        "new_countries_created": [],
        "confirmed_kept_first": True,
    }

    index_path = META_DIR / "index.json"
    health_path = META_DIR / "health.json"
    for path in (index_path, health_path):
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
        countries_path.write_text(json.dumps(old, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if sum(_actual_counts().values()) != total:
        raise RuntimeError("catalog metadata reconciliation failed")
    print(f"INFO catalog_reconciled countries={len(countries)} nodes={total} empty_files_removed=true")
    print("INFO catalog_reconciled_counts=" + json.dumps(counts, sort_keys=True))


def main() -> None:
    unknown = _collect_global_unknown()
    seen = set(unknown)
    quarantined_unknown, quarantined = _quarantine_confirmed_cloudflare()
    for uri in quarantined_unknown:
        if uri not in seen:
            seen.add(uri)
            unknown.append(uri)

    country_files = _nonempty_country_files()
    added_by_country = _redistribute_equal(unknown, country_files)
    redistributed_total = sum(added_by_country.values())
    remaining_unknown = len(unknown) - redistributed_total
    _refresh_protocols(unknown)
    if remaining_unknown == 0:
        _delete_global_shards()

    _rebuild_metadata(added_by_country, len(unknown), quarantined, remaining_unknown)
    print(
        f"INFO unknown_distribution_rule total={len(unknown)} countries={len(country_files)} "
        f"base={len(unknown) // len(country_files) if country_files else 0} "
        f"remainder={len(unknown) % len(country_files) if country_files else 0} "
        f"redistributed={redistributed_total} confirmed_kept_first=true"
    )


if __name__ == "__main__":
    main()
