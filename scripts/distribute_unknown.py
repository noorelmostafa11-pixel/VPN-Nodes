#!/usr/bin/env python3
"""Distribute unresolved nodes across already-discovered country feeds.

Known country nodes keep their original order and therefore stay first in each
country file. Only nodes that remain UNKNOWN after the normal GeoLite2/DNS
resolution are redistributed. No new country is created.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pycountry

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
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")


def _collect_unknown() -> list[str]:
    nodes: list[str] = []
    seen: set[str] = set()
    for path in sorted(GLOBAL_DIR.glob("server-*.txt")):
        for line in _read_lines(path):
            if line not in seen:
                seen.add(line)
                nodes.append(line)
    return nodes


def _protocol_of(uri: str) -> str | None:
    match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://", uri)
    if not match:
        return None
    return SCHEME_TO_PROTOCOL.get(match.group(1).lower())


def main() -> None:
    unknown = _collect_unknown()
    country_files = {
        path.stem.upper(): path
        for path in COUNTRIES_DIR.glob("*.txt")
        if path.stem.upper() in ISO_CODES and path.is_file()
    }
    countries = sorted(country_files)

    redistributed_by_country = {country: 0 for country in countries}
    if unknown and countries:
        # Round-robin gives every discovered country the same number of
        # redistributed nodes, with at most one node difference.
        for index, uri in enumerate(unknown):
            country = countries[index % len(countries)]
            path = country_files[country]
            existing = _read_lines(path)
            if uri not in set(existing):
                existing.append(uri)
                _write_lines(path, existing)
                redistributed_by_country[country] += 1

        # Keep protocol feeds consistent with the country feeds.
        for uri in unknown:
            protocol = _protocol_of(uri)
            if not protocol:
                continue
            path = PROTOCOLS_DIR / f"{protocol}.txt"
            existing = _read_lines(path)
            if uri not in set(existing):
                existing.append(uri)
                _write_lines(path, existing)

        # The unknown pool has been consumed; remove its old global shards.
        for path in GLOBAL_DIR.glob("server-*.txt"):
            path.unlink()

    redistributed_total = sum(redistributed_by_country.values())
    remaining_unknown = len(unknown) - redistributed_total

    # Refresh metadata counts without changing discovery provenance.
    index_path = META_DIR / "index.json"
    health_path = META_DIR / "health.json"
    countries_path = META_DIR / "countries.json"

    for path in (index_path, health_path):
        if not path.is_file():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        if "published_by_country" in data:
            for country, added in redistributed_by_country.items():
                if added:
                    data["published_by_country"][country] = data["published_by_country"].get(country, 0) + added
        if "reachable_by_country" in data:
            for country, added in redistributed_by_country.items():
                if added:
                    data["reachable_by_country"][country] = data["reachable_by_country"].get(country, 0) + added
        data["redistribution"] = {
            "source": "UNKNOWN/global",
            "eligible_unknown": len(unknown),
            "redistributed_total": redistributed_total,
            "remaining_unknown": remaining_unknown,
            "countries_used": countries,
            "by_country": redistributed_by_country,
            "strategy": "round_robin_equal_append_after_discovered_nodes",
            "new_countries_created": [],
        }
        data["global_unknown"] = {
            "total": remaining_unknown,
            "server_size": 500,
            "servers": (remaining_unknown + 499) // 500,
            "files": "global/server-N.txt",
        }
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if countries_path.is_file():
        data = json.loads(countries_path.read_text(encoding="utf-8"))
        for item in data.get("countries", []):
            country = item.get("code")
            if country in redistributed_by_country:
                added = redistributed_by_country[country]
                if added:
                    item["nodes"] = int(item.get("nodes", 0)) + added
                    item["reachable"] = int(item.get("reachable", 0)) + added
        data["redistribution"] = {
            "redistributed_total": redistributed_total,
            "remaining_unknown": remaining_unknown,
            "by_country": redistributed_by_country,
            "new_countries_created": [],
        }
        countries_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(
        f"INFO unknown_redistribution eligible={len(unknown)} "
        f"redistributed={redistributed_total} remaining={remaining_unknown} "
        f"countries={len(countries)}"
    )
    print("INFO unknown_redistribution_by_country=" + json.dumps(redistributed_by_country, sort_keys=True))


if __name__ == "__main__":
    main()
