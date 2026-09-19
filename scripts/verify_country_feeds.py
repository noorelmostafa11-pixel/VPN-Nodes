#!/usr/bin/env python3
"""Fail CI if full feeds or their on-demand shards are inconsistent."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import node_identity

ROOT = Path(__file__).resolve().parents[1]
COUNTRIES = ROOT / "output" / "countries"
COUNTRY_SHARDS = ROOT / "output" / "country_shards"
COUNTRIES_META = ROOT / "output" / "metadata" / "countries.json"


def read_lines(path: Path) -> list[str]:
    return [
        raw.strip()
        for raw in path.read_text(encoding="utf-8").splitlines()
        if raw.strip()
    ]


def main() -> int:
    files = sorted(COUNTRIES.glob("*.txt"))
    if not files:
        raise SystemExit("No country feeds were generated")
    if not COUNTRIES_META.is_file():
        raise SystemExit("countries.json was not generated")

    metadata = json.loads(COUNTRIES_META.read_text(encoding="utf-8"))
    shard_size = int(metadata.get("shard_size") or 0)
    if shard_size < 100 or shard_size > 5000:
        raise SystemExit(f"Invalid country shard size: {shard_size}")
    by_country = {
        str(item.get("code") or "").upper(): item
        for item in metadata.get("countries", [])
    }

    total = 0
    duplicates = 0
    total_shards = 0
    examples: list[str] = []

    for path in files:
        country = path.stem.upper()
        lines = read_lines(path)
        seen: dict[str, str] = {}
        per_key: defaultdict[str, int] = defaultdict(int)
        for uri in lines:
            total += 1
            key = node_identity.dedup_key(uri)
            per_key[key] += 1
            if key in seen:
                duplicates += 1
                if len(examples) < 20:
                    examples.append(f"{path.name}: {uri[:180]}")
            else:
                seen[key] = uri

        shards = sorted((COUNTRY_SHARDS / country).glob("*.txt"))
        if not shards:
            raise SystemExit(f"No country shards were generated for {country}")
        rebuilt: list[str] = []
        for shard in shards:
            shard_lines = read_lines(shard)
            if not shard_lines or len(shard_lines) > shard_size:
                raise SystemExit(
                    f"Invalid shard size for {shard.relative_to(ROOT)}: {len(shard_lines)}"
                )
            rebuilt.extend(shard_lines)
        if rebuilt != lines:
            raise SystemExit(f"Shard reassembly mismatch for {country}")

        expected = by_country.get(country) or {}
        if int(expected.get("nodes") or -1) != len(lines):
            raise SystemExit(f"Country metadata node mismatch for {country}")
        if int(expected.get("shards") or -1) != len(shards):
            raise SystemExit(f"Country metadata shard mismatch for {country}")
        if int(expected.get("shard_size") or -1) != shard_size:
            raise SystemExit(f"Country metadata shard size mismatch for {country}")
        total_shards += len(shards)

    print(
        f"INFO country_feed_nodes={total} semantic_duplicates={duplicates} "
        f"files={len(files)} shards={total_shards} shard_size={shard_size}"
    )
    if duplicates:
        for example in examples:
            print(f"DUPLICATE {example}")
        raise SystemExit(f"Found {duplicates} semantic duplicate node(s) in country feeds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
