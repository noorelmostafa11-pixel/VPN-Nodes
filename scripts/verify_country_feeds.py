#!/usr/bin/env python3
"""Fail CI if a generated country feed contains a semantic duplicate."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import node_identity

ROOT = Path(__file__).resolve().parents[1]
COUNTRIES = ROOT / "output" / "countries"


def main() -> int:
    files = sorted(COUNTRIES.glob("*.txt"))
    if not files:
        raise SystemExit("No country feeds were generated")

    total = 0
    duplicates = 0
    examples: list[str] = []

    for path in files:
        seen: dict[str, str] = {}
        per_key: defaultdict[str, int] = defaultdict(int)
        for raw in path.read_text(encoding="utf-8").splitlines():
            uri = raw.strip()
            if not uri:
                continue
            total += 1
            key = node_identity.dedup_key(uri)
            per_key[key] += 1
            if key in seen:
                duplicates += 1
                if len(examples) < 20:
                    examples.append(f"{path.name}: {uri[:180]}")
            else:
                seen[key] = uri

    print(f"INFO country_feed_nodes={total} semantic_duplicates={duplicates} files={len(files)}")
    if duplicates:
        for example in examples:
            print(f"DUPLICATE {example}")
        raise SystemExit(f"Found {duplicates} semantic duplicate node(s) in country feeds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
