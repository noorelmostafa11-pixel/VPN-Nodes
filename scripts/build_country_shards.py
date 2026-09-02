#!/usr/bin/env python3
"""Split each published country feed into small independently signed app shards.

The monolithic output/countries/<CC>.txt files remain untouched for backwards
compatibility. Android can read the signed manifest, download only one shard for
the selected country, and fetch later shards only when the current one is exhausted.
"""
from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path

import pycountry

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
COUNTRIES = OUT / "countries"
SHARDS = OUT / "country_shards"
META = OUT / "metadata"
COUNTRIES_JSON = META / "countries.json"
APP_POOL = META / "app_pool.json"
SHARD_SIZE = int(os.environ.get("COUNTRY_SHARD_SIZE", "25"))


def _previous_names() -> dict[str, str]:
    if not COUNTRIES_JSON.is_file():
        return {}
    try:
        payload = json.loads(COUNTRIES_JSON.read_text(encoding="utf-8"))
    except Exception:
        return {}
    names: dict[str, str] = {}
    for item in payload.get("countries", []):
        code = str(item.get("code") or "").strip().upper()
        name = str(item.get("name") or "").strip()
        if len(code) == 2 and name:
            names[code] = name
    return names


def _country_name(code: str, previous: dict[str, str]) -> str:
    if code in previous:
        return previous[code]
    match = pycountry.countries.get(alpha_2=code)
    return str(match.name) if match is not None else code


def _read_lines(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> int:
    if SHARD_SIZE < 5 or SHARD_SIZE > 100:
        raise SystemExit(f"COUNTRY_SHARD_SIZE must be between 5 and 100, got {SHARD_SIZE}")
    feeds = sorted(COUNTRIES.glob("*.txt"))
    if not feeds:
        raise SystemExit("No output/countries/*.txt feeds exist")

    previous = _previous_names()
    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if APP_POOL.is_file():
        try:
            generated_at = str(json.loads(APP_POOL.read_text(encoding="utf-8")).get("generated_at") or generated_at)
        except Exception:
            pass

    if SHARDS.exists():
        shutil.rmtree(SHARDS)
    SHARDS.mkdir(parents=True, exist_ok=True)
    META.mkdir(parents=True, exist_ok=True)

    metadata: list[dict] = []
    total_nodes = 0
    total_shards = 0

    for feed in feeds:
        code = feed.stem.strip().upper()
        if len(code) != 2 or not code.isalpha():
            raise SystemExit(f"Invalid country feed filename: {feed.name}")
        lines = _read_lines(feed)
        if not lines:
            continue

        country_dir = SHARDS / code
        country_dir.mkdir(parents=True, exist_ok=True)
        shard_paths: list[Path] = []
        for index, start in enumerate(range(0, len(lines), SHARD_SIZE)):
            chunk = lines[start:start + SHARD_SIZE]
            shard = country_dir / f"{index:03d}.txt"
            shard.write_text("\n".join(chunk) + "\n", encoding="utf-8")
            shard_paths.append(shard)

        # Publication guard: byte-normalized line order must reassemble exactly.
        rebuilt: list[str] = []
        for shard in shard_paths:
            rebuilt.extend(_read_lines(shard))
        if rebuilt != lines:
            raise SystemExit(f"Shard reassembly mismatch for {code}")
        if any(len(_read_lines(path)) > SHARD_SIZE for path in shard_paths):
            raise SystemExit(f"Oversized shard generated for {code}")

        shard_count = len(shard_paths)
        metadata.append({
            "code": code,
            "name": _country_name(code, previous),
            "nodes": len(lines),
            "active": 0,
            "backup": len(lines),
            "shards": shard_count,
            "shard_size": SHARD_SIZE,
            "shard_path": f"output/country_shards/{code}",
        })
        total_nodes += len(lines)
        total_shards += shard_count

    payload = {
        "schema": 2,
        "generated_at": generated_at,
        "shard_size": SHARD_SIZE,
        "countries": metadata,
    }
    COUNTRIES_JSON.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(
        f"OK country_shards countries={len(metadata)} nodes={total_nodes} "
        f"shards={total_shards} shard_size={SHARD_SIZE}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
