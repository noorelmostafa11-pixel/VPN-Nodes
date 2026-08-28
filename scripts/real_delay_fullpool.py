#!/usr/bin/env python3
"""Run authoritative Xray Real Delay against candidates selected from the
complete TCP-reachable pool, then publish the tested-good nodes first.

The collector writes the full reachable set to metadata/reachable_pool.jsonl
before any per-country publication limit is applied. This script consumes that
staging file, so the 250-node country publication cap cannot hide a good node
from the 3200-node Real Delay selection.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from real_delay_v2 import XRAY, WORKERS, test_one

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
LIMIT = int(os.environ.get("REAL_DELAY_CANDIDATES", "3200"))
MAX_PER_COUNTRY = int(os.environ.get("REAL_DELAY_PUBLISH_PER_COUNTRY", "250"))


def load_reachable_pool():
    path = OUT / "metadata" / "reachable_pool.jsonl"
    if not path.exists():
        raise SystemExit("Missing complete reachable pool: metadata/reachable_pool.jsonl")
    pool = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        uri = str(item.get("uri", "")).strip()
        if not uri:
            continue
        item["country"] = item.get("country") or "UNKNOWN"
        item["protocol"] = item.get("protocol") or uri.split(":", 1)[0].lower()
        pool.setdefault(hashlib.sha256(uri.encode()).hexdigest(), item)
    return list(pool.values())


def choose_candidates(pool):
    total = min(LIMIT, len(pool))
    if not total:
        return []
    by_country = defaultdict(list)
    for item in pool:
        by_country[item["country"]].append(item)
    countries = sorted(by_country)
    quotas = {c: max(1, int(total * len(by_country[c]) / len(pool))) for c in countries}
    while sum(quotas.values()) > total:
        c = max(quotas, key=lambda x: (quotas[x], len(by_country[x])))
        if quotas[c] <= 1:
            break
        quotas[c] -= 1
    while sum(quotas.values()) < total:
        c = max(countries, key=lambda x: len(by_country[x]) - quotas[x])
        if quotas[c] >= len(by_country[c]):
            break
        quotas[c] += 1
    chosen = []
    for country in countries:
        items = by_country[country]
        n = min(quotas[country], len(items))
        if n == len(items):
            chosen.extend(items)
            continue
        idx = sorted({min(len(items) - 1, int(i * len(items) / n)) for i in range(n)})
        if idx and idx[0] != 0:
            idx[0] = 0
        chosen.extend(items[i] for i in idx[:n])
    return chosen[:total]


def publish(pool, results):
    alive = [r for r in results if r.get("alive") and r.get("delay_ms", -1) > 0]
    alive_by_country = defaultdict(list)
    all_by_country = defaultdict(list)
    for item in pool:
        all_by_country[item["country"]].append(item)
    for item in alive:
        alive_by_country[item["country"]].append(item)
    for items in alive_by_country.values():
        items.sort(key=lambda r: (r["delay_ms"], r.get("protocol", ""), r["uri"]))

    countries_dir = OUT / "countries"
    protocols_dir = OUT / "protocols"
    metadata_dir = OUT / "metadata"
    countries_dir.mkdir(parents=True, exist_ok=True)
    protocols_dir.mkdir(parents=True, exist_ok=True)
    metadata_dir.mkdir(parents=True, exist_ok=True)
    for path in countries_dir.glob("*.txt"):
        path.unlink()
    for path in protocols_dir.glob("*.txt"):
        path.unlink()

    final_by_country = {}
    for country, items in sorted(all_by_country.items()):
        promoted = alive_by_country.get(country, [])
        promoted_uris = {x["uri"] for x in promoted}
        fallback = [x for x in items if x["uri"] not in promoted_uris]
        fallback.sort(key=lambda r: (
            r.get("latency_ms") if r.get("latency_ms") is not None else 999999,
            -r.get("source_priority", 0),
            r.get("protocol", ""),
            r.get("uri", ""),
        ))
        final_by_country[country] = (promoted + fallback)[:MAX_PER_COUNTRY]
        (countries_dir / f"{country}.txt").write_text(
            "\n".join(x["uri"] for x in final_by_country[country]) +
            ("\n" if final_by_country[country] else ""),
            encoding="utf-8",
        )

    by_protocol = defaultdict(list)
    for items in final_by_country.values():
        for item in items:
            by_protocol[item.get("protocol", item["uri"].split(":", 1)[0].lower())].append(item)
    for proto, items in sorted(by_protocol.items()):
        (protocols_dir / f"{proto}.txt").write_text(
            "\n".join(x["uri"] for x in items) + ("\n" if items else ""),
            encoding="utf-8",
        )

    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (metadata_dir / "real_delay.json").write_text(json.dumps({
        "schema": 3,
        "generated_at": generated_at,
        "engine": "Xray",
        "target": "https://www.gstatic.com/generate_204",
        "candidate_source": "complete reachable_pool.jsonl",
        "reachable_pool": len(pool),
        "real_delay_candidates": len(results),
        "alive": len(alive),
        "dead": len(results) - len(alive),
        "publish_limit_per_country": MAX_PER_COUNTRY,
        "results": sorted(results, key=lambda r: (
            r["country"],
            0 if r.get("alive") else 1,
            r.get("delay_ms", 10**9) if r.get("delay_ms", -1) > 0 else 10**9,
            r.get("protocol", ""),
            r["uri"],
        )),
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (metadata_dir / "real_delay_summary.json").write_text(json.dumps({
        "generated_at": generated_at,
        "reachable_pool": len(pool),
        "real_delay_candidates": len(results),
        "alive": len(alive),
        "dead": len(results) - len(alive),
        "untested_reachable_retained_as_fallback": len(pool) - len(results),
        "countries_published": len(final_by_country),
        "protocols_published": {p: len(v) for p, v in sorted(by_protocol.items())},
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    if not XRAY.exists():
        raise SystemExit(f"Xray binary not found: {XRAY}")
    pool = load_reachable_pool()
    candidates = choose_candidates(pool)
    print(f"INFO real_delay_pool={len(pool)} selected={len(candidates)} workers={WORKERS} selection_source=full_reachable_pool")
    if not candidates:
        raise SystemExit("No reachable candidates available for Real Delay")
    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = [executor.submit(test_one, item, i) for i, item in enumerate(candidates)]
        for n, future in enumerate(as_completed(futures), 1):
            results.append(future.result())
            if n % 100 == 0 or n == len(candidates):
                print(f"INFO real_delay_progress={n}/{len(candidates)} alive={sum(1 for r in results if r.get('alive'))}")
    publish(pool, results)
    alive = sum(1 for r in results if r.get("alive"))
    print(f"OK real_delay selected={len(results)} alive={alive} dead={len(results)-alive} published_from_full_reachable=true")


if __name__ == "__main__":
    main()
