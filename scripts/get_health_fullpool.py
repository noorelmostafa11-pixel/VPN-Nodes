#!/usr/bin/env python3
"""Lightweight Xray GET health check.

Keeps the existing full reachable-pool selection and protocol handling, but
replaces the Real Delay ranking stage with a simple HTTP GET through Xray.
Success means the configured node can establish the Xray tunnel and receive an
HTTP response from the fixed test endpoint. Failure is recorded as -1.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from real_delay_v2 import XRAY, WORKERS, test

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
LIMIT = int(os.environ.get("GET_HEALTH_CANDIDATES", "3200"))
MAX_PER_COUNTRY = int(os.environ.get("GET_HEALTH_PUBLISH_PER_COUNTRY", "250"))


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
    if not pool:
        raise SystemExit("Complete reachable pool is empty: metadata/reachable_pool.jsonl")
    return list(pool.values())


def choose_candidates(pool):
    total = min(LIMIT, len(pool))
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
        idxs = sorted({min(len(items) - 1, int(i * len(items) / n)) for i in range(n)})
        chosen.extend(items[i] for i in idxs[:n])
    return chosen[:total]


def publish(pool, results):
    alive = [r for r in results if r.get("alive")]
    alive_by_country = defaultdict(list)
    all_by_country = defaultdict(list)
    for item in pool:
        all_by_country[item["country"]].append(item)
    for item in alive:
        alive_by_country[item["country"]].append(item)
    for items in alive_by_country.values():
        # Preserve the existing catalog ordering after the GET health pass.
        items.sort(key=lambda r: (
            -(r.get("source_priority", 0)),
            r.get("latency_ms") if r.get("latency_ms") is not None else 999999,
            r.get("protocol", ""),
            r.get("uri", ""),
        ))

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

    final = {}
    for country, items in sorted(all_by_country.items()):
        passed = alive_by_country.get(country, [])
        passed_uris = {x["uri"] for x in passed}
        fallback = [x for x in items if x["uri"] not in passed_uris]
        fallback.sort(key=lambda r: (
            -(r.get("source_priority", 0)),
            r.get("latency_ms") if r.get("latency_ms") is not None else 999999,
            r.get("protocol", ""),
            r.get("uri", ""),
        ))
        final[country] = (passed + fallback)[:MAX_PER_COUNTRY]
        (countries_dir / f"{country}.txt").write_text(
            "\n".join(x["uri"] for x in final[country]) + ("\n" if final[country] else ""),
            encoding="utf-8",
        )

    by_protocol = defaultdict(list)
    for items in final.values():
        for item in items:
            by_protocol[item.get("protocol") or item["uri"].split(":", 1)[0].lower()].append(item)
    for name, items in sorted(by_protocol.items()):
        (protocols_dir / f"{name}.txt").write_text(
            "\n".join(x["uri"] for x in items) + ("\n" if items else ""),
            encoding="utf-8",
        )

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload = {
        "schema": 1,
        "generated_at": now,
        "engine": "Xray",
        "test": "GET https://www.gstatic.com/generate_204 through Xray SOCKS tunnel",
        "candidate_source": "metadata/reachable_pool.jsonl",
        "reachable_pool": len(pool),
        "get_candidates": len(results),
        "alive": len(alive),
        "dead": len(results) - len(alive),
        "publish_limit_per_country": MAX_PER_COUNTRY,
        "results": results,
    }
    (metadata_dir / "get_health.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (metadata_dir / "get_health_summary.json").write_text(json.dumps({
        "generated_at": now,
        "reachable_pool": len(pool),
        "get_candidates": len(results),
        "alive": len(alive),
        "dead": len(results) - len(alive),
        "untested_reachable_retained_as_fallback": len(pool) - len(results),
        "countries_published": len(final),
        "protocols_published": {p: len(v) for p, v in sorted(by_protocol.items())},
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    if not XRAY.exists():
        raise SystemExit(f"Xray binary not found: {XRAY}")
    pool = load_reachable_pool()
    candidates = choose_candidates(pool)
    print(f"INFO get_health_pool={len(pool)} selected={len(candidates)} workers={WORKERS} selection_source=metadata/reachable_pool.jsonl")
    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = [executor.submit(test, item, i) for i, item in enumerate(candidates)]
        for n, future in enumerate(as_completed(futures), 1):
            result = future.result()
            # The existing Xray GET worker already proves tunnel + HTTP GET;
            # the exact latency is not used for ranking in this stage.
            if not result.get("alive"):
                result["delay_ms"] = -1
            results.append(result)
            if n % 100 == 0 or n == len(candidates):
                print(f"INFO get_health_progress={n}/{len(candidates)} alive={sum(1 for r in results if r.get('alive'))}")
    publish(pool, results)
    alive = sum(1 for r in results if r.get("alive"))
    print(f"OK get_health selected={len(results)} alive={alive} dead={len(results)-alive} published_from_full_reachable=true")


if __name__ == "__main__":
    main()
