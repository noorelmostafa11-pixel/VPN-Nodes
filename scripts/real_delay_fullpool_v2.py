#!/usr/bin/env python3
"""Run Xray Real Delay against 3200 candidates from the complete TCP-reachable output.

Preferred input: metadata/reachable_pool.jsonl produced by update_catalog.py.
Fallback: protocol outputs, which contain the full reachable protocol pool in the
current catalog. Country files are used to recover authoritative country labels
for already-published nodes; otherwise the node remark is classified to a country.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import unquote, urlparse

from real_delay_v2 import XRAY, WORKERS, test

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
LIMIT = int(os.environ.get("REAL_DELAY_CANDIDATES", "3200"))
MAX_PER_COUNTRY = int(os.environ.get("REAL_DELAY_PUBLISH_PER_COUNTRY", "250"))

ALIASES = {
    "uk": "GB", "england": "GB", "greatbritain": "GB", "unitedkingdom": "GB",
    "uae": "AE", "emirates": "AE", "unitedarabemirates": "AE", "usa": "US",
    "america": "US", "unitedstates": "US", "southkorea": "KR", "korea": "KR",
    "russia": "RU", "iran": "IR", "taiwan": "TW", "japan": "JP",
    "singapore": "SG", "seychelles": "SC", "slovenia": "SI", "germany": "DE",
    "france": "FR", "canada": "CA", "australia": "AU", "austria": "AT",
    "netherlands": "NL", "poland": "PL", "turkey": "TR", "turkiye": "TR",
    "hongkong": "HK", "finland": "FI", "sweden": "SE", "denmark": "DK",
    "bulgaria": "BG", "azerbaijan": "AZ", "china": "CN", "estonia": "EE",
    "czechrepublic": "CZ", "czechia": "CZ", "southafrica": "ZA",
    "newzealand": "NZ", "saudiarabia": "SA",
}


def proto(uri: str) -> str:
    s = uri.split(":", 1)[0].lower()
    return "shadowsocks" if s == "ss" else s


def country_from_uri(uri: str) -> str:
    frag = unquote(urlparse(uri).fragment or "")
    compact = re.sub(r"[^a-z0-9]+", "", frag.lower())
    for token, code in ALIASES.items():
        if token in compact:
            return code
    for code in re.findall(r"(?<![A-Za-z0-9])([A-Z]{2})(?![A-Za-z0-9])", frag):
        if code.upper() not in {"WS", "SS", "TLS"}:
            return code.upper()
    return "UNKNOWN"


def key(uri: str) -> str:
    return hashlib.sha256(uri.encode()).hexdigest()


def load_pool():
    staging = OUT / "metadata" / "reachable_pool.jsonl"
    rows = {}
    source = None
    if staging.exists():
        source = "metadata/reachable_pool.jsonl"
        for line in staging.read_text(encoding="utf-8", errors="replace").splitlines():
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
            item["protocol"] = item.get("protocol") or proto(uri)
            rows.setdefault(key(uri), item)
    else:
        source = "output/protocols/*.txt"
        # Protocol feeds are the complete reachable protocol indexes in the
        # existing catalog; unlike countries/*.txt they are not country-capped.
        for path in sorted((OUT / "protocols").glob("*.txt")):
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                uri = line.strip()
                if not re.match(r"^(vless|vmess|trojan|ss)://", uri, re.I):
                    continue
                rows.setdefault(key(uri), {
                    "uri": uri,
                    "country": country_from_uri(uri),
                    "protocol": proto(uri),
                })
    return list(rows.values()), source


def choose_candidates(pool):
    total = min(LIMIT, len(pool))
    if not total:
        return []
    by_country = defaultdict(list)
    for item in pool:
        by_country[item.get("country") or "UNKNOWN"].append(item)
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
        chosen.extend(items[i] for i in idx[:n])
    return chosen[:total]


def publish(pool, results):
    alive = [r for r in results if r.get("alive") and r.get("delay_ms", -1) > 0]
    alive_by_country = defaultdict(list)
    all_by_country = defaultdict(list)
    for item in pool:
        all_by_country[item.get("country") or "UNKNOWN"].append(item)
    for item in alive:
        alive_by_country[item.get("country") or "UNKNOWN"].append(item)
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

    final = {}
    for country, items in sorted(all_by_country.items()):
        promoted = alive_by_country.get(country, [])
        promoted_uris = {x["uri"] for x in promoted}
        fallback = [x for x in items if x["uri"] not in promoted_uris]
        fallback.sort(key=lambda r: (
            r.get("latency_ms") if r.get("latency_ms") is not None else 999999,
            -r.get("source_priority", 0), r.get("protocol", ""), r.get("uri", "")))
        final[country] = (promoted + fallback)[:MAX_PER_COUNTRY]
        (countries_dir / f"{country}.txt").write_text(
            "\n".join(x["uri"] for x in final[country]) + ("\n" if final[country] else ""),
            encoding="utf-8")

    by_protocol = defaultdict(list)
    for items in final.values():
        for item in items:
            by_protocol[item.get("protocol") or proto(item["uri"])].append(item)
    for name, items in sorted(by_protocol.items()):
        (protocols_dir / f"{name}.txt").write_text(
            "\n".join(x["uri"] for x in items) + ("\n" if items else ""),
            encoding="utf-8")

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (metadata_dir / "real_delay.json").write_text(json.dumps({
        "schema": 4, "generated_at": now, "engine": "Xray",
        "target": "https://www.gstatic.com/generate_204",
        "candidate_source": "complete reachable pool",
        "reachable_pool": len(pool), "real_delay_candidates": len(results),
        "alive": len(alive), "dead": len(results) - len(alive),
        "publish_limit_per_country": MAX_PER_COUNTRY,
        "results": sorted(results, key=lambda r: (
            r.get("country", "UNKNOWN"), 0 if r.get("alive") else 1,
            r.get("delay_ms") if r.get("delay_ms", -1) > 0 else 10**9,
            r.get("protocol", ""), r["uri"])),
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (metadata_dir / "real_delay_summary.json").write_text(json.dumps({
        "generated_at": now, "reachable_pool": len(pool),
        "real_delay_candidates": len(results), "alive": len(alive),
        "dead": len(results) - len(alive),
        "untested_reachable_retained_as_fallback": len(pool) - len(results),
        "countries_published": len(final),
        "protocols_published": {p: len(v) for p, v in sorted(by_protocol.items())},
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    if not XRAY.exists():
        raise SystemExit(f"Xray binary not found: {XRAY}")
    pool, source = load_pool()
    candidates = choose_candidates(pool)
    print(f"INFO real_delay_pool={len(pool)} selected={len(candidates)} workers={WORKERS} selection_source={source}")
    if not candidates:
        raise SystemExit("No reachable candidates available for Real Delay")
    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = [executor.submit(test, item, i) for i, item in enumerate(candidates)]
        for n, future in enumerate(as_completed(futures), 1):
            results.append(future.result())
            if n % 100 == 0 or n == len(candidates):
                print(f"INFO real_delay_progress={n}/{len(candidates)} alive={sum(1 for r in results if r.get('alive'))}")
    publish(pool, results)
    alive = sum(1 for r in results if r.get("alive"))
    print(f"OK real_delay selected={len(results)} alive={alive} dead={len(results)-alive} published_from_full_reachable=true")


if __name__ == "__main__":
    main()
