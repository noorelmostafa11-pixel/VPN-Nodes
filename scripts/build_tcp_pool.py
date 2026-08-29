#!/usr/bin/env python3
"""Build the TCP-reachable node catalog without protocol/Xray health checks."""
from __future__ import annotations

import asyncio
import json
import time
from collections import defaultdict
from pathlib import Path

import pycountry

import update_catalog as catalog
import country_resolver

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
SOURCES = ROOT / "sources" / "sources.json"
GEOIP_DB = ROOT / "data" / "GeoLite2-Country.mmdb"
TCP_TIMEOUT = float(catalog.CONNECT_TIMEOUT)
TCP_WORKERS = 512
MAX_PER_COUNTRY = 10**9
GLOBAL_SERVER_SIZE = 500


def iso_name(code: str) -> str:
    if code == "UNKNOWN":
        return "Unknown"
    country = pycountry.countries.get(alpha_2=code)
    return country.name if country else code


async def tcp_probe(item: dict, semaphore: asyncio.Semaphore) -> tuple[dict, float | None]:
    started = time.perf_counter()
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(item["host"], item["port"]), timeout=TCP_TIMEOUT
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return item, round((time.perf_counter() - started) * 1000, 1)
        except Exception:
            return item, None


async def run_tcp_checks(rows: list[dict]) -> list[dict]:
    semaphore = asyncio.Semaphore(TCP_WORKERS)
    results: list[dict] = []
    total = len(rows)
    completed = 0

    async def one(item: dict):
        nonlocal completed
        row, latency = await tcp_probe(item, semaphore)
        completed += 1
        if latency is not None:
            row["latency_ms"] = latency
            results.append(row)
        if completed % 1000 == 0 or completed == total:
            print(f"INFO tcp_progress={completed}/{total} reachable={len(results)}")

    await asyncio.gather(*(one(item) for item in rows))
    return results


def rank(row: dict):
    return (
        row.get("latency_ms", 10**9),
        -row.get("source_priority", 0),
        row.get("protocol", ""),
        row.get("host", ""),
        row.get("uri", ""),
    )


def write_catalog(checked: list[dict], all_rows: list[dict], source_health: list[dict], resolution: dict):
    by_country: dict[str, list[dict]] = defaultdict(list)
    for row in checked:
        by_country[row["country"]].append(row)
    for items in by_country.values():
        items.sort(key=rank)

    reachable_by_country = {c: len(v) for c, v in sorted(by_country.items())}
    published_by_country = {c: v[:MAX_PER_COUNTRY] for c, v in sorted(by_country.items())}
    rejected = {c: max(0, len(by_country[c]) - len(published_by_country[c])) for c in sorted(by_country)}
    rejected_total = sum(rejected.values())
    unknown_items = list(published_by_country.get("UNKNOWN", []))
    global_servers = [unknown_items[i:i + GLOBAL_SERVER_SIZE] for i in range(0, len(unknown_items), GLOBAL_SERVER_SIZE)]

    published_protocols: dict[str, list[dict]] = defaultdict(list)
    for items in published_by_country.values():
        for item in items:
            published_protocols[item["protocol"]].append(item)
    for items in published_protocols.values():
        items.sort(key=rank)

    print(
        f"INFO publication reachable={len(checked)} published={sum(map(len, published_by_country.values()))} "
        f"country_cap_rejected={rejected_total} max_per_country={MAX_PER_COUNTRY}"
    )
    print(f"INFO global_unknown={len(unknown_items)} global_servers={len(global_servers)} server_size={GLOBAL_SERVER_SIZE}")

    for directory in (OUT / "countries", OUT / "protocols", OUT / "global", OUT / "metadata"):
        directory.mkdir(parents=True, exist_ok=True)
    for path in (OUT / "countries").glob("*.txt"):
        path.unlink()
    for path in (OUT / "protocols").glob("*.txt"):
        path.unlink()
    for path in (OUT / "global").glob("server-*.txt"):
        path.unlink()

    for country, items in published_by_country.items():
        text = "\n".join(item["uri"] for item in items)
        if text:
            text += "\n"
        (OUT / "countries" / f"{country}.txt").write_text(text, encoding="utf-8")

    for protocol, items in published_protocols.items():
        (OUT / "protocols" / f"{protocol}.txt").write_text(
            "\n".join(item["uri"] for item in items) + "\n", encoding="utf-8"
        )

    for number, items in enumerate(global_servers, 1):
        (OUT / "global" / f"server-{number}.txt").write_text(
            "\n".join(item["uri"] for item in items) + "\n", encoding="utf-8"
        )

    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    resolver_stats = {
        "dns_resolved": resolution.get("hostname", 0),
        "geolite2_local": resolution.get("geoip_local", 0),
        "unknown": sum(1 for r in checked if r.get("country") == "UNKNOWN"),
        "database_loaded": bool(resolution.get("database_loaded")),
        "database": resolution.get("database", str(GEOIP_DB)),
    }
    index = {
        "schema": 6,
        "generated_at": generated_at,
        "total_fetched": len(all_rows),
        "unique_parsed": len(all_rows),
        "health_candidates": len(all_rows),
        "reachable_total": len(checked),
        "reachable_published": len(checked),
        "published_total": sum(map(len, published_by_country.values())),
        "publication_rejected_total": rejected_total,
        "publication_rejection_reasons": {"country_cap": rejected_total},
        "reachable_by_country": reachable_by_country,
        "published_by_country": {c: len(v) for c, v in published_by_country.items()},
        "country_cap_rejected_by_country": rejected,
        "allowed_ports": [80, 443],
        "protocols": {p: len(published_protocols.get(p, [])) for p in sorted(catalog.PROTOCOLS)},
        "countries": len(published_by_country),
        "country_names": {c: iso_name(c) for c in sorted(published_by_country)},
        "country_policy": "Dynamic ISO-3166 countries from live nodes; explicit node metadata wins; hostname is resolved to IP with cached DNS; unresolved nodes use local GeoLite2 Country; no online geolocation API is used during catalog generation",
        "health_policy": "Every parsed node is asynchronously TCP-screened on ports 80/443; TCP latency is the primary ranking metric; no Xray/GET health stage",
        "source_failures": sum(1 for s in source_health if not s["ok"]),
        "tcp_workers": TCP_WORKERS,
        "max_per_country": MAX_PER_COUNTRY,
        "global_unknown": {"total": len(unknown_items), "server_size": GLOBAL_SERVER_SIZE, "servers": len(global_servers), "files": "global/server-N.txt"},
        "country_resolution": resolver_stats,
        "files": {"countries": "countries/", "protocols": "protocols/", "global": "global/"},
    }

    (OUT / "metadata/index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (OUT / "metadata/countries.json").write_text(
        json.dumps(
            {"countries": [{"code": c, "name": iso_name(c), "nodes": len(v), "reachable": reachable_by_country.get(c, 0), "cap_rejected": rejected.get(c, 0)} for c, v in sorted(published_by_country.items())]},
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    (OUT / "metadata/health.json").write_text(
        json.dumps(
            {
                "generated_at": generated_at,
                "sources": source_health,
                "reachable_total": len(checked),
                "reachable_published": len(checked),
                "published_total": sum(map(len, published_by_country.values())),
                "publication_rejected_total": rejected_total,
                "reachable_by_country": reachable_by_country,
                "published_by_country": {c: len(v) for c, v in published_by_country.items()},
                "country_cap_rejected_by_country": rejected,
                "health_candidates": len(all_rows),
                "tcp_workers": TCP_WORKERS,
                "country_resolution": resolver_stats,
                "global_unknown": {"total": len(unknown_items), "server_size": GLOBAL_SERVER_SIZE, "servers": len(global_servers)},
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(index, ensure_ascii=False, indent=2))
    return index


def main():
    if not GEOIP_DB.is_file() or GEOIP_DB.stat().st_size == 0:
        raise RuntimeError(
            f"Missing local GeoLite2 database: {GEOIP_DB}. Run the GeoLite2 database workflow first."
        )

    cfg = json.loads(SOURCES.read_text(encoding="utf-8"))
    all_rows: list[dict] = []
    source_health: list[dict] = []
    successful_sources = 0

    for item in sorted(cfg["sources"], key=lambda source: -source.get("priority", 0)):
        started = time.perf_counter()
        try:
            rows = catalog.collect_source(item)
            all_rows.extend(rows)
            successful_sources += 1
            source_health.append({"name": item["name"], "ok": True, "nodes": len(rows), "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)})
            print(f"OK {item['name']}: {len(rows)}")
        except Exception as exc:
            source_health.append({"name": item["name"], "ok": False, "nodes": 0, "error": str(exc), "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)})
            print(f"WARN {item['name']}: {exc}")

    failed = [s for s in source_health if not s["ok"]]
    if failed:
        fallback = catalog.load_previous_snapshot()
        all_rows.extend(fallback)
        print(f"INFO source_failures={len(failed)} snapshot_fallback={len(fallback)}")
    if successful_sources == 0 and not all_rows:
        raise RuntimeError("All upstream sources failed and no previous snapshot exists")

    unique: dict[str, dict] = {}
    for row in all_rows:
        unique.setdefault(catalog.dedup_key(row["uri"]), row)
    rows = list(unique.values())
    for row in rows:
        if row["country"] not in catalog.ISO_CODES:
            row["country"] = "UNKNOWN"

    print(f"INFO parsed={len(rows)} tcp_candidates={len(rows)} async_tcp=true workers={TCP_WORKERS}")
    checked = asyncio.run(run_tcp_checks(rows))
    print(f"INFO tcp_reachable={len(checked)} tcp_dead={len(rows) - len(checked)}")

    resolution = country_resolver.resolve_rows(checked)
    print(
        f"INFO country_dns_resolved={resolution['hostname']} "
        f"geolite2_local={resolution['geoip_local']} unknown_remaining={resolution['unknown']} "
        f"database_loaded={resolution['database_loaded']}"
    )

    write_catalog(checked, rows, source_health, resolution)


if __name__ == "__main__":
    main()
