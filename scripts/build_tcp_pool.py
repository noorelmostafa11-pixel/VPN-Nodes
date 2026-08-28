#!/usr/bin/env python3
"""Build the complete TCP-reachable node catalog without Xray/GET health."""
from __future__ import annotations

import asyncio
import json
import time
from collections import defaultdict
from pathlib import Path

import pycountry

import update_catalog as catalog

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
SOURCES = ROOT / "sources" / "sources.json"

TCP_TIMEOUT = float(catalog.CONNECT_TIMEOUT)
TCP_WORKERS = 512
MAX_PER_COUNTRY = int(catalog.MAX_GENERATED_PER_COUNTRY)


def iso_name(code: str) -> str:
    if code == "UNKNOWN":
        return "Unknown"
    country = pycountry.countries.get(alpha_2=code)
    return country.name if country else code


async def tcp_probe(item: dict, semaphore: asyncio.Semaphore) -> tuple[dict, float | None]:
    started = time.perf_counter()
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(item["host"], item["port"]),
                timeout=TCP_TIMEOUT,
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

    async def one(item: dict) -> None:
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
    latency = row.get("latency_ms")
    if latency is None:
        latency = 10**9
    return (
        latency,
        -row.get("source_priority", 0),
        row.get("protocol", ""),
        row.get("host", ""),
        row.get("uri", ""),
    )


def write_catalog(checked: list[dict], all_rows: list[dict], source_health: list[dict]) -> dict:
    by_country: dict[str, list[dict]] = defaultdict(list)
    by_protocol: dict[str, list[dict]] = defaultdict(list)
    for row in checked:
        by_country[row["country"]].append(row)
        by_protocol[row["protocol"]].append(row)

    for items in by_country.values():
        items.sort(key=rank)
    for items in by_protocol.values():
        items.sort(key=rank)

    reachable_by_country = {
        country: len(items) for country, items in sorted(by_country.items())
    }
    published_by_country = {
        country: items[:MAX_PER_COUNTRY]
        for country, items in sorted(by_country.items())
    }
    rejected_by_country_cap = {
        country: max(0, len(by_country[country]) - len(published_by_country[country]))
        for country in sorted(by_country)
    }
    cap_rejected_total = sum(rejected_by_country_cap.values())

    print(
        f"INFO publication reachable={len(checked)} "
        f"published={sum(len(v) for v in published_by_country.values())} "
        f"country_cap_rejected={cap_rejected_total} max_per_country={MAX_PER_COUNTRY}"
    )
    for country in sorted(reachable_by_country):
        rejected = rejected_by_country_cap[country]
        if rejected:
            print(
                f"INFO publication_country={country} "
                f"reachable={reachable_by_country[country]} "
                f"published={len(published_by_country[country])} "
                f"cap_rejected={rejected}"
            )

    for directory in (OUT / "countries", OUT / "protocols", OUT / "metadata"):
        directory.mkdir(parents=True, exist_ok=True)
    for path in (OUT / "countries").glob("*.txt"):
        path.unlink()
    for path in (OUT / "protocols").glob("*.txt"):
        path.unlink()

    for country, items in published_by_country.items():
        text = "\n".join(item["uri"] for item in items)
        if text:
            text += "\n"
        (OUT / "countries" / f"{country}.txt").write_text(text, encoding="utf-8")

    published_protocols: dict[str, list[dict]] = defaultdict(list)
    for items in published_by_country.values():
        for item in items:
            published_protocols[item["protocol"]].append(item)
    for protocol, items in published_protocols.items():
        items.sort(key=rank)
        (OUT / "protocols" / f"{protocol}.txt").write_text(
            "\n".join(item["uri"] for item in items) + "\n",
            encoding="utf-8",
        )

    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    index = {
        "schema": 4,
        "generated_at": generated_at,
        "total_fetched": len(all_rows),
        "unique_parsed": len(all_rows),
        "health_candidates": len(all_rows),
        "reachable_total": len(checked),
        "reachable_published": len(checked),
        "published_total": sum(len(v) for v in published_by_country.values()),
        "publication_rejected_total": cap_rejected_total,
        "publication_rejection_reasons": {
            "country_cap": cap_rejected_total,
        },
        "reachable_by_country": reachable_by_country,
        "published_by_country": {
            country: len(items) for country, items in published_by_country.items()
        },
        "country_cap_rejected_by_country": rejected_by_country_cap,
        "allowed_ports": [80, 443],
        "protocols": {p: len(published_protocols.get(p, [])) for p in sorted(catalog.PROTOCOLS)},
        "countries": len(published_by_country),
        "country_names": {
            country: iso_name(country) for country in sorted(published_by_country)
        },
        "country_policy": "ISO-3166 alpha-2 only; explicit node metadata wins over feed hint; unresolved nodes go to UNKNOWN",
        "health_policy": "Every parsed node is asynchronously TCP-screened on ports 80/443; TCP latency is the primary ranking metric; source priority is a tie-breaker only; no Xray/GET health stage",
        "source_failures": sum(1 for source in source_health if not source["ok"]),
        "tcp_workers": TCP_WORKERS,
        "max_per_country": MAX_PER_COUNTRY,
        "files": {"countries": "countries/", "protocols": "protocols/"},
    }
    (OUT / "metadata/index.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (OUT / "metadata/countries.json").write_text(
        json.dumps(
            {
                "countries": [
                    {
                        "code": c,
                        "name": iso_name(c),
                        "nodes": len(items),
                        "reachable": reachable_by_country.get(c, 0),
                        "cap_rejected": rejected_by_country_cap.get(c, 0),
                    }
                    for c, items in sorted(published_by_country.items())
                ]
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (OUT / "metadata/health.json").write_text(
        json.dumps(
            {
                "generated_at": generated_at,
                "sources": source_health,
                "reachable_total": len(checked),
                "reachable_published": len(checked),
                "published_total": sum(len(v) for v in published_by_country.values()),
                "publication_rejected_total": cap_rejected_total,
                "publication_rejection_reasons": {"country_cap": cap_rejected_total},
                "reachable_by_country": reachable_by_country,
                "published_by_country": {
                    country: len(items) for country, items in published_by_country.items()
                },
                "country_cap_rejected_by_country": rejected_by_country_cap,
                "health_candidates": len(all_rows),
                "tcp_workers": TCP_WORKERS,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(index, ensure_ascii=False, indent=2))
    return index


def main() -> None:
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
            source_health.append(
                {
                    "name": item["name"],
                    "ok": True,
                    "nodes": len(rows),
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                }
            )
            print(f"OK {item['name']}: {len(rows)}")
        except Exception as exc:
            source_health.append(
                {
                    "name": item["name"],
                    "ok": False,
                    "nodes": 0,
                    "error": str(exc),
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                }
            )
            print(f"WARN {item['name']}: {exc}")

    failed_sources = [source for source in source_health if not source["ok"]]
    if failed_sources:
        fallback = catalog.load_previous_snapshot()
        all_rows.extend(fallback)
        print(f"INFO source_failures={len(failed_sources)} snapshot_fallback={len(fallback)}")

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
    print(f"INFO tcp_reachable={len(checked)} tcp_dead={len(rows)-len(checked)}")
    write_catalog(checked, rows, source_health)


if __name__ == "__main__":
    main()
