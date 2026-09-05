#!/usr/bin/env python3
"""Build the lightweight app-facing TCP pool.

Repository responsibility stops at endpoint TCP liveness and country assignment.
The Android application owns Xray startup and the final real-traffic health check.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
from pathlib import Path

import update_catalog as catalog

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
SOURCES = ROOT / "sources" / "sources.json"
TCP_TIMEOUT = float(catalog.CONNECT_TIMEOUT)
TCP_WORKERS = 512
COUNTRY_SHARD_SIZE = int(os.environ.get("COUNTRY_SHARD_SIZE", "1000"))
COUNTRY_SHARD_MAX_BYTES = 4 * 1024 * 1024


async def tcp_probe(item: dict, semaphore: asyncio.Semaphore) -> tuple[dict, float | None]:
    async with semaphore:
        started = time.perf_counter()
        try:
            _, writer = await asyncio.wait_for(
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
            results.append({
                **row,
                "latency_ms": latency,
                "liveness": "ALIVE",
                "country": "UNKNOWN",
                "country_resolution": "pending",
            })
        if completed % 1000 == 0 or completed == total:
            print(f"INFO tcp_progress={completed}/{total} reachable={len(results)}")

    await asyncio.gather(*(one(item) for item in rows))
    return results


def publish_app_pool(rows: list[dict], source_health: list[dict]) -> dict:
    """Publish every TCP-alive node, globally ordered by TCP latency per country.

    Country/source discovery method never affects ranking. Once a node is assigned
    to a country, every node in that country's feed competes in one common list
    sorted by latency_ms ascending. Protocol/source/URI are deterministic tie-breaks
    only when two measured TCP latencies are equal.

    No TLS, WebSocket, HTTP/2 or protocol handshake is performed here; Xray on
    Android is the final compatibility and Internet-health authority.
    """
    import country_resolver
    import pycountry

    if COUNTRY_SHARD_SIZE < 100 or COUNTRY_SHARD_SIZE > 5000:
        raise ValueError(
            f"COUNTRY_SHARD_SIZE must be between 100 and 5000, got {COUNTRY_SHARD_SIZE}"
        )

    country_result = country_resolver.resolve_rows(rows) if rows else {
        "hostname": 0,
        "geoip_local": 0,
        "metadata_fallback": 0,
        "unknown": 0,
    }

    legacy_active_dir = OUT / "active"
    if legacy_active_dir.exists():
        shutil.rmtree(legacy_active_dir)

    country_shards_dir = OUT / "country_shards"
    if country_shards_dir.exists():
        shutil.rmtree(country_shards_dir)

    out_dirs = {
        name: OUT / name
        for name in ("countries", "country_shards", "backup", "protocols", "metadata")
    }
    for directory in out_dirs.values():
        directory.mkdir(parents=True, exist_ok=True)

    for name in ("countries", "backup", "protocols"):
        for path in out_dirs[name].glob("*.txt"):
            path.unlink()

    grouped: dict[str, list[dict]] = {}
    protocol_rows: dict[str, list[str]] = {}
    unknown_rows: list[str] = []

    for row in rows:
        country = str(row.get("country") or "UNKNOWN").upper()
        if country == "UNKNOWN":
            unknown_rows.append(row["uri"])
            continue
        grouped.setdefault(country, []).append(row)
        protocol = str(row.get("protocol") or "").lower()
        if protocol:
            protocol_rows.setdefault(protocol, []).append(row["uri"])

    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    published_total = 0
    published_shards = 0
    countries_meta: list[dict] = []
    for country, country_rows in sorted(grouped.items()):
        # Source and country-resolution method MUST NOT influence ranking.
        # Every node assigned to this country is ordered only by measured TCP ms.
        country_rows.sort(key=lambda item: (
            float(item.get("latency_ms", 10**9)),
            str(item.get("protocol", "")),
            str(item.get("source", "")),
            str(item.get("uri", "")),
        ))
        uris = [row["uri"] for row in country_rows]
        (out_dirs["countries"] / f"{country}.txt").write_text(
            "\n".join(uris) + "\n", encoding="utf-8"
        )

        shard_dir = out_dirs["country_shards"] / country
        shard_dir.mkdir(parents=True, exist_ok=True)
        shard_count = 0
        for shard_index, start in enumerate(range(0, len(uris), COUNTRY_SHARD_SIZE)):
            chunk = uris[start:start + COUNTRY_SHARD_SIZE]
            shard_bytes = ("\n".join(chunk) + "\n").encode("utf-8")
            if len(shard_bytes) > COUNTRY_SHARD_MAX_BYTES:
                raise ValueError(
                    f"Country shard {country}/{shard_index:03d}.txt exceeds "
                    f"{COUNTRY_SHARD_MAX_BYTES} bytes"
                )
            (shard_dir / f"{shard_index:03d}.txt").write_bytes(shard_bytes)
            shard_count += 1

        published_total += len(uris)
        published_shards += shard_count

        match = pycountry.countries.get(alpha_2=country)
        countries_meta.append({
            "code": country,
            "name": str(match.name) if match is not None else country,
            "nodes": len(uris),
            "active": 0,
            "backup": len(uris),
            "shards": shard_count,
            "shard_size": COUNTRY_SHARD_SIZE,
            "shard_path": f"output/country_shards/{country}",
        })

    for protocol, uris in protocol_rows.items():
        (out_dirs["protocols"] / f"{protocol}.txt").write_text(
            "\n".join(uris) + "\n", encoding="utf-8"
        )

    if unknown_rows:
        (out_dirs["metadata"] / "tcp_alive_unknown_country.txt").write_text(
            "\n".join(unknown_rows) + "\n", encoding="utf-8"
        )
    else:
        (out_dirs["metadata"] / "tcp_alive_unknown_country.txt").unlink(missing_ok=True)

    (out_dirs["metadata"] / "countries.json").write_text(
        json.dumps(
            {
                "schema": 2,
                "generated_at": generated_at,
                "shard_size": COUNTRY_SHARD_SIZE,
                "countries": countries_meta,
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )

    app_meta = {
        "schema": 22,
        "generated_at": generated_at,
        "mode": "tcp_liveness_only_android_final_xray_check",
        "liveness_test": "TCP connect to advertised endpoint",
        "final_runtime_test": "Android Xray + local HTTP health-check",
        "allowed_ports": sorted(catalog.ALLOWED_PORTS),
        "tcp_workers": TCP_WORKERS,
        "per_country_cap": None,
        "active_per_country": None,
        "backup_per_country": None,
        "selection_policy": "all_tcp_alive_nodes_with_resolved_country; latency_ascending_only",
        "country_order_policy": "latency_ascending_only",
        "country_feed_directory": "output/countries",
        "country_shard_directory": "output/country_shards",
        "country_shard_size": COUNTRY_SHARD_SIZE,
        "country_shards_generated": True,
        "published_country_shards": published_shards,
        "active_directory_generated": False,
        "alive_with_country": sum(len(v) for v in grouped.values()),
        "alive_unknown_country": len(unknown_rows),
        "published_country_nodes": published_total,
        "published_active": published_total,
        "published_backup": 0,
        "published_total": published_total,
        "country_resolution": country_result,
        "source_failures": sum(1 for source in source_health if not source.get("ok")),
        "sources": source_health,
    }
    (out_dirs["metadata"] / "app_pool.json").write_text(
        json.dumps(app_meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    print(
        f"INFO APP_POOL tcp_only=true alive_with_country={app_meta['alive_with_country']} "
        f"countries={len(countries_meta)} nodes={published_total} "
        f"shards={published_shards} shard_size={COUNTRY_SHARD_SIZE} "
        f"order=latency_ascending_only"
    )
    return app_meta


def main() -> None:
    cfg = json.loads(SOURCES.read_text(encoding="utf-8"))
    all_rows: list[dict] = []
    source_health: list[dict] = []
    successful_sources = 0

    for item in cfg["sources"]:
        started = time.perf_counter()
        try:
            if item.get("format") == "v2nodes":
                from v2nodes_adapter import collect as collect_v2nodes
                raw_uris = collect_v2nodes(
                    item.get("url", "https://www.v2nodes.com/"),
                    int(item.get("max_pages", 5000)),
                )
                rows = catalog.parse_lines("\n".join(raw_uris), item["name"])
            else:
                rows = catalog.collect_source(item)
            all_rows.extend(rows)
            successful_sources += 1
            source_health.append({
                "name": item["name"],
                "ok": True,
                "nodes": len(rows),
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
            })
            print(f"OK {item['name']}: {len(rows)}")
        except Exception as exc:
            source_health.append({
                "name": item["name"],
                "ok": False,
                "nodes": 0,
                "error": str(exc),
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
            })
            print(f"WARN {item['name']}: {exc}")

    if successful_sources == 0 and not all_rows:
        raise RuntimeError("All upstream sources failed")

    protocol_rows = [
        row for row in all_rows
        if str(row.get("protocol") or "").lower() != "openvpn"
    ]
    unique: dict[str, dict] = {}
    for row in protocol_rows:
        unique.setdefault(catalog.dedup_key(row["uri"]), row)
    rows = list(unique.values())

    print(
        f"INFO parsed={len(all_rows)} protocol_candidates={len(rows)} "
        f"async_tcp=true workers={TCP_WORKERS} xray_deep_test=false"
    )
    tcp_checked = asyncio.run(run_tcp_checks(rows))
    print(
        f"INFO tcp_reachable={len(tcp_checked)} tcp_dead={len(rows) - len(tcp_checked)} "
        f"openvpn_separate=true"
    )

    meta = OUT / "metadata"
    meta.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": 3,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_parsed": len(all_rows),
        "protocol_candidates": len(rows),
        "tcp_reachable": len(tcp_checked),
        "tcp_workers": TCP_WORKERS,
        "allowed_ports": sorted(catalog.ALLOWED_PORTS),
        "xray_deep_test": False,
        "android_final_xray_test": True,
        "source_failures": sum(1 for s in source_health if not s.get("ok")),
        "sources": source_health,
        "nodes": tcp_checked,
        "country_order_policy": "latency_ascending_only",
    }
    (meta / "tcp_reachable.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    publish_app_pool(tcp_checked, source_health)
    print(f"INFO tcp_pool_saved={len(tcp_checked)} path=output/metadata/tcp_reachable.json")


if __name__ == "__main__":
    main()
