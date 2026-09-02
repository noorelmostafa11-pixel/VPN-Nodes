#!/usr/bin/env python3
"""Build the lightweight, app-facing node pool.

The repository performs two fast validation layers before publication:
1) asynchronous TCP liveness; 2) advertised transport handshake where that can be
validated independently of protocol credentials.  The Android application still
owns the final runtime tunnel/Internet health-check.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import time
from pathlib import Path

import update_catalog as catalog

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
SOURCES = ROOT / "sources" / "sources.json"
TCP_TIMEOUT = float(catalog.CONNECT_TIMEOUT)
TCP_WORKERS = 512


async def tcp_probe(item: dict, semaphore: asyncio.Semaphore) -> tuple[dict, float | None]:
    started = time.perf_counter()
    async with semaphore:
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

    async def one(item: dict):
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


def publish_app_pool(rows: list[dict], source_health: list[dict], handshake_meta: dict | None = None) -> dict:
    """Publish transport-validated nodes with resolved country; no per-country cap.

    Explicit country metadata remains first. Within each metadata tier, nodes with a
    verified active transport handshake rank ahead of TCP+syntax-only nodes, then by
    measured transport latency and TCP latency.
    """
    import country_resolver

    handshake_meta = handshake_meta or {}
    country_result = country_resolver.resolve_rows(rows) if rows else {
        "hostname": 0,
        "geoip_local": 0,
        "metadata_fallback": 0,
        "unknown": 0,
    }

    legacy_active_dir = OUT / "active"
    if legacy_active_dir.exists():
        shutil.rmtree(legacy_active_dir)

    out_dirs = {
        name: OUT / name for name in ("countries", "backup", "protocols", "metadata")
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

    published_total = 0
    for country, country_rows in sorted(grouped.items()):
        country_rows.sort(key=lambda item: (
            0 if str(item.get("country_resolution") or "").lower() == "metadata_explicit" else 1,
            -int(item.get("health_score", 60)),
            float(item.get("handshake_latency_ms") if item.get("handshake_latency_ms") is not None else 10**9),
            float(item.get("latency_ms", 10**9)),
            str(item.get("protocol", "")),
            str(item.get("source", "")),
            str(item.get("uri", "")),
        ))
        uris = [row["uri"] for row in country_rows]
        (out_dirs["countries"] / f"{country}.txt").write_text(
            "\n".join(uris) + "\n", encoding="utf-8"
        )
        published_total += len(uris)

    for protocol, uris in protocol_rows.items():
        (out_dirs["protocols"] / f"{protocol}.txt").write_text(
            "\n".join(uris) + "\n", encoding="utf-8"
        )

    if unknown_rows:
        (out_dirs["metadata"] / "tcp_alive_unknown_country.txt").write_text(
            "\n".join(unknown_rows) + "\n", encoding="utf-8"
        )

    app_meta = {
        "schema": 22,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": "tcp_plus_transport_handshake_android_final_runtime_check",
        "liveness_test": "TCP connect plus advertised TLS/WebSocket/HTTP2 transport handshake where independently testable",
        "final_runtime_test": "Android Xray + local HTTP health-check",
        "allowed_ports": [80, 443],
        "tcp_workers": TCP_WORKERS,
        "transport_handshake_workers": handshake_meta.get("workers"),
        "transport_handshake_timeout_seconds": handshake_meta.get("timeout_seconds"),
        "transport_handshake_rounds": handshake_meta.get("rounds"),
        "per_country_cap": None,
        "active_per_country": None,
        "backup_per_country": None,
        "selection_policy": "all_transport_publishable_nodes_with_resolved_country; explicit_country_metadata_first_then_handshake_quality_then_latency",
        "country_order_policy": "explicit_country_metadata_first; verified_transport_before_tcp_syntax_only; handshake_latency_then_tcp_latency",
        "country_feed_directory": "output/countries",
        "active_directory_generated": False,
        "alive_with_country": sum(len(v) for v in grouped.values()),
        "alive_unknown_country": len(unknown_rows),
        "published_country_nodes": published_total,
        "published_active": published_total,
        "published_backup": 0,
        "published_total": published_total,
        "transport_handshake": handshake_meta,
        "country_resolution": country_result,
        "source_failures": sum(1 for source in source_health if not source["ok"]),
        "sources": source_health,
    }
    (out_dirs["metadata"] / "app_pool.json").write_text(
        json.dumps(app_meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    print(
        f"INFO APP_POOL alive_with_country={app_meta['alive_with_country']} "
        f"countries={published_total} backup=0 published={published_total} "
        f"transport_validation=true per_country_cap=None"
    )
    return app_meta


def main() -> None:
    import transport_handshake

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
        f"async_tcp=true workers={TCP_WORKERS} transport_validation=true"
    )
    tcp_checked = asyncio.run(run_tcp_checks(rows))
    print(
        f"INFO tcp_reachable={len(tcp_checked)} tcp_dead={len(rows) - len(tcp_checked)} "
        f"openvpn_separate=true"
    )

    meta = OUT / "metadata"
    meta.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": 2,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_parsed": len(all_rows),
        "protocol_candidates": len(rows),
        "tcp_reachable": len(tcp_checked),
        "tcp_workers": TCP_WORKERS,
        "allowed_ports": [80, 443],
        "source_failures": sum(1 for s in source_health if not s["ok"]),
        "sources": source_health,
        "nodes": tcp_checked,
    }
    (meta / "tcp_reachable.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    validated, handshake_meta = asyncio.run(transport_handshake.run_transport_checks(tcp_checked))
    (meta / "transport_handshake.json").write_text(
        json.dumps(handshake_meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    publish_app_pool(validated, source_health, handshake_meta)
    print(
        f"INFO transport_pool_saved={len(validated)} tcp_input={len(tcp_checked)} "
        f"report=output/metadata/transport_handshake.json"
    )


if __name__ == "__main__":
    main()
