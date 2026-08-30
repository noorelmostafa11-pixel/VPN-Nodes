#!/usr/bin/env python3
"""Build the lightweight, app-facing node pool.

The workflow intentionally stops at TCP liveness. The Android application owns the
Xray/runtime health check and performs the final real-traffic validation itself.
OpenVPN sources are kept on a separate protocol path and are never mixed into the
Xray feed consumed by the Android app.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import update_catalog as catalog

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
SOURCES = ROOT / "sources" / "sources.json"
TCP_TIMEOUT = float(catalog.CONNECT_TIMEOUT)
TCP_WORKERS = 512
ACTIVE_PER_COUNTRY = 5
BACKUP_PER_COUNTRY = 5
MAX_POOL_PER_COUNTRY = ACTIVE_PER_COUNTRY + BACKUP_PER_COUNTRY


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


def publish_app_pool(rows: list[dict], source_health: list[dict]) -> dict:
    """Resolve country and publish only TCP-ALIVE nodes for Android consumption.

    No Xray test is performed here. The app receives these live endpoints and then
    runs its own Xray + Internet health-check.
    """
    import country_resolver

    country_result = country_resolver.resolve_rows(rows) if rows else {
        "hostname": 0,
        "geoip_local": 0,
        "metadata_fallback": 0,
        "unknown": 0,
    }

    out_dirs = {
        name: OUT / name for name in ("countries", "active", "backup", "protocols", "metadata")
    }
    for directory in out_dirs.values():
        directory.mkdir(parents=True, exist_ok=True)

    for name in ("countries", "active", "backup", "protocols"):
        for path in out_dirs[name].glob("*.txt"):
            path.unlink()

    # Keep only nodes for which the country resolver produced a usable country.
    # UNKNOWN remains in metadata/tcp_reachable.json but is not exposed as a
    # country feed because the Android app selects by country.
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        country = str(row.get("country") or "UNKNOWN").upper()
        if country == "UNKNOWN":
            continue
        grouped.setdefault(country, []).append(row)

    active_total = 0
    backup_total = 0
    protocol_rows: dict[str, list[str]] = {}

    for country, country_rows in sorted(grouped.items()):
        country_rows.sort(key=lambda item: (
            float(item.get("latency_ms", 10**9)),
            str(item.get("protocol", "")),
            str(item.get("source", "")),
            str(item.get("uri", "")),
        ))
        selected = country_rows[:MAX_POOL_PER_COUNTRY]
        active = selected[:ACTIVE_PER_COUNTRY]
        backup = selected[ACTIVE_PER_COUNTRY:MAX_POOL_PER_COUNTRY]

        if active:
            (out_dirs["active"] / f"{country}.txt").write_text(
                "\n".join(row["uri"] for row in active) + "\n",
                encoding="utf-8",
            )
            active_total += len(active)

        if backup:
            (out_dirs["backup"] / f"{country}.txt").write_text(
                "\n".join(row["uri"] for row in backup) + "\n",
                encoding="utf-8",
            )
            backup_total += len(backup)

        combined = active + backup
        if combined:
            (out_dirs["countries"] / f"{country}.txt").write_text(
                "\n".join(row["uri"] for row in combined) + "\n",
                encoding="utf-8",
            )

        for row in combined:
            protocol = str(row.get("protocol") or "").lower()
            if protocol:
                protocol_rows.setdefault(protocol, []).append(row["uri"])

    for protocol, uris in protocol_rows.items():
        (out_dirs["protocols"] / f"{protocol}.txt").write_text(
            "\n".join(uris) + "\n",
            encoding="utf-8",
        )

    app_meta = {
        "schema": 19,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": "tcp_liveness_only_android_final_xray_check",
        "liveness_test": "TCP connect to advertised endpoint",
        "final_runtime_test": "Android Xray + local HTTP health-check",
        "allowed_ports": [80, 443],
        "tcp_workers": TCP_WORKERS,
        "active_per_country": ACTIVE_PER_COUNTRY,
        "backup_per_country": BACKUP_PER_COUNTRY,
        "max_pool_per_country": MAX_POOL_PER_COUNTRY,
        "alive_with_country": sum(len(v) for v in grouped.values()),
        "published_active": active_total,
        "published_backup": backup_total,
        "published_total": active_total + backup_total,
        "country_resolution": country_result,
        "source_failures": sum(1 for source in source_health if not source["ok"]),
        "sources": source_health,
    }
    (out_dirs["metadata"] / "app_pool.json").write_text(
        json.dumps(app_meta, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(
        f"INFO APP_POOL alive_with_country={app_meta['alive_with_country']} "
        f"active={active_total} backup={backup_total} "
        f"published={active_total + backup_total}"
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

    # OpenVPN candidates stay protocol-separated. They may be collected into their
    # dedicated metadata file, but they never enter the Xray/app TCP feed.
    xray_rows = [
        row for row in all_rows
        if str(row.get("protocol") or "").lower() != "openvpn"
    ]

    unique: dict[str, dict] = {}
    for row in xray_rows:
        unique.setdefault(catalog.dedup_key(row["uri"]), row)
    rows = list(unique.values())

    print(
        f"INFO parsed={len(all_rows)} xray_candidates={len(rows)} "
        f"async_tcp=true workers={TCP_WORKERS} xray_deep_test=false"
    )
    checked = asyncio.run(run_tcp_checks(rows))
    print(
        f"INFO tcp_reachable={len(checked)} tcp_dead={len(rows) - len(checked)} "
        f"openvpn_separate=true"
    )

    meta = OUT / "metadata"
    meta.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_parsed": len(all_rows),
        "xray_candidates": len(rows),
        "tcp_reachable": len(checked),
        "tcp_workers": TCP_WORKERS,
        "allowed_ports": [80, 443],
        "xray_deep_test": False,
        "android_final_xray_test": True,
        "source_failures": sum(1 for s in source_health if not s["ok"]),
        "sources": source_health,
        "nodes": checked,
    }
    (meta / "tcp_reachable.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    publish_app_pool(checked, source_health)
    print(f"INFO tcp_pool_saved={len(checked)} path=output/metadata/tcp_reachable.json")


if __name__ == "__main__":
    main()
