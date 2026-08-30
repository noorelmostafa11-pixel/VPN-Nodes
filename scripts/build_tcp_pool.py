#!/usr/bin/env python3
"""Build the TCP-reachable Xray candidate pool; OpenVPN is handled separately."""
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
            results.append({**row, "latency_ms": latency, "country": "UNKNOWN", "country_resolution": "pending_xray"})
        if completed % 1000 == 0 or completed == total:
            print(f"INFO tcp_progress={completed}/{total} reachable={len(results)}")

    await asyncio.gather(*(one(item) for item in rows))
    return results

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
            source_health.append({"name": item["name"], "ok": True, "nodes": len(rows), "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)})
            print(f"OK {item['name']}: {len(rows)}")
        except Exception as exc:
            source_health.append({"name": item["name"], "ok": False, "nodes": 0, "error": str(exc), "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)})
            print(f"WARN {item['name']}: {exc}")

    if successful_sources == 0 and not all_rows:
        raise RuntimeError("All upstream sources failed")

    # OpenVPN candidates have their own protocol-specific path. Never send them
    # through the Xray TCP pool, deduplication, or Xray health stage.
    xray_rows = [row for row in all_rows if str(row.get("protocol") or "").lower() != "openvpn"]

    unique: dict[str, dict] = {}
    for row in xray_rows:
        unique.setdefault(catalog.dedup_key(row["uri"]), row)
    rows = list(unique.values())
    for row in rows:
        row["country"] = "UNKNOWN"
        row["country_resolution"] = "pending_xray"

    print(f"INFO parsed={len(all_rows)} xray_candidates={len(rows)} async_tcp=true workers={TCP_WORKERS}")
    checked = asyncio.run(run_tcp_checks(rows))
    print(f"INFO tcp_reachable={len(checked)} tcp_dead={len(rows) - len(checked)} openvpn_separate=true")

    meta = OUT / "metadata"
    meta.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_parsed": len(all_rows),
        "xray_candidates": len(rows),
        "tcp_reachable": len(checked),
        "tcp_workers": TCP_WORKERS,
        "allowed_ports": [80, 443],
        "source_failures": sum(1 for s in source_health if not s["ok"]),
        "sources": source_health,
        "nodes": [{k: v for k, v in item.items() if k != "node"} for item in checked],
    }
    (meta / "tcp_reachable.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"INFO tcp_pool_saved={len(checked)} path=output/metadata/tcp_reachable.json")

if __name__ == "__main__": main()
