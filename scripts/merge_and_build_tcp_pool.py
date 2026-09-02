#!/usr/bin/env python3
"""Merge sequential collector outputs, then run the repository's common pool."""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import build_tcp_pool as common
import update_catalog as catalog

ROOT = Path(__file__).resolve().parents[1]
META = ROOT / "output" / "metadata"
INPUTS = (
    META / "sources_candidates.json",
    META / "telegram_candidates.json",
    META / "v2nodes_candidates.json",
)


def load_rows(path: Path) -> tuple[list[dict], list[dict]]:
    if not path.is_file():
        raise RuntimeError(f"Missing candidate file: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    return list(payload.get("rows", [])), list(payload.get("sources", payload.get("channels", [])))


def main() -> int:
    all_rows: list[dict] = []
    source_health: list[dict] = []
    for path in INPUTS:
        rows, health = load_rows(path)
        all_rows.extend(rows)
        source_health.extend(health)
        print(f"INFO loaded {path.name}: rows={len(rows)}")

    xray_rows = [row for row in all_rows if str(row.get("protocol") or "").lower() != "openvpn"]
    unique: dict[str, dict] = {}
    for row in xray_rows:
        unique.setdefault(catalog.dedup_key(row["uri"]), row)
    rows = list(unique.values())

    print(f"INFO merged={len(all_rows)} xray_candidates={len(rows)}")
    checked = asyncio.run(common.run_tcp_checks(rows))
    print(f"INFO tcp_reachable={len(checked)} tcp_dead={len(rows) - len(checked)}")

    # Runtime-only handoff for the owned-Xray pilot. This file is intentionally
    # gitignored and does not alter the existing publication policy.
    META.mkdir(parents=True, exist_ok=True)
    tcp_payload = {
        "schema": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_parsed": len(all_rows),
        "xray_candidates": len(rows),
        "tcp_reachable": len(checked),
        "tcp_workers": common.TCP_WORKERS,
        "allowed_ports": sorted(catalog.ALLOWED_PORTS),
        "source_failures": sum(1 for source in source_health if not source.get("ok")),
        "sources": source_health,
        "nodes": checked,
    }
    (META / "tcp_reachable.json").write_text(
        json.dumps(tcp_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"INFO runtime_tcp_pool={len(checked)} path=output/metadata/tcp_reachable.json")

    meta = common.publish_app_pool(checked, source_health)
    merged_payload = {
        "schema": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_parsed": len(all_rows),
        "xray_candidates": len(rows),
        "tcp_reachable": len(checked),
        "sources": source_health,
        "common_pool": meta,
    }
    (META / "merged_pool.json").write_text(
        json.dumps(merged_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
