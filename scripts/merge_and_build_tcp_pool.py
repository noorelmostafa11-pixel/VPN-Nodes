#!/usr/bin/env python3
"""Merge collectors, run TCP liveness, then full-pool transport validation."""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import build_tcp_pool as common
import transport_handshake
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

    protocol_rows = [row for row in all_rows if str(row.get("protocol") or "").lower() != "openvpn"]
    unique: dict[str, dict] = {}
    for row in protocol_rows:
        unique.setdefault(catalog.dedup_key(row["uri"]), row)
    rows = list(unique.values())

    print(f"INFO merged={len(all_rows)} protocol_candidates={len(rows)}")
    tcp_checked = asyncio.run(common.run_tcp_checks(rows))
    print(f"INFO tcp_reachable={len(tcp_checked)} tcp_dead={len(rows) - len(tcp_checked)}")

    # Runtime-only TCP snapshot. It remains useful for diagnostics but is no longer
    # the publication boundary: every TCP-reachable row is evaluated below.
    META.mkdir(parents=True, exist_ok=True)
    tcp_payload = {
        "schema": 2,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_parsed": len(all_rows),
        "protocol_candidates": len(rows),
        "tcp_reachable": len(tcp_checked),
        "tcp_workers": common.TCP_WORKERS,
        "allowed_ports": sorted(catalog.ALLOWED_PORTS),
        "source_failures": sum(1 for source in source_health if not source.get("ok")),
        "sources": source_health,
        "nodes": tcp_checked,
    }
    (META / "tcp_reachable.json").write_text(
        json.dumps(tcp_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"INFO runtime_tcp_pool={len(tcp_checked)} path=output/metadata/tcp_reachable.json")

    validated, handshake_meta = asyncio.run(transport_handshake.run_transport_checks(tcp_checked))
    (META / "transport_handshake.json").write_text(
        json.dumps(handshake_meta, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        f"INFO transport_publishable={len(validated)} "
        f"transport_rejected={len(tcp_checked) - len(validated)}"
    )

    meta = common.publish_app_pool(validated, source_health, handshake_meta)
    merged_payload = {
        "schema": 2,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_parsed": len(all_rows),
        "protocol_candidates": len(rows),
        "tcp_reachable": len(tcp_checked),
        "transport_publishable": len(validated),
        "transport_rejected": len(tcp_checked) - len(validated),
        "sources": source_health,
        "transport_handshake": handshake_meta,
        "common_pool": meta,
    }
    (META / "merged_pool.json").write_text(
        json.dumps(merged_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
