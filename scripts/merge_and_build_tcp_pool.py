#!/usr/bin/env python3
"""Merge collectors, semantic-dedup, run TCP, then transport validation."""
from __future__ import annotations

import asyncio
import html
import json
import time
from pathlib import Path

import build_tcp_pool as common
import node_identity
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

    protocol_rows: list[dict] = []
    html_uri_normalized = 0
    for original in all_rows:
        if str(original.get("protocol") or "").lower() == "openvpn":
            continue
        raw_uri = str(original.get("uri") or "").strip()
        clean_uri = html.unescape(raw_uri)
        if clean_uri != raw_uri:
            html_uri_normalized += 1
        protocol_rows.append({**original, "uri": clean_uri})

    unique: dict[str, dict] = {}
    for row in protocol_rows:
        unique.setdefault(node_identity.dedup_key(row["uri"]), row)
    rows = list(unique.values())
    semantic_dedup_removed = len(protocol_rows) - len(rows)

    print(
        f"INFO merged={len(all_rows)} protocol_rows={len(protocol_rows)} "
        f"protocol_candidates={len(rows)} semantic_dedup_removed={semantic_dedup_removed} "
        f"html_uri_normalized={html_uri_normalized}"
    )
    tcp_checked = asyncio.run(common.run_tcp_checks(rows))
    print(f"INFO tcp_reachable={len(tcp_checked)} tcp_dead={len(rows) - len(tcp_checked)}")

    # Runtime-only TCP snapshot. It remains useful for diagnostics but is no longer
    # the publication boundary: every TCP-reachable row is evaluated below.
    META.mkdir(parents=True, exist_ok=True)
    tcp_payload = {
        "schema": 4,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_parsed": len(all_rows),
        "protocol_rows": len(protocol_rows),
        "protocol_candidates": len(rows),
        "semantic_dedup_removed": semantic_dedup_removed,
        "html_uri_normalized": html_uri_normalized,
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
        f"transport_hard_rejected={len(tcp_checked) - len(validated)} "
        f"transport_soft_publishable={handshake_meta.get('soft_failed_publishable', 0)}"
    )

    meta = common.publish_app_pool(validated, source_health, handshake_meta)
    merged_payload = {
        "schema": 4,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_parsed": len(all_rows),
        "protocol_rows": len(protocol_rows),
        "protocol_candidates": len(rows),
        "semantic_dedup_removed": semantic_dedup_removed,
        "html_uri_normalized": html_uri_normalized,
        "tcp_reachable": len(tcp_checked),
        "transport_publishable": len(validated),
        "transport_rejected": len(tcp_checked) - len(validated),
        "transport_soft_publishable": handshake_meta.get("soft_failed_publishable", 0),
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