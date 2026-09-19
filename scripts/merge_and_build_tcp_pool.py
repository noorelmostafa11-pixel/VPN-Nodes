#!/usr/bin/env python3
"""Merge collectors, semantic-dedup, then publish the common TCP-only pool."""
from __future__ import annotations

import asyncio
import html
import json
import time
import urllib.parse
from pathlib import Path

import build_tcp_pool as common
import node_identity
import source_freshness
import update_catalog as catalog

ROOT = Path(__file__).resolve().parents[1]
META = ROOT / "output" / "metadata"
SOURCE_FRESHNESS_STATE = META / "source_freshness.json"
SOURCE_CONFIG = ROOT / "sources" / "sources.json"
INPUTS = (
    META / "sources_candidates.json",
    META / "telegram_candidates.json",
    META / "v2nodes_candidates.json",
)



def is_insecure_plain_vless(uri: str) -> bool:
    """True only when VLESS has neither transport security nor VLESS Encryption."""
    try:
        parsed = urllib.parse.urlsplit(uri)
        if parsed.scheme.lower() != "vless":
            return False
        query = {
            key.lower(): values
            for key, values in urllib.parse.parse_qs(
                parsed.query,
                keep_blank_values=True,
            ).items()
        }

        def first(*keys: str) -> str:
            for key in keys:
                values = query.get(key.lower())
                if values:
                    return str(values[0]).strip()
            return ""

        security = (first("security", "tls") or "none").lower()
        encryption = (first("encryption") or "none").lower()
        has_reality_key = bool(first("pbk", "publicKey"))
        return (
            not has_reality_key
            and security in {"none", "false", "0"}
            and encryption == "none"
        )
    except (TypeError, ValueError):
        return False


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

    source_cfg = json.loads(SOURCE_CONFIG.read_text(encoding="utf-8"))
    max_stale_hours = int(
        source_cfg.get("freshness_policy", {}).get(
            "max_unchanged_hours", source_freshness.DEFAULT_MAX_STALE_HOURS
        )
    )
    all_rows, source_health, freshness = source_freshness.apply_source_freshness(
        all_rows,
        source_health,
        SOURCE_FRESHNESS_STATE,
        max_stale_hours=max_stale_hours,
    )
    print(
        f"INFO source_freshness checked={freshness['sources_checked']} "
        f"active={freshness['active_sources']} stale={freshness['stale_sources']} "
        f"mirrors={freshness['duplicate_sources']} failed={freshness['failed_sources']} "
        f"empty={freshness['empty_sources']} "
        f"included_nodes={freshness['included_nodes']}"
    )

    protocol_rows: list[dict] = []
    html_uri_normalized = 0
    insecure_plain_vless_removed = 0
    for original in all_rows:
        if str(original.get("protocol") or "").lower() == "openvpn":
            continue
        raw_uri = str(original.get("uri") or "").strip()
        clean_uri = html.unescape(raw_uri)
        if clean_uri != raw_uri:
            html_uri_normalized += 1
        if is_insecure_plain_vless(clean_uri):
            insecure_plain_vless_removed += 1
            continue
        protocol_rows.append({**original, "uri": clean_uri})

    unique: dict[str, dict] = {}
    for row in protocol_rows:
        unique.setdefault(node_identity.dedup_key(row["uri"]), row)
    rows = list(unique.values())
    semantic_dedup_removed = len(protocol_rows) - len(rows)

    print(
        f"INFO merged={len(all_rows)} protocol_rows={len(protocol_rows)} "
        f"protocol_candidates={len(rows)} semantic_dedup_removed={semantic_dedup_removed} "
        f"html_uri_normalized={html_uri_normalized} "
        f"insecure_plain_vless_removed={insecure_plain_vless_removed}"
    )

    tcp_checked = asyncio.run(common.run_tcp_checks(rows))
    print(f"INFO tcp_reachable={len(tcp_checked)} tcp_dead={len(rows) - len(tcp_checked)}")

    META.mkdir(parents=True, exist_ok=True)
    # Remove stale metadata from the abandoned transport-handshake publication path.
    (META / "transport_handshake.json").unlink(missing_ok=True)

    compact_freshness = {key: value for key, value in freshness.items() if key != "sources"}
    tcp_payload = {
        "schema": 5,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_parsed": len(all_rows),
        "protocol_rows": len(protocol_rows),
        "protocol_candidates": len(rows),
        "semantic_dedup_removed": semantic_dedup_removed,
        "html_uri_normalized": html_uri_normalized,
        "insecure_plain_vless_removed": insecure_plain_vless_removed,
        "tcp_reachable": len(tcp_checked),
        "tcp_workers": common.TCP_WORKERS,
        "allowed_ports": sorted(catalog.ALLOWED_PORTS),
        "source_failures": sum(1 for source in source_health if not source.get("ok")),
        "source_freshness": compact_freshness,
        "sources": source_health,
        "nodes": tcp_checked,
        "country_order_policy": "latency_ascending_only",
    }
    (META / "tcp_reachable.json").write_text(
        json.dumps(tcp_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    meta = common.publish_app_pool(tcp_checked, source_health, freshness)
    merged_payload = {
        "schema": 5,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": "tcp_only_android_final_xray_check",
        "total_parsed": len(all_rows),
        "protocol_rows": len(protocol_rows),
        "protocol_candidates": len(rows),
        "semantic_dedup_removed": semantic_dedup_removed,
        "html_uri_normalized": html_uri_normalized,
        "insecure_plain_vless_removed": insecure_plain_vless_removed,
        "tcp_reachable": len(tcp_checked),
        "source_freshness": compact_freshness,
        "sources": source_health,
        "common_pool": meta,
    }
    (META / "merged_pool.json").write_text(
        json.dumps(merged_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        f"INFO published_tcp_only={meta.get('published_total', 0)} "
        f"order=latency_ascending_only android_final_xray=true"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
