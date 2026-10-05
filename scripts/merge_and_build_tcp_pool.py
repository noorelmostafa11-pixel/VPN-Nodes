#!/usr/bin/env python3
"""Merge collectors, connection-equivalent dedup, then publish the TCP-only pool."""
from __future__ import annotations

import asyncio
import html
import json
import time
from pathlib import Path

import build_tcp_pool as common
import node_identity
import source_freshness
import update_catalog as catalog

ROOT = Path(__file__).resolve().parents[1]
META = ROOT / "output" / "metadata"
SOURCE_FRESHNESS_STATE = META / "source_freshness.json"
INPUTS = (
    META / "sources_candidates.json",
    META / "telegram_candidates.json",
    META / "v2nodes_candidates.json",
)


def _endpoint_key(row: dict) -> tuple[str, int] | None:
    host = str(row.get("host") or "").strip().lower()
    try:
        port = int(row.get("port") or 0)
    except (TypeError, ValueError):
        return None
    if not host or port not in catalog.ALLOWED_PORTS:
        return None
    return host, port


async def run_tcp_checks_by_endpoint(rows: list[dict]) -> tuple[list[dict], int, int]:
    """Probe TCP once per host:port, then map liveness back to every config."""
    endpoint_rows: dict[tuple[str, int], dict] = {}
    for row in rows:
        endpoint = _endpoint_key(row)
        if endpoint is None:
            continue
        endpoint_rows.setdefault(
            endpoint,
            {"host": endpoint[0], "port": endpoint[1]},
        )

    checked_endpoints = await common.run_tcp_checks(list(endpoint_rows.values()))
    reachable: dict[tuple[str, int], dict] = {}
    for endpoint_row in checked_endpoints:
        endpoint = _endpoint_key(endpoint_row)
        if endpoint is not None:
            reachable[endpoint] = endpoint_row

    checked_configs: list[dict] = []
    for row in rows:
        endpoint = _endpoint_key(row)
        if endpoint is None:
            continue
        endpoint_result = reachable.get(endpoint)
        if endpoint_result is None:
            continue
        checked_configs.append({
            **row,
            "latency_ms": endpoint_result["latency_ms"],
            "liveness": endpoint_result.get("liveness", "ALIVE"),
            "country": endpoint_result.get("country", "UNKNOWN"),
            "country_resolution": endpoint_result.get("country_resolution", "pending"),
        })

    return checked_configs, len(endpoint_rows), len(reachable)



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

    all_rows, source_health, freshness = source_freshness.apply_source_freshness(
        all_rows,
        source_health,
        SOURCE_FRESHNESS_STATE,
    )
    print(
        f"INFO source_freshness checked={freshness['sources_checked']} "
        f"active={freshness['active_sources']} stale=0 mirrors=0 "
        f"failed={freshness['failed_sources']} "
        f"empty={freshness['empty_sources']} "
        f"included_nodes={freshness['included_nodes']} "
        f"policy={freshness['filtering_policy']}"
    )

    protocol_rows: list[dict] = []
    html_uri_normalized = 0
    for original in all_rows:
        if str(original.get("protocol") or "").lower() == "openvpn":
            continue
        if _endpoint_key(original) is None:
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
    connection_dedup_removed = len(protocol_rows) - len(rows)

    print(
        f"INFO merged={len(all_rows)} protocol_rows={len(protocol_rows)} "
        f"protocol_candidates={len(rows)} connection_dedup_removed={connection_dedup_removed} "
        f"dedup_mode=xray_connection_equivalent "
        f"html_uri_normalized={html_uri_normalized}"
    )

    tcp_checked, tcp_unique_endpoints, tcp_reachable_endpoints = asyncio.run(
        run_tcp_checks_by_endpoint(rows)
    )
    print(
        f"INFO tcp_unique_endpoints={tcp_unique_endpoints} "
        f"tcp_reachable_endpoints={tcp_reachable_endpoints} "
        f"tcp_dead_endpoints={tcp_unique_endpoints - tcp_reachable_endpoints} "
        f"tcp_reachable_configs={len(tcp_checked)} "
        f"tcp_dead_configs={len(rows) - len(tcp_checked)}"
    )

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
        "dedup_mode": "xray_connection_equivalent",
        "connection_dedup_removed": connection_dedup_removed,
        "semantic_dedup_removed": connection_dedup_removed,
        "html_uri_normalized": html_uri_normalized,
        "tcp_probe_mode": "one_probe_per_host_port",
        "tcp_unique_endpoints": tcp_unique_endpoints,
        "tcp_reachable_endpoints": tcp_reachable_endpoints,
        "tcp_dead_endpoints": tcp_unique_endpoints - tcp_reachable_endpoints,
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
        "dedup_mode": "xray_connection_equivalent",
        "connection_dedup_removed": connection_dedup_removed,
        "semantic_dedup_removed": connection_dedup_removed,
        "html_uri_normalized": html_uri_normalized,
        "tcp_probe_mode": "one_probe_per_host_port",
        "tcp_unique_endpoints": tcp_unique_endpoints,
        "tcp_reachable_endpoints": tcp_reachable_endpoints,
        "tcp_dead_endpoints": tcp_unique_endpoints - tcp_reachable_endpoints,
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
