"""Optional post-PASS, post-dedup speed observations; never node eligibility."""
from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from pathlib import Path

from owned_core import PROTOCOL_ORDER, connection_key, digest, validate_manifest

POLICY = {"target": "https://speed.cloudflare.com/__down?bytes=1048576",
          "sample_bytes": 1048576, "workers": 4, "shards": 8, "node_timeout_ms": 8000}
POOL_SCHEMA = "vpn-node-speed-pool-v1"
REPORT_SCHEMA = "vpn-node-speed-shard-v1"
RANK_SCHEMA = "vpn-country-speed-ranking-v1"


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Speed metadata must be an object")
    return value


def node_identity(row: dict) -> dict:
    raw = row.get("raw")
    if (not isinstance(raw, str) or not raw or any(c in raw for c in "\r\n")
            or row.get("protocol") not in PROTOCOL_ORDER
            or type(row.get("index")) is not int or row["index"] < 0):
        raise ValueError("Invalid speed input identity")
    node_id = hashlib.sha256(raw.encode()).hexdigest()
    if row.get("node_id") != node_id:
        raise ValueError("Speed input differs from original successful URI")
    return {"raw": raw, "protocol": row["protocol"], "index": row["index"],
            "node_id": node_id, "connection_key": connection_key(row.get("connection_key"))}


def write_pool(rows: list[dict], core: dict, candidate_hash: str, directory: Path) -> None:
    validate_manifest(core)
    directory.mkdir(parents=True, exist_ok=False)
    pool = {"schema": POOL_SCHEMA, "core": core, "candidates_sha256": candidate_hash,
            "policy": POLICY, "nodes": [node_identity(row) for row in rows]}
    (directory / "pool.json").write_text(json.dumps(pool, ensure_ascii=False) + "\n", encoding="utf-8")


def load_pool(path: Path) -> dict:
    pool = read_json(path)
    validate_manifest(pool.get("core") or {})
    if pool.get("schema") != POOL_SCHEMA or pool.get("policy") != POLICY or not isinstance(pool.get("nodes"), list):
        raise ValueError("Invalid speed pool or measurement policy")
    nodes = [node_identity(row) for row in pool["nodes"]]
    if len({n["node_id"] for n in nodes}) != len(nodes):
        raise ValueError("Speed pool contains duplicate original URIs")
    if len({(n["protocol"], n["index"]) for n in nodes}) != len(nodes):
        raise ValueError("Speed pool contains duplicate source identities")
    pool["nodes"] = nodes
    return pool


def assigned(pool: dict, shard: int) -> list[tuple[int, dict]]:
    if shard not in range(POLICY["shards"]):
        raise ValueError("Invalid speed shard")
    return [(i, row) for i, row in enumerate(pool["nodes"]) if i % POLICY["shards"] == shard]


def observation(result: dict | None, row: dict, local_index: int) -> dict:
    record = {"status": "UNMEASURED", "bits_per_second": 0, "sample_bytes": 0,
              "transfer_ns": 0, "first_byte_ms": 0, "code": "SPEED_NOT_COMPLETED"}
    if result is None:
        return record
    if (result.get("index") != local_index or result.get("source") != "nodes.txt"
            or result.get("line") != local_index + 1 or result.get("node_id") != row["node_id"]):
        raise ValueError("Speed result is not for the exact assigned original URI")
    if result.get("connection_key") and row["connection_key"] and result["connection_key"] != row["connection_key"]:
        raise ValueError("Speed core connection differs from the successful connection")
    status = result.get("status")
    if status not in {"MEASURED", "UNMEASURED", "RUNNER_ERROR", "CANCELLED"}:
        raise ValueError("Unexpected speed result status")
    sample = result.get("speed") or {}
    if status != "MEASURED":
        if sample.get("bits_per_second", 0) != 0:
            raise ValueError("Unmeasured node carries a ranking score")
        record["code"] = str((result.get("failure") or {}).get("code") or "SPEED_UNAVAILABLE")
        return record
    integers = ("bytes", "transfer_ns", "bits_per_second", "first_byte_ms")
    if any(type(sample.get(k)) is not int for k in integers):
        raise ValueError("Invalid speed sample numbers")
    size, duration, bps, first = (sample[k] for k in integers)
    if (result.get("protocol") != row["protocol"] or result.get("network_tested") is not True
            or result.get("failure") or not connection_key(result.get("connection_key"))
            or sample.get("target") != POLICY["target"] or sample.get("http_status") != 200
            or sample.get("verified_tls") is not True or size != POLICY["sample_bytes"]
            or duration <= 0 or duration > POLICY["node_timeout_ms"] * 1_000_000
            or first < 0 or first > POLICY["node_timeout_ms"]
            or bps <= 0 or bps != size * 8 * 1_000_000_000 // duration):
        raise ValueError("Measured speed lacks a complete, authenticated, consistent sample")
    return {"status": "MEASURED", "bits_per_second": bps, "sample_bytes": size,
            "transfer_ns": duration, "first_byte_ms": first, "code": "OK"}


def apply_ranking(rows: list[dict], pool_path: Path, results_root: Path,
                  core: dict, candidate_hash: str) -> dict:
    pool = load_pool(pool_path)
    if pool["core"] != core or pool.get("candidates_sha256") != candidate_hash:
        raise ValueError("Speed input came from another core or candidate snapshot")
    expected = {row["node_id"]: node_identity(row) for row in rows}
    if expected != {row["node_id"]: row for row in pool["nodes"]}:
        raise ValueError("Speed pool does not match the final deduplicated successful set")
    records = {node["node_id"]: observation(None, node, 0) for node in pool["nodes"]}
    seen_shards = set()
    seen_nodes = set()
    pool_hash = digest(pool_path)
    for path in sorted(results_root.rglob("observations.jsonl")):
        summary = read_json(path.parent / "summary.json")
        shard = summary.get("shard")
        if type(shard) is not int or shard not in range(POLICY["shards"]) or shard in seen_shards:
            raise ValueError("Duplicate or foreign speed shard")
        if (summary.get("schema") != REPORT_SCHEMA or summary.get("policy") != POLICY
                or summary.get("core") != core or summary.get("pool_sha256") != pool_hash):
            raise ValueError("Speed shard provenance or measurement policy mismatch")
        targets = assigned(pool, shard)
        if summary.get("assigned") != len(targets):
            raise ValueError("Speed shard assignment count mismatch")
        by_index = {i: (local, row) for local, (i, row) in enumerate(targets)}
        actual = Counter()
        for line in path.read_text(encoding="utf-8").splitlines():
            entry = json.loads(line)
            index = entry.get("index")
            if type(index) is not int or index not in by_index:
                raise ValueError("Foreign speed observation")
            local, row = by_index[index]
            if entry.get("node_id") != row["node_id"] or row["node_id"] in seen_nodes:
                raise ValueError("Duplicate or mismatched speed observation")
            seen_nodes.add(row["node_id"])
            records[row["node_id"]] = observation(entry.get("measurement"), row, local)
            actual[records[row["node_id"]]["status"]] += 1
        if sum(actual.values()) != len(targets) or summary.get("statuses") != dict(actual):
            raise ValueError("Speed shard observation coverage mismatch")
        seen_shards.add(shard)
    counts = Counter()
    for row in rows:
        record = records[row["node_id"]]
        try:
            latency = float(row.get("http204_ms"))
        except (TypeError, ValueError):
            latency = math.inf
        record["https_latency_ms"] = latency if latency > 0 and math.isfinite(latency) else None
        row["_speed"] = record
        counts[record["status"]] += 1
    summary = {"schema": RANK_SCHEMA, "policy": POLICY, "total_concurrency": 32,
               "pool_sha256": pool_hash, "measured": counts["MEASURED"],
               "unmeasured": counts["UNMEASURED"], "missing_shards": sorted(set(range(8)) - seen_shards),
               "order": "measured download bps descending; unmeasured retained by verified HTTPS delay",
               "scope": "one 1 MiB sample from GitHub runners; estimate at measurement time, not a speed guarantee",
               "eligibility_changed": False}
    return {"schema": RANK_SCHEMA, "summary": summary, "core": core, "nodes": records}


def verify_ranking(document: dict, summary: dict, core: dict, published: list[str], countries: list[Path]) -> None:
    if (document.get("schema") != RANK_SCHEMA or document.get("core") != core
            or document.get("summary") != summary or summary.get("policy") != POLICY
            or summary.get("total_concurrency") != 32 or summary.get("eligibility_changed") is not False):
        raise ValueError("Published speed policy/provenance mismatch")
    records = document.get("nodes")
    expected_ids = {hashlib.sha256(raw.encode()).hexdigest() for raw in published}
    if not isinstance(records, dict) or set(records) != expected_ids:
        raise ValueError("Speed metadata must retain every published original URI")
    counts = Counter()
    for record in records.values():
        status = record.get("status")
        if status not in {"MEASURED", "UNMEASURED"}:
            raise ValueError("Invalid published speed status")
        counts[status] += 1
        rate = record.get("bits_per_second")
        if type(rate) is not int or (status == "UNMEASURED" and rate != 0):
            raise ValueError("Invalid published speed score")
        if status == "MEASURED":
            size, duration = record.get("sample_bytes"), record.get("transfer_ns")
            if (size != POLICY["sample_bytes"] or type(duration) is not int or duration <= 0
                    or duration > POLICY["node_timeout_ms"] * 1_000_000
                    or rate <= 0 or rate != size * 8 * 1_000_000_000 // duration):
                raise ValueError("Invalid published speed sample")
    if summary.get("measured") != counts["MEASURED"] or summary.get("unmeasured") != counts["UNMEASURED"]:
        raise ValueError("Published speed accounting mismatch")
    for path in countries:
        keys = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            record = records[hashlib.sha256(raw.encode()).hexdigest()]
            latency = record.get("https_latency_ms")
            if not isinstance(latency, (int, float)) or latency <= 0 or not math.isfinite(latency):
                latency = math.inf
            measured = record["status"] == "MEASURED"
            keys.append((0 if measured else 1, -record["bits_per_second"] if measured else 0, latency))
        if keys != sorted(keys):
            raise ValueError("Country feed is not ordered by measured speed and fallback response time")
