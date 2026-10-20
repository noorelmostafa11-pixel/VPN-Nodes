"""Optional post-PASS, post-dedup delay observations; never node eligibility."""
from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from pathlib import Path

from owned_core import PROTOCOL_ORDER, connection_key, digest, validate_manifest

POLICY = {"target": "https://www.google.com/generate_204", "attempts_per_node": 2,
          "interval_ms": 100, "max_response_bytes": 65536,
          "workers": 4, "shards": 8, "node_timeout_ms": 5000}
POOL_SCHEMA = "vpn-node-delay-pool-v1"
REPORT_SCHEMA = "vpn-node-delay-shard-v1"
RANK_SCHEMA = "vpn-country-delay-ranking-v1"


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Delay metadata must be an object")
    return value


def node_identity(row: dict) -> dict:
    raw = row.get("raw")
    if (not isinstance(raw, str) or not raw or any(c in raw for c in "\r\n")
            or row.get("protocol") not in PROTOCOL_ORDER
            or type(row.get("index")) is not int or row["index"] < 0):
        raise ValueError("Invalid delay input identity")
    node_id = hashlib.sha256(raw.encode()).hexdigest()
    if row.get("node_id") != node_id:
        raise ValueError("Delay input differs from original successful URI")
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
        raise ValueError("Invalid delay pool or measurement policy")
    nodes = [node_identity(row) for row in pool["nodes"]]
    if len({n["node_id"] for n in nodes}) != len(nodes):
        raise ValueError("Delay pool contains duplicate original URIs")
    if len({(n["protocol"], n["index"]) for n in nodes}) != len(nodes):
        raise ValueError("Delay pool contains duplicate source identities")
    pool["nodes"] = nodes
    return pool


def assigned(pool: dict, shard: int) -> list[tuple[int, dict]]:
    if shard not in range(POLICY["shards"]):
        raise ValueError("Invalid delay shard")
    return [(i, row) for i, row in enumerate(pool["nodes"]) if i % POLICY["shards"] == shard]


def validate_sample(sample: dict) -> tuple[int, int, list[dict]]:
    timings = sample.get("samples")
    if sample.get("target") != POLICY["target"] or not isinstance(timings, list) or len(timings) != 2:
        raise ValueError("Real Delay needs both requests to the same authenticated target")
    durations = []
    for item in timings:
        if not isinstance(item, dict):
            raise ValueError("Invalid Real Delay request receipt")
        if any(type(item.get(k)) is not int for k in ("http_status", "bytes", "duration_ns", "delay_ms")):
            raise ValueError("Invalid Real Delay request numbers")
        duration = item["duration_ns"]
        if (not 200 <= item["http_status"] < 300 or item.get("verified_tls") is not True
                or not 0 <= item["bytes"] <= POLICY["max_response_bytes"]
                or not 0 < duration <= POLICY["node_timeout_ms"] * 1_000_000
                or item["delay_ms"] != max(1, duration // 1_000_000)
                or type(item.get("connection_reused")) is not bool):
            raise ValueError("Real Delay lacks a complete, bounded HTTPS response")
        durations.append(duration)
    if sum(durations) + POLICY["interval_ms"] * 1_000_000 > POLICY["node_timeout_ms"] * 1_000_000:
        raise ValueError("Real Delay exceeds the shared node deadline")
    best = min(durations)
    delay = max(1, best // 1_000_000)
    if (type(sample.get("real_delay_ns")) is not int or sample["real_delay_ns"] != best
            or type(sample.get("real_delay_ms")) is not int or sample["real_delay_ms"] != delay):
        raise ValueError("Real Delay must equal the minimum of the two request durations")
    return best, delay, timings


def observation(result: dict | None, row: dict, local_index: int) -> dict:
    record = {"status": "UNMEASURED", "real_delay_ms": 0, "real_delay_ns": 0,
              "samples": [], "code": "DELAY_NOT_COMPLETED"}
    if result is None:
        return record
    if (result.get("index") != local_index or result.get("source") != "nodes.txt"
            or result.get("line") != local_index + 1 or result.get("node_id") != row["node_id"]):
        raise ValueError("Delay result is not for the exact assigned original URI")
    if result.get("connection_key") and row["connection_key"] and result["connection_key"] != row["connection_key"]:
        raise ValueError("Delay core connection differs from the successful connection")
    status = result.get("status")
    if status not in {"MEASURED", "UNMEASURED", "RUNNER_ERROR", "CANCELLED"}:
        raise ValueError("Unexpected delay result status")
    sample = result.get("delay") or {}
    if status != "MEASURED":
        if sample.get("real_delay_ms", 0) != 0 or sample.get("real_delay_ns", 0) != 0:
            raise ValueError("Unmeasured node carries a ranking score")
        record["code"] = str((result.get("failure") or {}).get("code") or "DELAY_UNAVAILABLE")
        return record
    if (result.get("protocol") != row["protocol"] or result.get("network_tested") is not True
            or result.get("failure") or not connection_key(result.get("connection_key"))):
        raise ValueError("Measured delay lacks node/network evidence")
    best, delay, timings = validate_sample(sample)
    return {"status": "MEASURED", "real_delay_ms": delay, "real_delay_ns": best,
            "samples": timings, "code": "OK"}


def apply_ranking(rows: list[dict], pool_path: Path, results_root: Path,
                  core: dict, candidate_hash: str) -> dict:
    pool = load_pool(pool_path)
    if pool["core"] != core or pool.get("candidates_sha256") != candidate_hash:
        raise ValueError("Delay input came from another core or candidate snapshot")
    expected = {row["node_id"]: node_identity(row) for row in rows}
    if expected != {row["node_id"]: row for row in pool["nodes"]}:
        raise ValueError("Delay pool does not match the final deduplicated successful set")
    records = {node["node_id"]: observation(None, node, 0) for node in pool["nodes"]}
    seen_shards = set()
    seen_nodes = set()
    pool_hash = digest(pool_path)
    for path in sorted(results_root.rglob("observations.jsonl")):
        summary = read_json(path.parent / "summary.json")
        shard = summary.get("shard")
        if type(shard) is not int or shard not in range(POLICY["shards"]) or shard in seen_shards:
            raise ValueError("Duplicate or foreign delay shard")
        if (summary.get("schema") != REPORT_SCHEMA or summary.get("policy") != POLICY
                or summary.get("core") != core or summary.get("pool_sha256") != pool_hash):
            raise ValueError("Delay shard provenance or measurement policy mismatch")
        targets = assigned(pool, shard)
        if summary.get("assigned") != len(targets):
            raise ValueError("Delay shard assignment count mismatch")
        by_index = {i: (local, row) for local, (i, row) in enumerate(targets)}
        actual = Counter()
        for line in path.read_text(encoding="utf-8").splitlines():
            entry = json.loads(line)
            index = entry.get("index")
            if type(index) is not int or index not in by_index:
                raise ValueError("Foreign delay observation")
            local, row = by_index[index]
            if entry.get("node_id") != row["node_id"] or row["node_id"] in seen_nodes:
                raise ValueError("Duplicate or mismatched delay observation")
            seen_nodes.add(row["node_id"])
            records[row["node_id"]] = observation(entry.get("measurement"), row, local)
            actual[records[row["node_id"]]["status"]] += 1
        if sum(actual.values()) != len(targets) or summary.get("statuses") != dict(actual):
            raise ValueError("Delay shard observation coverage mismatch")
        seen_shards.add(shard)
    counts = Counter()
    for row in rows:
        record = records[row["node_id"]]
        try:
            latency = float(row.get("http204_ms"))
        except (TypeError, ValueError):
            latency = math.inf
        record["https_latency_ms"] = latency if latency > 0 and math.isfinite(latency) else None
        row["_delay"] = record
        counts[record["status"]] += 1
    summary = {"schema": RANK_SCHEMA, "policy": POLICY, "total_concurrency": 32,
               "pool_sha256": pool_hash, "measured": counts["MEASURED"],
               "unmeasured": counts["UNMEASURED"], "missing_shards": sorted(set(range(8)) - seen_shards),
               "order": "measured Real Delay ms ascending; unmeasured retained by verified HTTPS delay",
               "scope": "minimum of two HTTPS request times from GitHub runners; response latency, not download throughput",
               "eligibility_changed": False}
    return {"schema": RANK_SCHEMA, "summary": summary, "core": core, "nodes": records}


def verify_ranking(document: dict, summary: dict, core: dict, published: list[str], countries: list[Path]) -> None:
    if (document.get("schema") != RANK_SCHEMA or document.get("core") != core
            or document.get("summary") != summary or summary.get("policy") != POLICY
            or summary.get("total_concurrency") != 32 or summary.get("eligibility_changed") is not False):
        raise ValueError("Published delay policy/provenance mismatch")
    records = document.get("nodes")
    expected_ids = {hashlib.sha256(raw.encode()).hexdigest() for raw in published}
    if not isinstance(records, dict) or set(records) != expected_ids:
        raise ValueError("Delay metadata must retain every published original URI")
    counts = Counter()
    for record in records.values():
        status = record.get("status")
        if status not in {"MEASURED", "UNMEASURED"}:
            raise ValueError("Invalid published delay status")
        counts[status] += 1
        delay = record.get("real_delay_ms")
        if type(delay) is not int or (status == "UNMEASURED" and (delay != 0 or record.get("real_delay_ns") != 0)):
            raise ValueError("Invalid published Real Delay score")
        if status == "MEASURED":
            validate_sample(dict(record, target=POLICY["target"]))
    if summary.get("measured") != counts["MEASURED"] or summary.get("unmeasured") != counts["UNMEASURED"]:
        raise ValueError("Published delay accounting mismatch")
    for path in countries:
        keys = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            record = records[hashlib.sha256(raw.encode()).hexdigest()]
            latency = record.get("https_latency_ms")
            if not isinstance(latency, (int, float)) or latency <= 0 or not math.isfinite(latency):
                latency = math.inf
            measured = record["status"] == "MEASURED"
            keys.append((0 if measured else 1, record["real_delay_ms"] if measured else 0, latency))
        if keys != sorted(keys):
            raise ValueError("Country feed is not ordered by ascending Real Delay and fallback response time")
