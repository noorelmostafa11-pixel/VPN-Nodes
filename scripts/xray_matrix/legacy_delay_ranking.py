"""Read-only validation of previously published Real Delay catalogs."""
import hashlib
import math
from collections import Counter
from pathlib import Path

POLICY = {'target': 'https://www.google.com/generate_204', 'attempts_per_node': 2, 'interval_ms': 100, 'max_response_bytes': 65536, 'workers': 4, 'shards': 8, 'node_timeout_ms': 5000}
RANK_SCHEMA = 'vpn-country-delay-ranking-v1'

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
