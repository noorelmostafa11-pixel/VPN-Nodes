"""Read-only verification of already-published legacy download-score catalogs."""
import hashlib
import math
from collections import Counter

from pathlib import Path

POLICY = {"target": "https://speed.cloudflare.com/__down?bytes=1048576", "sample_bytes": 1048576, "workers": 4, "shards": 8, "node_timeout_ms": 8000}
RANK_SCHEMA = "vpn-country-speed-ranking-v1"

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
