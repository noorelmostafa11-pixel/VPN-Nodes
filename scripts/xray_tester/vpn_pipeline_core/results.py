from __future__ import annotations

import json
import shutil
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import PREVIOUS_DIR, PROTOCOL_SOURCES, PUBLISHED_DIR, TESTER_SCHEMA, XRAY_VERSION
from .models import TestResult
from .storage import atomic_write_text, node_fingerprint, redact_error, replace_tree, safe_rmtree, write_lines


def validate_completeness(results: list[TestResult], expected_indices: list[int]) -> None:
    if len(results) != len(expected_indices):
        raise RuntimeError(
            f"Incomplete run: results={len(results)} assigned={len(expected_indices)}"
        )
    indexes = [r.index for r in results]
    if len(indexes) != len(set(indexes)):
        raise RuntimeError("Duplicate result indexes detected")
    if sorted(indexes) != sorted(expected_indices):
        raise RuntimeError("Result global-index coverage does not match worker assignment")

def save_role_protocol_results(run_dir: Path, role: str, protocol: str, results: list[TestResult]) -> dict[str, Any]:
    working = [r.raw for r in results if r.ok]
    failed = [r.raw for r in results if not r.ok]
    write_lines(run_dir / f"{role}_working_{protocol}.txt", working)
    write_lines(run_dir / f"{role}_failed_{protocol}.txt", failed)

    private_country_rows = [
        json.dumps({"protocol": r.protocol, "country": r.country, "raw": r.raw}, ensure_ascii=False)
        for r in results if r.ok
    ]
    atomic_write_text(
        run_dir / f"{role}_working_{protocol}_country.jsonl",
        "\n".join(private_country_rows) + ("\n" if private_country_rows else ""),
    )

    detail_rows = []
    for result in results:
        record = asdict(result)
        record.pop("raw", None)
        record.pop("source_raw", None)
        record["node_hash"] = node_fingerprint(result.source_raw or result.raw)
        if result.source_raw:
            record["tested_node_hash"] = node_fingerprint(result.raw)
        record["error"] = redact_error(record.get("error", ""))
        record["country_error"] = redact_error(record.get("country_error", ""))
        detail_rows.append(json.dumps(record, ensure_ascii=False))
    atomic_write_text(
        run_dir / f"{role}_{protocol}_details.jsonl",
        "\n".join(detail_rows) + ("\n" if detail_rows else ""),
    )
    failures = Counter(r.stage for r in results if not r.ok)
    countries = Counter(r.country for r in results if r.ok)
    return {
        "total": len(results),
        "working": len(working),
        "failed": len(failed),
        "failure_stages": dict(failures),
        "countries": dict(countries),
    }

def publish_lkg(run_dir: Path, all_results: dict[str, list[TestResult]], stats: dict[str, Any]) -> tuple[bool, str]:
    total_working = sum(1 for rows in all_results.values() for r in rows if r.ok)

    staged = run_dir / "publish_stage"
    if staged.exists():
        safe_rmtree(staged, run_dir)
    (staged / "protocols").mkdir(parents=True)
    (staged / "countries").mkdir(parents=True)

    country_nodes: dict[str, list[str]] = {}
    for protocol, rows in all_results.items():
        working = [r for r in rows if r.ok]
        working.sort(key=lambda r: r.index)
        filename = "shadowsocks.txt" if protocol == "ss" else f"{protocol}.txt"
        write_lines(staged / "protocols" / filename, [r.raw for r in working])
        for r in working:
            country_nodes.setdefault(r.country or "XX", []).append(r.raw)
    for country, nodes in sorted(country_nodes.items()):
        write_lines(staged / "countries" / f"{country}.txt", nodes)

    published_stats = dict(stats)
    published_stats["published"] = True
    published_stats["publish_reason"] = "accepted"
    published_stats["published_at_utc"] = datetime.now(timezone.utc).isoformat()
    atomic_write_text(staged / "stats.json", json.dumps(published_stats, indent=2, ensure_ascii=False) + "\n")

    if PUBLISHED_DIR.exists() and any(PUBLISHED_DIR.iterdir()):
        previous_stage = run_dir / "previous_stage"
        if previous_stage.exists():
            safe_rmtree(previous_stage, run_dir)
        shutil.copytree(PUBLISHED_DIR, previous_stage)
        replace_tree(PREVIOUS_DIR, previous_stage)
    replace_tree(PUBLISHED_DIR, staged)
    return True, "accepted"

def build_run_id(source_sha: str) -> str:
    return f"s{TESTER_SCHEMA}-xray{XRAY_VERSION.replace('.', '')}-{source_sha[:16]}"

def parse_protocols(value: str) -> list[str]:
    normalized = (value or "").strip().lower()
    if not normalized or normalized == "all":
        return ["vless", "vmess", "trojan", "ss"]
    requested: list[str] = []
    seen: set[str] = set()
    for item in normalized.split(","):
        protocol = item.strip().lower()
        if not protocol or protocol in seen:
            continue
        seen.add(protocol)
        requested.append(protocol)
    if not requested:
        raise ValueError("At least one protocol must be requested")
    unknown = [x for x in requested if x not in PROTOCOL_SOURCES]
    if unknown:
        raise ValueError(f"Unknown protocols: {', '.join(unknown)}")
    return requested
