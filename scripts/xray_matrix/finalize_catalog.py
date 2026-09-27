#!/usr/bin/env python3
"""Merge ten Xray shards and publish a signed-catalog-ready output tree.

Country authority order is strict:
1. Country returned through the working node by the private country endpoint.
2. ONLY when that value is XX, local GeoLite2 is used as a fallback.
3. If GeoLite2 cannot classify it, XX is preserved.

The public repository's old all-node country resolver is intentionally not run.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import country_resolver  # noqa: E402

PROTOCOL_ORDER = ("vless", "vmess", "trojan", "ss")
PUBLIC_PROTOCOL = {"vless": "vless", "vmess": "vmess", "trojan": "trojan", "shadowsocks": "ss"}
PROTOCOL_FILENAME = {"vless": "vless.txt", "vmess": "vmess.txt", "trojan": "trojan.txt", "ss": "shadowsocks.txt"}
COUNTRY_SHARD_SIZE = 1000
COUNTRY_SHARD_MAX_BYTES = 4 * 1024 * 1024


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def write_lines(path: Path, values: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(values) + ("\n" if values else ""), encoding="utf-8")


def fallback_country_for_xx(row: dict) -> str:
    host = str(row.get("host") or "").strip().strip("[]")
    if not host:
        return "XX"
    ip = country_resolver.resolve_ip(host)
    if not ip:
        return "XX"
    code = country_resolver.country_from_ip(ip)
    value = str(code or "").upper()
    return value if re.fullmatch(r"[A-Z]{2}", value) else "XX"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--source-freshness", type=Path, required=True)
    parser.add_argument("--cache-root", type=Path)
    args = parser.parse_args()

    candidates = read_json(args.candidates)
    candidate_rows = candidates.get("nodes")
    if not isinstance(candidate_rows, list) or not candidate_rows:
        raise SystemExit("Candidate pool is empty or invalid")

    expected_by_protocol = Counter()
    candidates_by_identity: dict[tuple[str, int], dict] = {}
    protocol_offsets = Counter()
    for row in candidate_rows:
        public = str(row.get("protocol") or "").lower()
        protocol = PUBLIC_PROTOCOL.get(public)
        if protocol is None:
            raise SystemExit(f"Unexpected candidate protocol: {public!r}")
        protocol_index = protocol_offsets[protocol]
        protocol_offsets[protocol] += 1
        expected_by_protocol[protocol] += 1
        candidates_by_identity[(protocol, protocol_index)] = row

    summary_paths = sorted(args.results_root.rglob("summary.json"))
    working_paths = sorted(args.results_root.rglob("working.jsonl"))
    if len(summary_paths) != 10 or len(working_paths) != 10:
        raise SystemExit(
            f"Expected exactly 10 shard artifacts, got summaries={len(summary_paths)} working={len(working_paths)}"
        )

    summaries = [read_json(path) for path in summary_paths]
    shard_ids = sorted(int(item.get("shard", -1)) for item in summaries)
    if shard_ids != list(range(10)):
        raise SystemExit(f"Shard coverage mismatch: {shard_ids}")
    if any(int(item.get("shards", 0)) != 10 or int(item.get("workers", 0)) != 40 for item in summaries):
        raise SystemExit("Unexpected matrix size or tester worker count")

    tested_by_protocol = Counter()
    assigned_by_protocol = Counter()
    working_summary_by_protocol = Counter()
    failure_stages: dict[str, Counter] = {p: Counter() for p in PROTOCOL_ORDER}
    for summary in summaries:
        protocols = summary.get("protocols")
        if not isinstance(protocols, dict):
            raise SystemExit("Invalid shard protocol summary")
        for protocol in PROTOCOL_ORDER:
            row = protocols.get(protocol)
            if not isinstance(row, dict):
                raise SystemExit(f"Missing {protocol} shard summary")
            assigned_by_protocol[protocol] += int(row.get("assigned", -1))
            tested_by_protocol[protocol] += int(row.get("tested", -1))
            working_summary_by_protocol[protocol] += int(row.get("working", -1))
            failure_stages[protocol].update(row.get("failure_stages") or {})

    for protocol in PROTOCOL_ORDER:
        expected = expected_by_protocol[protocol]
        if assigned_by_protocol[protocol] != expected or tested_by_protocol[protocol] != expected:
            raise SystemExit(
                f"Incomplete matrix coverage for {protocol}: expected={expected} "
                f"assigned={assigned_by_protocol[protocol]} tested={tested_by_protocol[protocol]}"
            )

    working: list[dict] = []
    identities: set[tuple[str, int]] = set()
    for path in working_paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict) or row.get("ok") is not True:
                raise SystemExit(f"Invalid working row in {path}")
            protocol = str(row.get("protocol") or "").lower()
            index = int(row.get("index", -1))
            shard = int(row.get("shard", -1))
            if protocol not in PROTOCOL_ORDER or index < 0 or shard != index % 10:
                raise SystemExit(f"Invalid working identity: {protocol}/{index}/shard={shard}")
            identity = (protocol, index)
            if identity in identities:
                raise SystemExit(f"Duplicate working identity: {protocol}/{index}")
            identities.add(identity)
            country = str(row.get("country") or "XX").upper()
            if not re.fullmatch(r"[A-Z]{2}", country):
                raise SystemExit(f"Invalid endpoint country: {country!r}")
            candidate = candidates_by_identity.get(identity)
            if candidate is None:
                raise SystemExit(f"Working identity missing from candidates: {protocol}/{index}")
            row["country"] = country
            # Preserve the public repository's established per-country ordering:
            # measured TCP latency ascending, with the same deterministic
            # tie-break fields used by build_tcp_pool.publish_app_pool().
            row["candidate_latency_ms"] = candidate.get("latency_ms")
            row["candidate_source"] = str(candidate.get("source") or "")
            working.append(row)

    actual_working = Counter(str(row["protocol"]) for row in working)
    for protocol in PROTOCOL_ORDER:
        if actual_working[protocol] != working_summary_by_protocol[protocol]:
            raise SystemExit(
                f"Working artifact mismatch for {protocol}: "
                f"summary={working_summary_by_protocol[protocol]} rows={actual_working[protocol]}"
            )
    if not working:
        raise SystemExit("Refusing to publish an empty Xray-verified catalog")

    # Endpoint country is authoritative.  GeoLite2 sees ONLY successful XX rows.
    xx_rows = [row for row in working if str(row.get("country") or "XX").upper() == "XX"]
    classified = 0
    if xx_rows:
        with ThreadPoolExecutor(max_workers=64) as pool:
            fallback_codes = list(pool.map(fallback_country_for_xx, xx_rows))
        for row, code in zip(xx_rows, fallback_codes):
            if code != "XX":
                row["country"] = code
                classified += 1
    geoip_summary = {
        "provider": "GeoLite2-Country",
        "scope": "working_xx_only",
        "attempted": len(xx_rows),
        "classified": classified,
        "unresolved": len(xx_rows) - classified,
    }
    endpoint_assigned = len(working) - len(xx_rows)
    xray_working_total = len(working)

    # Match the established worker publication rule: only literal raw equality
    # is a duplicate. Never collapse nodes merely because endpoint/host/config
    # fields look semantically similar.
    deduped: list[dict] = []
    seen_raw: set[str] = set()
    for row in sorted(working, key=lambda item: (PROTOCOL_ORDER.index(str(item["protocol"])), int(item["index"]))):
        raw = str(row.get("raw") or "")
        if raw in seen_raw:
            continue
        seen_raw.add(raw)
        deduped.append(row)
    exact_duplicates_removed = len(working) - len(deduped)
    working = deduped

    output = ROOT / "output"
    metadata = output / "metadata"
    for name in ("countries", "country_shards", "protocols", "active", "backup"):
        path = output / name
        if path.exists():
            shutil.rmtree(path)
    for path in (output / "countries", output / "country_shards", output / "protocols", metadata):
        path.mkdir(parents=True, exist_ok=True)

    # Preserve current source-freshness state and source adapter caches generated
    # in the candidate job, without publishing candidate/failed raw-node pools.
    shutil.copy2(args.source_freshness, metadata / "source_freshness.json")
    if args.cache_root and args.cache_root.is_dir():
        for cache in args.cache_root.glob("*_cache.json"):
            shutil.copy2(cache, metadata / cache.name)

    for transient in ("tcp_reachable.json", "xray_candidates.json", "merged_pool.json"):
        (metadata / transient).unlink(missing_ok=True)

    working.sort(key=lambda row: (PROTOCOL_ORDER.index(str(row["protocol"])), int(row["index"])))
    protocol_groups: dict[str, list[dict]] = {p: [] for p in PROTOCOL_ORDER}
    country_groups: dict[str, list[dict]] = {}
    for row in working:
        protocol = str(row["protocol"])
        protocol_groups[protocol].append(row)
        country_groups.setdefault(str(row["country"]), []).append(row)

    for protocol in PROTOCOL_ORDER:
        write_lines(output / "protocols" / PROTOCOL_FILENAME[protocol], [str(row["raw"]) for row in protocol_groups[protocol]])

    try:
        import pycountry
    except ImportError as exc:
        raise SystemExit("pycountry is required by the repository requirements") from exc

    countries_meta: list[dict] = []
    published_shards = 0
    for country in sorted(country_groups):
        rows = country_groups[country]
        rows.sort(key=lambda row: (
            float(row.get("candidate_latency_ms") if row.get("candidate_latency_ms") is not None else 10**9),
            str(row.get("protocol") or ""),
            str(row.get("candidate_source") or ""),
            str(row.get("raw") or ""),
        ))
        uris = [str(row["raw"]) for row in rows]
        write_lines(output / "countries" / f"{country}.txt", uris)
        shard_dir = output / "country_shards" / country
        shard_count = 0
        for shard_index, start in enumerate(range(0, len(uris), COUNTRY_SHARD_SIZE)):
            chunk = uris[start:start + COUNTRY_SHARD_SIZE]
            data = ("\n".join(chunk) + "\n").encode("utf-8")
            if len(data) > COUNTRY_SHARD_MAX_BYTES:
                raise SystemExit(f"Country shard too large: {country}/{shard_index:03d}")
            shard_dir.mkdir(parents=True, exist_ok=True)
            (shard_dir / f"{shard_index:03d}.txt").write_bytes(data)
            shard_count += 1
        published_shards += shard_count
        match = pycountry.countries.get(alpha_2=country)
        countries_meta.append({
            "code": country,
            "name": str(match.name) if match is not None else country,
            "nodes": len(uris),
            "active": 0,
            "backup": len(uris),
            "shards": shard_count,
            "shard_size": COUNTRY_SHARD_SIZE,
            "shard_path": f"output/country_shards/{country}",
        })

    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    source_freshness = candidates.get("source_freshness") or {}
    sources = candidates.get("sources") or []
    total = len(working)
    protocol_counts = {p: len(protocol_groups[p]) for p in PROTOCOL_ORDER}
    country_counts = {country: len(rows) for country, rows in sorted(country_groups.items())}

    countries_payload = {
        "schema": 2,
        "generated_at": generated_at,
        "shard_size": COUNTRY_SHARD_SIZE,
        "countries": countries_meta,
    }
    (metadata / "countries.json").write_text(
        json.dumps(countries_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    test_summary = {}
    for protocol in PROTOCOL_ORDER:
        tested = tested_by_protocol[protocol]
        succeeded = working_summary_by_protocol[protocol]
        test_summary[protocol] = {
            "source_total": expected_by_protocol[protocol],
            "tested": tested,
            "working": succeeded,
            "failed": tested - succeeded,
            "published_after_exact_dedup": protocol_counts[protocol],
            "failure_stages": dict(sorted(failure_stages[protocol].items())),
        }

    app_pool = {
        "schema": 23,
        "generated_at": generated_at,
        "mode": "xray_26_9_9_real_https_verified",
        "liveness_test": "existing public TCP pool followed by server-identical Xray real HTTPS test",
        "final_runtime_test": "Xray 26.9.9 + one verified HTTPS response",
        "xray_matrix_shards": 10,
        "xray_workers_per_runner": 40,
        "xray_total_concurrency": 400,
        "country_policy": "endpoint_first; GeoLite2 only for successful XX",
        "country_shard_size": COUNTRY_SHARD_SIZE,
        "country_shards_generated": True,
        "published_country_shards": published_shards,
        "tcp_reachable_total": len(candidate_rows),
        "xray_tested_total": sum(tested_by_protocol.values()),
        "xray_working_total": xray_working_total,
        "exact_duplicate_raw_removed_after_xray": exact_duplicates_removed,
        "endpoint_country_assigned": endpoint_assigned,
        "geoip_xx_fallback": geoip_summary,
        "published_country_nodes": total,
        "published_total": total,
        "protocols": protocol_counts,
        "countries": country_counts,
        "source_failures": sum(1 for row in sources if not row.get("ok")),
        "source_freshness": source_freshness,
        "sources": sources,
        "test_summary": test_summary,
    }
    (metadata / "app_pool.json").write_text(
        json.dumps(app_pool, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    legacy_index = {
        "schema": 10,
        "generated_at": generated_at,
        "tcp_reachable_total": len(candidate_rows),
        "xray_included": total,
        "config_conversion_failed": sum(
            failure_stages[p].get("source_invalid", 0) + failure_stages[p].get("unsupported", 0)
            for p in PROTOCOL_ORDER
        ),
        "active": 0,
        "backup": total,
        "failed_after_core": sum(tested_by_protocol.values()) - total,
        "healthy": total,
        "published_total": total,
        "countries": len(country_groups),
        "published_by_country": {
            country: {"active": 0, "backup": count, "total": count}
            for country, count in country_counts.items()
        },
        "country_names": {item["code"]: item["name"] for item in countries_meta},
        "health_policy": "Xray 26.9.9 real HTTPS success required before publication.",
        "country_policy": "country endpoint first; GeoLite2 fallback only for successful XX nodes",
        "geoip_xx_fallback": geoip_summary,
        "test_summary": test_summary,
    }
    (metadata / "index.json").write_text(
        json.dumps(legacy_index, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(
        f"OK FINAL tested={sum(tested_by_protocol.values())} xray_working={xray_working_total} "
        f"published={total} exact_duplicates_removed={exact_duplicates_removed} "
        f"endpoint_country={endpoint_assigned} xx_geoip_attempted={len(xx_rows)} "
        f"xx_geoip_classified={classified} xx_remaining={len(xx_rows)-classified} "
        f"countries={len(country_groups)} shards={published_shards}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
