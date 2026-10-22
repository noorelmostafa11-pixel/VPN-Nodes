#!/usr/bin/env python3
"""Feed exact source links to VPN-Core-Test's production nodecheck command."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import subprocess
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit
from owned_core import (MATRIX_SHARDS, WORKERS, PROTOCOL_ORDER, PUBLIC_PROTOCOL,
                        TARGET_LABELS, connection_key, digest, read_json, verified_attempt, verify_binary,
                        verify_prepared_input)


def assign(rows: list[dict], shard: int, shards: int) -> list[tuple[str, int, dict]]:
    grouped: dict[str, list[dict]] = {p: [] for p in PROTOCOL_ORDER}
    for row in rows:
        protocol = PUBLIC_PROTOCOL.get(str(row.get("protocol", "")).lower())
        raw = row.get("uri")
        # NUL is safe in this byte-preserving line/JSON handoff. Leave invalid
        # URI controls to the core so one bad source cannot abort every shard.
        # CR/LF remain framing errors: they would create additional input lines.
        if protocol is None or not isinstance(raw, str) or not raw or any(c in raw for c in "\r\n"):
            raise ValueError("Invalid four-protocol candidate row")
        grouped[protocol].append(row)
    return [(p, i, row) for p in PROTOCOL_ORDER for i, row in enumerate(grouped[p]) if i % shards == shard]


def convert_results(report_dir: Path, assigned: list[tuple[str, int, dict]], manifest: dict) -> tuple[list[dict], dict]:
    summary = read_json(report_dir / "summary.json")
    count = len(assigned)
    if (summary.get("schema") != "xray-node-connectivity-v1"
            or summary.get("completed") is not True or summary.get("runner_errors") != 0
            or any(summary.get(k) != count for k in ("inventory", "selected", "finished"))
            or summary.get("shard") != 0 or summary.get("shards") != 1
            or summary.get("revision") != manifest["revision"]
            or summary.get("binary_sha256") != manifest["binary_sha256"]
            or set(summary.get("targets", [])) != set(TARGET_LABELS)
            or summary.get("workers") != WORKERS
            or summary.get("node_timeout_ms") != 6000 or summary.get("attempt_timeout_ms") != 2000
            or summary.get("exit_metadata_enabled") is not True or summary.get("metadata_timeout_ms") != 4000
            or summary.get("input_sha256") != {"nodes.txt": digest(report_dir.parent / "nodes.txt")}):
        raise ValueError("Core report provenance, options or completeness mismatch")
    counts = {p: {"assigned": 0, "tested": 0, "working": 0, "failed": 0,
                  "success_endpoints": Counter(), "failure_stages": Counter()} for p in PROTOCOL_ORDER}
    for protocol, _, _ in assigned:
        counts[protocol]["assigned"] += 1
    seen: set[int] = set()
    working = []
    statuses: Counter = Counter()
    with (report_dir / "results.jsonl").open(encoding="utf-8") as stream:
        for line in stream:
            result = json.loads(line)
            index = result.get("index")
            if not isinstance(index, int) or index not in range(count) or index in seen:
                raise ValueError("Missing, duplicate or foreign core result identity")
            seen.add(index)
            protocol, protocol_index, candidate = assigned[index]
            raw = candidate["uri"]
            node_id = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            if result.get("node_id") != node_id or result.get("source") != "nodes.txt" or result.get("line") != index + 1:
                raise ValueError("Core did not test the exact candidate link")
            status = result.get("status")
            if status not in {"PASS", "FAIL", "REJECTED"}:
                raise ValueError("Incomplete checker run; refusing publication")
            statuses[status] += 1
            stats = counts[protocol]
            stats["tested"] += 1
            if status != "PASS":
                stats["failed"] += 1
                stats["failure_stages"][(result.get("failure") or {}).get("code", status)] += 1
                continue
            if result.get("protocol") != protocol or result.get("network_tested") is not True:
                raise ValueError("Successful node protocol/evidence mismatch")
            attempt = verified_attempt(result)
            endpoint = TARGET_LABELS[attempt["target"]]
            stats["working"] += 1
            stats["success_endpoints"][endpoint] += 1
            metadata = result.get("exit_metadata") or {}
            country = str(metadata.get("country") or "XX").upper()
            if not re.fullmatch(r"[A-Z]{2}", country):
                raise ValueError("Invalid exit country")
            working.append({"protocol": protocol, "index": protocol_index, "raw": raw,
                            "host": candidate.get("host", ""), "port": candidate.get("port", 0),
                            "ok": True, "stage": "ok", "country": country,
                            "exit_ip": metadata.get("ip", ""), "http204_ms": attempt["duration_ms"],
                            "success_endpoint": endpoint, "node_id": node_id,
                            "connection_key": connection_key(result.get("connection_key"))})
    if len(seen) != count or dict(statuses) != {k: v for k, v in summary.get("statuses", {}).items() if v}:
        raise ValueError("Core observation coverage/count mismatch")
    return working, counts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--core-manifest", type=Path, required=True)
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--shards", type=int, default=MATRIX_SHARDS)
    args = parser.parse_args()
    if args.shards != MATRIX_SHARDS or args.shard not in range(args.shards):
        raise ValueError("Invalid production checker shard")
    manifest = read_json(args.core_manifest)
    verify_binary(args.core, manifest)
    country_url = os.environ.get("VPN_NODECHECK_COUNTRY_URL", "").strip()
    parsed = urlsplit(country_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("VPN_COUNTRY_URL must configure a valid HTTPS country service")
    snapshot = read_json(args.input)
    verify_prepared_input(snapshot, manifest)
    rows = snapshot.get("nodes")
    if not isinstance(rows, list) or not rows:
        raise ValueError("Candidate snapshot is empty or invalid")
    assigned = assign(rows, args.shard, args.shards)
    if args.output.exists() and any(args.output.iterdir()):
        raise ValueError("Shard output must be empty")
    args.output.mkdir(parents=True, exist_ok=True)
    input_file = args.output / "nodes.txt"
    input_file.write_bytes("".join(row["uri"] + "\n" for _, _, row in assigned).encode("utf-8"))
    try:
        if assigned:
            environment = dict(os.environ)
            environment["VPN_NODECHECK_EXIT_IP_URL"] = "https://api64.ipify.org?format=json"
            subprocess.run([str(args.core.resolve()), "nodecheck", "-input", str(input_file.resolve()),
                            "-output", str((args.output / "nodecheck").resolve()), "-workers", str(WORKERS),
                            "-node-timeout", "6s", "-attempt-timeout", "2s", "-metadata-timeout", "4s"],
                           check=True, env=environment)
            working, counts = convert_results(args.output / "nodecheck", assigned, manifest)
        else:
            working = []
            counts = {p: {"assigned": 0, "tested": 0, "working": 0, "failed": 0,
                          "success_endpoints": {}, "failure_stages": {}} for p in PROTOCOL_ORDER}
    finally:
        input_file.unlink(missing_ok=True)
    for row in working:
        row["shard"] = args.shard
    with (args.output / "working.jsonl").open("w", encoding="utf-8", newline="\n") as stream:
        for row in working:
            stream.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    summary = {"schema": 2, "shard": args.shard, "shards": args.shards, "workers": WORKERS,
               "core": manifest, "candidates_sha256": digest(args.input), "protocols": counts}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"OK owned-core shard={args.shard}/{args.shards} tested={len(assigned)} working={len(working)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
