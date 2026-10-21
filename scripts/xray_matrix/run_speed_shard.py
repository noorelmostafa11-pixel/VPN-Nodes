#!/usr/bin/env python3
"""Run VPN-Nodes' helper linked to the pinned, unchanged core library."""
from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from pathlib import Path

from owned_core import digest, verify_binary
from speed_ranking import POLICY, REPORT_SCHEMA, assigned, load_pool, observation, read_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pool", type=Path, required=True)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--tool", type=Path, required=True)
    parser.add_argument("--core-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--shard", type=int, required=True)
    args = parser.parse_args()
    pool = load_pool(args.pool)
    manifest = read_json(args.core_manifest)
    if manifest != pool["core"]:
        raise ValueError("Speed phase must reuse this run's exact core build")
    verify_binary(args.core, manifest)
    if (manifest.get("speed_core_revision") != manifest["revision"]
            or manifest.get("speed_binary_sha256") != digest(args.tool)):
        raise ValueError("Speed helper is not linked to this run's pinned core build")
    targets = assigned(pool, args.shard)
    args.output.mkdir(parents=True, exist_ok=False)
    nodes = args.output / "nodes.txt"
    results = {}
    returncode = 0
    try:
        if targets:
            nodes.write_bytes(('\n'.join(row['raw'] for _, row in targets) + '\n').encode())
            report = args.output / "core-report"
            completed = subprocess.run([str(args.tool.resolve()), "-input", str(nodes.resolve()),
                                        "-output", str(report.resolve()), "-workers", "4", "-node-timeout", "8s",
                                        "-primary-timeout", "5s", "-target", POLICY["target"],
                                        "-fallback-target", POLICY["fallback_target"]], check=False)
            returncode = completed.returncode
            summary_path = report / "summary.json"
            if summary_path.is_file():
                summary = read_json(summary_path)
                if (summary.get("schema") != "xray-node-speed-v1" or summary.get("revision") != manifest["revision"]
                        or summary.get("binary_sha256") != manifest["speed_binary_sha256"]
                        or summary.get("tool_revision") != manifest.get("speed_tool_revision")
                        or summary.get("input_sha256") != {"nodes.txt": digest(nodes)}
                        or summary.get("inventory") != len(targets) or summary.get("workers") != 4
                        or summary.get("sample_bytes") != POLICY["sample_bytes"] or summary.get("target") != POLICY["target"]
                        or summary.get("fallback_target") != POLICY["fallback_target"]
                        or summary.get("primary_timeout_ms") != POLICY["primary_timeout_ms"]
                        or summary.get("node_timeout_ms") != POLICY["node_timeout_ms"]):
                    raise ValueError("Speed command provenance/options mismatch")
                actual = Counter()
                for line in (report / "results.jsonl").read_text(encoding="utf-8").splitlines():
                    result = json.loads(line)
                    index = result.get("index")
                    if type(index) is not int or index not in range(len(targets)) or index in results:
                        raise ValueError("Foreign or duplicate speed result")
                    observation(result, targets[index][1], index)
                    results[index] = result
                    actual[result["status"]] += 1
                if summary.get("finished") != len(results) or summary.get("statuses") != dict(actual):
                    raise ValueError("Speed command result accounting mismatch")
                if summary.get("completed") is True and (returncode != 0 or len(results) != len(targets)):
                    raise ValueError("Incomplete speed command claims completion")
    finally:
        nodes.unlink(missing_ok=True)
    counts = Counter()
    with (args.output / "observations.jsonl").open("w", encoding="utf-8") as stream:
        for local, (index, row) in enumerate(targets):
            result = results.get(local)
            counts[observation(result, row, local)["status"]] += 1
            stream.write(json.dumps({"index": index, "node_id": row["node_id"], "measurement": result}) + '\n')
    summary = {"schema": REPORT_SCHEMA, "core": manifest, "policy": POLICY, "pool_sha256": digest(args.pool),
               "shard": args.shard, "assigned": len(targets), "statuses": dict(counts), "core_exit_code": returncode}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + '\n', encoding="utf-8")
    print(f"SPEED shard={args.shard} assigned={len(targets)} measured={counts['MEASURED']} unmeasured={counts['UNMEASURED']}")
    if returncode != 0:
        print("::warning::Speed command did not complete; successful nodes remain eligible without a speed score")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
