#!/usr/bin/env python3
"""Run one of ten GitHub matrix shards with the server-identical tester core."""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
TESTER_ROOT = ROOT / "scripts" / "xray_tester"
if str(TESTER_ROOT) not in sys.path:
    sys.path.insert(0, str(TESTER_ROOT))

PROTOCOL_ORDER = ("vless", "vmess", "trojan", "ss")
PUBLIC_TO_TESTER = {"vless": "vless", "vmess": "vmess", "trojan": "trojan", "shadowsocks": "ss"}


def require_secret_url(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"Required GitHub Actions secret {name} is not configured")
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise SystemExit(f"{name} must contain a valid HTTPS URL")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--shards", type=int, default=10)
    args = parser.parse_args()

    if args.shards != 10:
        raise SystemExit("Production GitHub matrix is fixed at exactly 10 shards")
    if args.shard < 0 or args.shard >= args.shards:
        raise SystemExit("Invalid shard index")

    # Validate secrets before importing config.  Values are intentionally never
    # printed, and the workflow also registers explicit log masks.
    require_secret_url("VPN_TEST_URL")
    require_secret_url("VPN_COUNTRY_URL")

    from vpn_pipeline_core import config  # noqa: E402
    from vpn_pipeline_core.results import validate_completeness  # noqa: E402
    from vpn_pipeline_core.storage import prepare_dirs  # noqa: E402
    from vpn_pipeline_core.testing import run_protocol_role  # noqa: E402
    from vpn_pipeline_core.xray_binary import find_xray  # noqa: E402

    if config.WORKERS != 40:
        raise SystemExit(f"Tester worker count changed unexpectedly: {config.WORKERS}")
    if not config.REAL_PING_URL or not config.COUNTRY_URL:
        raise SystemExit("Secret endpoint configuration was not loaded by tester core")

    payload = json.loads(args.input.read_text(encoding="utf-8"))
    rows = payload.get("nodes")
    if not isinstance(rows, list):
        raise SystemExit("Invalid xray_candidates.json")

    grouped: dict[str, list[dict]] = {name: [] for name in PROTOCOL_ORDER}
    for row in rows:
        public_protocol = str(row.get("protocol") or "").lower()
        protocol = PUBLIC_TO_TESTER.get(public_protocol)
        if protocol is None:
            raise SystemExit(f"Unexpected protocol: {public_protocol!r}")
        grouped[protocol].append(row)

    prepare_dirs()
    xray = find_xray()
    run_dir = ROOT / "xray-work" / f"shard-{args.shard:02d}"
    run_dir.mkdir(parents=True, exist_ok=True)
    args.output.mkdir(parents=True, exist_ok=True)

    summary = {
        "schema": 1,
        "shard": args.shard,
        "shards": args.shards,
        "workers": config.WORKERS,
        "protocols": {},
    }
    working_records: list[dict] = []

    for protocol in PROTOCOL_ORDER:
        all_protocol_rows = grouped[protocol]
        indexed = [(index, str(row.get("uri") or "")) for index, row in enumerate(all_protocol_rows)]
        assigned = [(index, raw) for index, raw in indexed if index % args.shards == args.shard]
        role = f"shard{args.shard:02d}"
        results = run_protocol_role(protocol, role, assigned, xray, run_dir, "github-matrix")
        validate_completeness(results, [index for index, _ in assigned])

        failures = Counter(r.stage for r in results if not r.ok)
        working = [r for r in results if r.ok]
        summary["protocols"][protocol] = {
            "source_total": len(all_protocol_rows),
            "assigned": len(assigned),
            "tested": len(results),
            "working": len(working),
            "failed": len(results) - len(working),
            "failure_stages": dict(sorted(failures.items())),
        }

        for result in working:
            record = asdict(result)
            # Keep only successful publication data. Failed raw nodes are not
            # uploaded as artifacts; aggregate coverage is proven by summaries.
            # Diagnostic strings are unnecessary for publication and are removed
            # so a public artifact cannot disclose either secret endpoint.
            record.pop("error", None)
            record.pop("country_error", None)
            record["shard"] = args.shard
            working_records.append(record)

    working_records.sort(key=lambda row: (PROTOCOL_ORDER.index(str(row["protocol"])), int(row["index"])))
    with (args.output / "working.jsonl").open("w", encoding="utf-8") as stream:
        for row in working_records:
            stream.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    (args.output / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    total_tested = sum(v["tested"] for v in summary["protocols"].values())
    total_working = sum(v["working"] for v in summary["protocols"].values())
    print(
        f"OK shard={args.shard}/{args.shards} tested={total_tested} "
        f"working={total_working} workers={config.WORKERS}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
