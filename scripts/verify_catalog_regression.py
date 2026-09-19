#!/usr/bin/env python3
"""Reject an unexpectedly collapsed or internally inconsistent app catalog."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def _load(path: Path) -> dict:
    if not path.is_file():
        raise ValueError(f"missing catalog metadata: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"invalid catalog metadata: {path}")
    return payload


def verify(
    previous_path: Path,
    current_path: Path,
    index_path: Path,
    *,
    minimum_nodes: int = 1000,
    minimum_ratio: float = 0.5,
) -> None:
    current = _load(current_path)
    previous = _load(previous_path) if previous_path.is_file() else {}
    legacy = _load(index_path)

    current_total = int(current.get("published_total") or 0)
    previous_total = int(previous.get("published_total") or 0)
    if current_total < minimum_nodes:
        raise ValueError(
            f"catalog collapsed below minimum: current={current_total} minimum={minimum_nodes}"
        )
    if previous_total and current_total < int(previous_total * minimum_ratio):
        raise ValueError(
            f"catalog collapsed versus previous: current={current_total} "
            f"previous={previous_total} minimum_ratio={minimum_ratio}"
        )

    country_total = int(current.get("published_country_nodes") or 0)
    if country_total != current_total:
        raise ValueError(
            f"app_pool totals disagree: published_total={current_total} country_nodes={country_total}"
        )
    if legacy.get("generated_at") != current.get("generated_at"):
        raise ValueError("legacy index generated_at does not match app_pool")
    if int(legacy.get("published_total") or 0) != current_total:
        raise ValueError("legacy index published_total does not match app_pool")
    if legacy.get("allowed_ports") != current.get("allowed_ports"):
        raise ValueError("legacy index allowed_ports does not match app_pool")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--previous", type=Path, default=Path("/tmp/previous_app_pool.json"))
    parser.add_argument("--current", type=Path, default=Path("output/metadata/app_pool.json"))
    parser.add_argument("--index", type=Path, default=Path("output/metadata/index.json"))
    args = parser.parse_args()
    verify(
        args.previous,
        args.current,
        args.index,
        minimum_nodes=int(os.environ.get("CATALOG_MIN_PUBLISHED_NODES", "1000")),
        minimum_ratio=float(os.environ.get("CATALOG_MIN_PREVIOUS_RATIO", "0.5")),
    )
    print("OK catalog regression guard")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
