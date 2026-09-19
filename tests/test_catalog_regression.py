#!/usr/bin/env python3
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from verify_catalog_regression import verify


def write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


with TemporaryDirectory() as tmp:
    base = Path(tmp)
    previous = base / "previous.json"
    current = base / "current.json"
    index = base / "index.json"
    write(previous, {"published_total": 40000})
    write(current, {
        "published_total": 30000,
        "published_country_nodes": 30000,
        "generated_at": "2026-01-01T00:00:00Z",
        "allowed_ports": [443],
    })
    write(index, {
        "published_total": 30000,
        "generated_at": "2026-01-01T00:00:00Z",
        "allowed_ports": [443],
    })
    verify(previous, current, index, minimum_nodes=1000, minimum_ratio=0.5)

    write(current, {
        "published_total": 10000,
        "published_country_nodes": 10000,
        "generated_at": "2026-01-01T00:00:00Z",
        "allowed_ports": [443],
    })
    write(index, {
        "published_total": 10000,
        "generated_at": "2026-01-01T00:00:00Z",
        "allowed_ports": [443],
    })
    # Production disables previous-run ratio gating. A legitimate dedup-policy
    # change may sharply reduce the catalog while remaining internally valid.
    verify(previous, current, index, minimum_nodes=1000, minimum_ratio=0.0)

    # The optional ratio guard still works if explicitly re-enabled.
    try:
        verify(previous, current, index, minimum_nodes=1000, minimum_ratio=0.5)
    except ValueError as exc:
        assert "collapsed versus previous" in str(exc)
    else:
        raise AssertionError("optional ratio guard did not reject a 75% catalog loss")

    # The absolute safety floor remains active even with ratio gating disabled.
    write(current, {
        "published_total": 999,
        "published_country_nodes": 999,
        "generated_at": "2026-01-01T00:00:00Z",
        "allowed_ports": [443],
    })
    write(index, {
        "published_total": 999,
        "generated_at": "2026-01-01T00:00:00Z",
        "allowed_ports": [443],
    })
    try:
        verify(previous, current, index, minimum_nodes=1000, minimum_ratio=0.0)
    except ValueError as exc:
        assert "collapsed below minimum" in str(exc)
    else:
        raise AssertionError("absolute catalog floor did not reject 999 nodes")

print("OK catalog regression guard")
