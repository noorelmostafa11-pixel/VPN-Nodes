#!/usr/bin/env python3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import source_freshness


def row_uri(source: str, uri: str) -> dict:
    return {
        "source": source,
        "uri": uri,
        "protocol": "vless",
        "host": "example.com",
        "port": 443,
    }


BASE = (
    "vless://11111111-1111-1111-1111-111111111111@example.com:443"
    "?security=tls&type=ws&fp=chrome#test"
)

with TemporaryDirectory() as tmp:
    state = Path(tmp) / "source_freshness.json"
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    health = [
        {"name": "source-a", "ok": True, "nodes": 1},
        {"name": "source-b", "ok": True, "nodes": 1},
    ]

    active, annotated, summary = source_freshness.apply_source_freshness(
        [row_uri("source-a", BASE), row_uri("source-b", BASE)],
        health,
        state,
        max_stale_hours=72,
        now=started,
    )
    assert len(active) == 1
    assert summary["duplicate_sources"] == 1
    assert next(x for x in annotated if x["name"] == "source-b")["duplicate_of"] == "source-a"

    active, _, summary = source_freshness.apply_source_freshness(
        [row_uri("source-a", BASE), row_uri("source-b", BASE)],
        health,
        state,
        max_stale_hours=72,
        now=started + timedelta(hours=73),
    )
    assert not active
    assert summary["stale_sources"] == 2

    changed = BASE.replace(
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
    )
    active, annotated, summary = source_freshness.apply_source_freshness(
        [row_uri("source-a", BASE), row_uri("source-b", changed)],
        health,
        state,
        max_stale_hours=72,
        now=started + timedelta(hours=74),
    )
    assert len(active) == 1 and active[0]["source"] == "source-b"
    b = next(x for x in annotated if x["name"] == "source-b")
    assert b["competition_active"] is True
    assert b["freshness_reason"] == "changed"
    assert summary["active_sources"] == 1

with TemporaryDirectory() as tmp:
    state = Path(tmp) / "source_freshness.json"
    started = datetime(2026, 1, 2, tzinfo=timezone.utc)
    health = [
        {"name": "source-a", "ok": True, "nodes": 1},
        {"name": "source-b", "ok": True, "nodes": 1},
    ]
    variant = BASE.replace("fp=chrome", "fp=firefox")
    active, annotated, summary = source_freshness.apply_source_freshness(
        [row_uri("source-a", BASE), row_uri("source-b", variant)],
        health,
        state,
        max_stale_hours=72,
        now=started,
    )
    assert len(active) == 2
    assert summary["duplicate_sources"] == 0
    assert all(x["duplicate_of"] is None for x in annotated)

print("OK 72-hour source freshness with exact-URI mirror detection")
