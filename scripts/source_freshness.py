#!/usr/bin/env python3
"""Track semantic source freshness without stopping source monitoring.

Every source is collected on every run. A source is allowed to compete when its
semantic node set changed within the configured window. Stale and exact-mirror
sources stay monitored and automatically become eligible when their content
changes.
"""
from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import node_identity

DEFAULT_MAX_STALE_HOURS = 72


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_iso(value: object, fallback: datetime) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return fallback


def _fingerprint(rows: list[dict]) -> tuple[str, int]:
    identities = sorted({
        node_identity.dedup_key(str(row.get("uri") or ""))
        for row in rows
        if str(row.get("uri") or "").strip()
    })
    digest = hashlib.sha256("\n".join(identities).encode("utf-8")).hexdigest()
    return digest, len(identities)


def _load_state(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    sources = payload.get("sources", {}) if isinstance(payload, dict) else {}
    return sources if isinstance(sources, dict) else {}


def apply_source_freshness(
    rows: list[dict],
    health: list[dict],
    state_path: Path,
    max_stale_hours: int | None = None,
    now: datetime | None = None,
) -> tuple[list[dict], list[dict], dict]:
    """Return competing rows, annotated health, and persisted freshness state."""
    current_time = (now or _utc_now()).astimezone(timezone.utc)
    configured_hours = max_stale_hours
    if configured_hours is None:
        configured_hours = int(os.environ.get("SOURCE_MAX_STALE_HOURS", DEFAULT_MAX_STALE_HOURS))
    if configured_hours < 1:
        raise ValueError("SOURCE_MAX_STALE_HOURS must be at least 1")

    previous = _load_state(state_path)
    health_by_name: dict[str, dict] = {}
    health_order: list[str] = []
    for entry in health:
        name = str(entry.get("name") or "UNKNOWN")
        if name not in health_by_name:
            health_order.append(name)
        health_by_name[name] = dict(entry)
    known_health_names = set(health_by_name)

    def canonical_source(row: dict) -> str:
        name = str(row.get("source") or "UNKNOWN")
        if name in known_health_names:
            return name
        # github_api/github_tree collectors retain the member path after a colon.
        parent = name.split(":", 1)[0]
        return parent if parent in known_health_names else name

    rows_by_source: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        rows_by_source[canonical_source(row)].append(row)
    for name in rows_by_source:
        if name not in health_by_name:
            health_order.append(name)
            health_by_name[name] = {"name": name, "ok": True, "nodes": len(rows_by_source[name])}

    current: dict[str, dict] = {}
    for name in health_order:
        entry = health_by_name[name]
        source_rows = rows_by_source.get(name, [])
        prior = previous.get(name, {}) if isinstance(previous.get(name), dict) else {}
        ok = bool(entry.get("ok")) and bool(source_rows)

        if ok:
            fingerprint, semantic_nodes = _fingerprint(source_rows)
            changed = fingerprint != str(prior.get("fingerprint") or "")
            if changed or not prior.get("last_changed_at"):
                last_changed = current_time
            else:
                last_changed = _parse_iso(prior.get("last_changed_at"), current_time)
            age_hours = max(0.0, (current_time - last_changed).total_seconds() / 3600)
            fresh = age_hours <= configured_hours
            reason = "changed" if changed else ("within_window" if fresh else "unchanged_too_long")
            state = {
                "fingerprint": fingerprint,
                "semantic_nodes": semantic_nodes,
                "last_checked_at": _iso(current_time),
                "last_changed_at": _iso(last_changed),
                "fresh": fresh,
                "competition_active": fresh,
                "freshness_reason": reason,
                "duplicate_of": None,
            }
        else:
            last_changed = _parse_iso(prior.get("last_changed_at"), current_time)
            state = {
                **prior,
                "last_checked_at": _iso(current_time),
                "last_changed_at": _iso(last_changed),
                "fresh": False,
                "competition_active": False,
                "freshness_reason": "fetch_failed" if not entry.get("ok") else "empty_source",
                "duplicate_of": None,
                "semantic_nodes": int(prior.get("semantic_nodes") or 0),
            }
        current[name] = state

    # Exact mirrors do not compete twice. The first healthy configured source is
    # retained; every mirror is still checked and can re-enter when it diverges.
    fingerprint_owner: dict[str, str] = {}
    for name in health_order:
        state = current[name]
        fingerprint = str(state.get("fingerprint") or "")
        if not state.get("competition_active") or not fingerprint:
            continue
        owner = fingerprint_owner.get(fingerprint)
        if owner is None:
            fingerprint_owner[fingerprint] = name
            continue
        state["competition_active"] = False
        state["duplicate_of"] = owner
        state["freshness_reason"] = "exact_mirror"

    filtered: list[dict] = []
    included_by_source: dict[str, int] = defaultdict(int)
    for row in rows:
        name = canonical_source(row)
        if current.get(name, {}).get("competition_active"):
            filtered.append(row)
            included_by_source[name] += 1

    annotated_health: list[dict] = []
    for name in health_order:
        state = current[name]
        last_changed = _parse_iso(state.get("last_changed_at"), current_time)
        entry = {
            **health_by_name[name],
            "fresh": bool(state.get("fresh")),
            "competition_active": bool(state.get("competition_active")),
            "included_nodes": included_by_source.get(name, 0),
            "last_changed_at": state.get("last_changed_at"),
            "age_hours": round(max(0.0, (current_time - last_changed).total_seconds() / 3600), 2),
            "freshness_reason": state.get("freshness_reason"),
            "duplicate_of": state.get("duplicate_of"),
        }
        annotated_health.append(entry)

    summary = {
        "schema": 1,
        "generated_at": _iso(current_time),
        "max_stale_hours": configured_hours,
        "sources_checked": len(current),
        "active_sources": sum(1 for state in current.values() if state.get("competition_active")),
        "stale_sources": sum(1 for state in current.values() if state.get("freshness_reason") == "unchanged_too_long"),
        "duplicate_sources": sum(1 for state in current.values() if state.get("freshness_reason") == "exact_mirror"),
        "failed_sources": sum(
            1 for state in current.values()
            if state.get("freshness_reason") in {"fetch_failed", "empty_source"}
        ),
        "input_nodes": len(rows),
        "included_nodes": len(filtered),
        "sources": current,
    }
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return filtered, annotated_health, summary
