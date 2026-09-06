#!/usr/bin/env python3
"""Build candidates from public sources plus dynamic subscriptions."""
from __future__ import annotations

import json
import time
from pathlib import Path

import update_catalog as catalog
from freev2raynodes_adapter import candidate_urls
from publicvpnlist_adapter import collect_publicvpnlist
from freeproxydb_adapter import collect_freeproxydb
from clashxw_daily_adapter import collect_clashxw_daily

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "sources" / "sources.json"
OUT = ROOT / "output" / "metadata" / "sources_candidates.json"
SPECIAL_FORMATS = {"telegram_catalog", "telegram_html", "v2nodes"}


def collect_freev2raynodes():
    rows = []
    for url in candidate_urls():
        try:
            rows.extend(catalog.collect_source({"name": "freev2raynodes", "url": url}))
        except Exception:
            continue
    return rows


def normalize_adapter_rows(items: list[dict], source_name: str) -> list[dict]:
    """Convert adapter URL-shaped rows to the catalog's canonical node rows."""
    rows: list[dict] = []
    seen_candidates: set[str] = set()
    seen_uris: set[str] = set()

    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for child in value.values():
                yield from strings(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                yield from strings(child)

    for item in items:
        for raw in strings(item):
            candidate = raw.strip()
            if not candidate or candidate in seen_candidates:
                continue
            seen_candidates.add(candidate)
            for row in catalog.parse_lines(candidate, source_name):
                if row["uri"] not in seen_uris:
                    seen_uris.add(row["uri"])
                    rows.append(row)
    return rows


def collect_special(
    name: str,
    collector,
    rows: list[dict],
    health: list[dict],
    *,
    normalize: bool = False,
) -> None:
    started = time.perf_counter()
    try:
        raw = collector()
        found = normalize_adapter_rows(raw, name) if normalize else raw
        entry = {
            "name": name,
            "ok": True,
            "nodes": len(found),
            "raw_nodes": len(raw),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        }
        if not found:
            entry["status"] = "no_supported_nodes"
        health.append(entry)
        rows.extend(found)
        level = "OK" if found else "SKIP"
        print(f"{level} source {name}: raw={len(raw)} normalized={len(found)}")
    except Exception as exc:
        health.append({
            "name": name,
            "ok": False,
            "nodes": 0,
            "raw_nodes": 0,
            "error": str(exc),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        })
        print(f"WARN source {name}: {exc}")


def main() -> int:
    cfg = json.loads(SOURCES.read_text(encoding="utf-8"))
    rows: list[dict] = []
    health: list[dict] = []
    started_all = time.perf_counter()

    for item in cfg.get("sources", []):
        if item.get("format") in SPECIAL_FORMATS:
            continue
        try:
            found = catalog.collect_source(item)
            rows.extend(found)
            entry = {"name": item["name"], "ok": True, "nodes": len(found)}
            if not found:
                entry["status"] = "no_supported_nodes"
            health.append(entry)
            print(f"{'OK' if found else 'SKIP'} source {item['name']}: {len(found)}")
        except Exception as exc:
            health.append({"name": item["name"], "ok": False, "nodes": 0, "error": str(exc)})
            print(f"WARN source {item['name']}: {exc}")

    collect_special("freev2raynodes", collect_freev2raynodes, rows, health)
    collect_special("PublicVPNList-api", collect_publicvpnlist, rows, health, normalize=True)
    collect_special("FreeProxyDB-api", collect_freeproxydb, rows, health, normalize=True)
    collect_special("ClashXW-Daily", collect_clashxw_daily, rows, health, normalize=True)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_ms": round((time.perf_counter()-started_all)*1000, 1),
        "rows": rows,
        "sources": health,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"INFO sources_candidates={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
