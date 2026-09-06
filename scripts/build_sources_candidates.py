#!/usr/bin/env python3
"""Build candidates from public sources plus dynamic subscriptions and HTML pages."""
from __future__ import annotations

import json
import time
from pathlib import Path

import update_catalog as catalog
from freev2raynodes_adapter import candidate_urls
from html_v2ray_parser import collect_html_source
from source_discovery import discover_source

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "sources" / "sources.json"
OUT = ROOT / "output" / "metadata" / "sources_candidates.json"
SPECIAL_FORMATS = {"telegram_catalog", "telegram_html", "v2nodes"}

HTML_SOURCES = [
    {"name": "sshs8", "url": "https://sshs8.com/free-vless-server-v2ray/"},
    {"name": "racevpn", "url": "https://www.racevpn.com/free-v2ray-server"},
    {"name": "v2rayse", "url": "https://v2.v2rayse.com/en/free-node/"},
]


def collect_freev2raynodes():
    rows = []
    for url in candidate_urls():
        try:
            rows.extend(catalog.collect_source({"name": "freev2raynodes", "url": url}))
        except Exception:
            continue
    return rows


def collect_html_sources():
    rows = []
    health = []
    for item in HTML_SOURCES:
        started = time.perf_counter()
        try:
            found = collect_html_source(item["name"], item["url"])
            if not found:
                discovered = discover_source(item["name"], item["url"])
                for endpoint in discovered.get("endpoints", []):
                    try:
                        found.extend(catalog.collect_source({"name": item["name"], "url": endpoint}))
                    except Exception:
                        continue
            rows.extend(found)
            health.append({"name": item["name"], "ok": True, "nodes": len(found),
                           "elapsed_ms": round((time.perf_counter()-started)*1000, 1)})
            print(f"OK html source {item['name']}: {len(found)}")
        except Exception as exc:
            health.append({"name": item["name"], "ok": False, "nodes": 0, "error": str(exc)})
            print(f"WARN html source {item['name']}: {exc}")
    return rows, health


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
            health.append({"name": item["name"], "ok": True, "nodes": len(found)})
            print(f"OK source {item['name']}: {len(found)}")
        except Exception as exc:
            print(f"WARN source {item['name']}: {exc}")

    dynamic = collect_freev2raynodes()
    rows.extend(dynamic)
    health.append({"name": "freev2raynodes", "ok": True, "nodes": len(dynamic)})
    print(f"OK source freev2raynodes: {len(dynamic)}")

    html_rows, html_health = collect_html_sources()
    rows.extend(html_rows)
    health.extend(html_health)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "elapsed_ms": round((time.perf_counter()-started_all)*1000, 1), "rows": rows, "sources": health}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"INFO sources_candidates={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
