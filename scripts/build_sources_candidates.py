#!/usr/bin/env python3
"""Build candidates from sources.json only.

Telegram and v2nodes are intentionally excluded and have dedicated workflow
steps. This script only collects/normalizes the ordinary public sources.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import update_catalog as catalog

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "sources" / "sources.json"
OUT = ROOT / "output" / "metadata" / "sources_candidates.json"
OPENVPN_CANDIDATES = ROOT / "output" / "metadata" / "openvpn_candidates.json"
SPECIAL_FORMATS = {"telegram_catalog", "telegram_html", "v2nodes"}


def main() -> int:
    cfg = json.loads(SOURCES.read_text(encoding="utf-8"))
    rows: list[dict] = []
    health: list[dict] = []
    started_all = time.perf_counter()

    # Never let a failed VPNGate fetch leave stale OpenVPN candidates from a
    # previous checkout. parse_vpngate_csv() recreates this file on success.
    OPENVPN_CANDIDATES.unlink(missing_ok=True)

    for item in cfg.get("sources", []):
        if item.get("format") in SPECIAL_FORMATS:
            continue
        started = time.perf_counter()
        try:
            found = catalog.collect_source(item)
            rows.extend(found)
            health.append({"name": item["name"], "ok": True, "nodes": len(found),
                           "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)})
            print(f"OK source {item['name']}: {len(found)}")
        except Exception as exc:
            health.append({"name": item["name"], "ok": False, "nodes": 0,
                           "error": str(exc),
                           "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)})
            print(f"WARN source {item['name']}: {exc}")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_ms": round((time.perf_counter() - started_all) * 1000, 1),
        "rows": rows,
        "sources": health,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"INFO sources_candidates={len(rows)} elapsed_ms={round((time.perf_counter() - started_all) * 1000, 1)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
