#!/usr/bin/env python3
"""Build candidates from v2nodes.com only."""
from __future__ import annotations

import json
import time
from pathlib import Path

import update_catalog as catalog
import v2nodes_adapter

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output" / "metadata" / "v2nodes_candidates.json"
BASE = v2nodes_adapter.BASE
MAX_PAGES = 5000


def main() -> int:
    started = time.perf_counter()
    uris = v2nodes_adapter.collect(start_url=BASE, max_pages=MAX_PAGES)
    if not uris:
        raise SystemExit("v2nodes returned no proxy URIs")
    rows = catalog.parse_lines("\n".join(uris), "v2nodes")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        "raw_uris": len(uris),
        "parsed": len(rows),
        "rows": rows,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"INFO v2nodes raw_uris={len(uris)} parsed={len(rows)} elapsed_ms={round((time.perf_counter() - started) * 1000, 1)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
