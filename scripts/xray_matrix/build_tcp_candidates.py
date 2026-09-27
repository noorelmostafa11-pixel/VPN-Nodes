#!/usr/bin/env python3
"""Build the existing public TCP candidate pool without country publication.

This intentionally reuses the repository's current collectors, source freshness,
semantic selection, and TCP liveness code.  The only intercepted call is
publish_app_pool(), because country resolution/publication must happen only
after the server-identical Xray real-HTTPS test.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import merge_and_build_tcp_pool as merge  # noqa: E402

META = ROOT / "output" / "metadata"
TCP_REACHABLE = META / "tcp_reachable.json"
XRAY_CANDIDATES = META / "xray_candidates.json"
SUPPORTED = {"vless", "vmess", "trojan", "shadowsocks"}


def _defer_publication(rows: list[dict], source_health: list[dict], freshness: dict | None = None) -> dict:
    """Do not run the public GeoIP/country publisher before Xray."""
    return {
        "published_total": len(rows),
        "publication_deferred_to_xray": True,
        "source_failures": sum(1 for row in source_health if not row.get("ok")),
        "source_freshness": {
            key: value for key, value in (freshness or {}).items() if key != "sources"
        },
    }


def main() -> int:
    merge.common.publish_app_pool = _defer_publication
    rc = merge.main()
    if rc not in (None, 0):
        return int(rc)
    if not TCP_REACHABLE.is_file():
        raise SystemExit("tcp_reachable.json was not generated")

    source = json.loads(TCP_REACHABLE.read_text(encoding="utf-8"))
    nodes = source.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        raise SystemExit("TCP candidate pool is empty")

    counts = Counter()
    normalized: list[dict] = []
    for item in nodes:
        if not isinstance(item, dict):
            raise SystemExit("Invalid TCP candidate row")
        protocol = str(item.get("protocol") or "").lower()
        uri = str(item.get("uri") or "").strip()
        if protocol not in SUPPORTED:
            raise SystemExit(f"Unexpected protocol in TCP candidate pool: {protocol!r}")
        expected_scheme = "ss" if protocol == "shadowsocks" else protocol
        if not uri.lower().startswith(expected_scheme + "://"):
            raise SystemExit(f"Protocol/URI mismatch for {protocol}")
        counts[protocol] += 1
        # Preserve the public TCP pool row exactly; xray_index is added only as
        # deterministic matrix identity and never alters raw node identity.
        normalized.append(dict(item))

    payload = {
        "schema": 1,
        "generated_at": source.get("generated_at"),
        "tcp_reachable": len(normalized),
        "protocol_counts": dict(sorted(counts.items())),
        "source_freshness": source.get("source_freshness") or {},
        "sources": source.get("sources") or [],
        "nodes": normalized,
    }
    XRAY_CANDIDATES.parent.mkdir(parents=True, exist_ok=True)
    XRAY_CANDIDATES.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        "OK Xray candidate pool: "
        f"total={len(normalized)} protocols={dict(sorted(counts.items()))}; "
        "country publication deferred until after Xray"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
