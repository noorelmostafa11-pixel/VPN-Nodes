#!/usr/bin/env python3
"""Connection-equivalent node identity for pre-Xray deduplication.

Two source URIs are duplicates only when the production parser turns them into
exactly the same connection data that the Xray engine will use. Cosmetic source
differences (remarks, query ordering, supported aliases/defaults) therefore
collapse naturally, while any field that changes the generated Xray connection
settings remains distinct.

If a source cannot be parsed, no semantic guess is made: only the exact cleaned
raw string can deduplicate with another identical malformed source.
"""
from __future__ import annotations

import html
import json
import sys
import urllib.parse
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TESTER_ROOT = ROOT / "scripts" / "xray_tester"
if str(TESTER_ROOT) not in sys.path:
    sys.path.insert(0, str(TESTER_ROOT))

from vpn_pipeline_core.parsers import PARSERS  # noqa: E402

SCHEME_TO_PROTOCOL = {
    "vless": "vless",
    "vmess": "vmess",
    "trojan": "trojan",
    "ss": "ss",
}


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _clean_source(uri: str) -> str:
    # The collector already performs the same HTML-entity cleanup before
    # deduplication. Keep it here too so direct callers get identical behavior.
    return html.unescape(str(uri).strip())


def _raw_fallback(clean: str) -> str:
    # Parser failures are never merged by interpretation. This preserves every
    # non-identical malformed/unsupported source for Xray/parser judgement.
    return "raw:" + clean


def connection_payload(uri: str) -> dict[str, Any] | None:
    """Return the exact connection-relevant Node fields consumed by Xray.

    None means the production parser could not represent the source. Callers
    must then fall back to exact-raw identity instead of guessing equivalence.
    """
    clean = _clean_source(uri)
    try:
        scheme = urllib.parse.urlsplit(clean).scheme.lower()
        protocol = SCHEME_TO_PROTOCOL.get(scheme)
        if protocol is None:
            return None
        node = PARSERS[protocol](clean, 0, "")
    except Exception:
        return None

    # xray_engine.make_xray_config() builds the outbound connection solely from
    # these fields. Runtime-only tags, local inbound ports, e-mail labels and
    # mux scaffolding are deliberately excluded because they do not identify
    # the remote node connection.
    return {
        "protocol": node.protocol,
        "host": str(node.host).lower(),
        "port": int(node.port),
        "outbound_settings": node.outbound_settings,
        "stream_settings": node.stream_settings,
    }


def dedup_key_with_status(uri: str) -> tuple[str, bool]:
    """Return (identity, parser_proven).

    parser_proven=True means two equal keys are guaranteed to generate the same
    production Xray connection data. False means exact-raw fallback was used.
    """
    clean = _clean_source(uri)
    payload = connection_payload(clean)
    if payload is None:
        return _raw_fallback(clean), False
    return "xray:" + _canonical_json(payload), True


def dedup_key(uri: str) -> str:
    """Return the safe pre-Xray duplicate identity for one source URI."""
    return dedup_key_with_status(uri)[0]
