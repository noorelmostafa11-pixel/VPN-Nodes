#!/usr/bin/env python3
"""Conservative connection identity used for duplicate-node removal.

Project policy:
- the fragment after the first '#' is display-only and never creates a new node;
- query-parameter order does not create a new node;
- percent-encoding differences inside query keys/values do not create a new node;
- query-key case does not create a new node;
- every real value remains significant: protocol, credentials, host/IP, port,
  transport/security settings, and every query parameter/value.

No defaults are invented and no transport/security semantics are collapsed.
"""
from __future__ import annotations

import json
from urllib.parse import unquote


def _decode_query_component(value: str) -> str:
    """Decode one percent-encoding layer without treating '+' as a space."""
    try:
        return unquote(value, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return value


def dedup_key(uri: str) -> str:
    """Return a conservative canonical identity for one share URI."""
    base = uri.split("#", 1)[0]
    query_at = base.find("?")
    if query_at < 0:
        return base

    head = base[:query_at]
    query = base[query_at + 1 :]
    if not query:
        return head

    pairs: list[tuple[str, bool, str]] = []
    for part in query.split("&"):
        if not part:
            continue
        key, separator, value = part.partition("=")
        pairs.append(
            (
                _decode_query_component(key).lower(),
                bool(separator),
                _decode_query_component(value),
            )
        )

    pairs.sort()
    return head + "?" + json.dumps(
        pairs,
        ensure_ascii=False,
        separators=(",", ":"),
    )
