from __future__ import annotations

import urllib.parse
from typing import Any

from ..models import Node
from ..source import canonicalize_protocol_uri
from .common import (
    parse_query,
    qfirst,
    qhas,
    stream_from_query,
)


def parse_vless(raw: str, index: int, _probe_url: str) -> Node:
    source_raw = raw
    canonical = canonicalize_protocol_uri("vless", raw)
    url = urllib.parse.urlsplit(canonical)
    if url.scheme.lower() != "vless":
        raise ValueError("Not VLESS URI")
    user_id = urllib.parse.unquote(url.username or "").strip()
    host = url.hostname or ""
    try:
        port = int(url.port or 0)
    except ValueError as e:
        raise ValueError("Invalid port") from e
    if not user_id or not host or not port:
        raise ValueError("VLESS missing id/host/port")
    q = parse_query(url.query)
    stream, insecure, sni, alpn, udp_bypass = stream_from_query(host, q, default_security="none")

    encryption = (
        qfirst(q, "encryption").strip()
        if qhas(q, "encryption")
        else "none"
    )

    settings: dict[str, Any] = {
        "id": user_id,
        "encryption": encryption,
    }
    flow = qfirst(q, "flow")
    if qhas(q, "flow"):
        settings["flow"] = flow
    return Node("vless", index, source_raw, host, port, settings, stream, insecure, sni, alpn, udp_bypass)
