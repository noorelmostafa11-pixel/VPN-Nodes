from __future__ import annotations

import urllib.parse

from ..models import Node
from ..source import canonicalize_protocol_uri
from .common import parse_query, qfirst, qhas, stream_from_query


def parse_trojan(raw: str, index: int, _probe_url: str) -> Node:
    source_raw = raw
    canonical = canonicalize_protocol_uri("trojan", raw)
    url = urllib.parse.urlsplit(canonical)
    if url.scheme.lower() != "trojan":
        raise ValueError("Not Trojan URI")
    password = urllib.parse.unquote(url.username or "")
    host = url.hostname or ""
    try:
        port = int(url.port or 0)
    except ValueError as e:
        raise ValueError("Invalid port") from e
    if not password or not host or not port:
        raise ValueError("Trojan missing password/host/port")
    q = parse_query(url.query)
    stream, insecure, sni, alpn, udp_bypass = stream_from_query(host, q, default_security="tls")
    settings = {"password": password}
    # Preserve Trojan Flow exactly when the source provides it.  Xray 26.9.9
    # owns the final decision and currently rejects non-empty Trojan Flow; the
    # parser must not silently turn that source into a different plain node.
    if qhas(q, "flow"):
        settings["flow"] = qfirst(q, "flow")
    return Node("trojan", index, source_raw, host, port, settings, stream, insecure, sni, alpn, udp_bypass)
