from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class UnsupportedNode(ValueError):
    """URI describes a valid feature this target Xray build cannot represent."""

class XrayProbeError(RuntimeError):
    """The Xray executable exists but its version could not be verified."""

@dataclass
class Node:
    protocol: str
    index: int
    raw: str
    host: str
    port: int
    outbound_settings: dict[str, Any]
    stream_settings: dict[str, Any]
    allow_insecure: bool = False
    tls_server_name: str = ""
    tls_alpn: tuple[str, ...] = ()
    udp_prefilter_bypass: bool = False

@dataclass
class TestResult:
    # This is a production result model, not a pytest test class.
    __test__ = False

    protocol: str
    index: int
    raw: str
    host: str
    port: int
    ok: bool
    # source_invalid includes a source whose emitted configuration is rejected
    # as invalid by the target Xray version without rewriting the source. It
    # does not claim that every such URI is invalid in every other application.
    stage: str
    error: str = ""
    tcp_ms: float | None = None
    http204_ms: float | None = None
    country: str = "XX"
    country_error: str = ""
    # A repaired working node always retains its original source identity and
    # records the explicit deterministic transformation that produced the URI
    # which itself passed the same Xray Real Delay test.
    source_raw: str = ""
    repair_strategy: str = ""
    real_delay_proven: bool = False
    # Exact HTTPS target that proved this node: google or microsoft.
    success_endpoint: str = ""
    # Public exit address observed through this node, only when the country
    # endpoint could not supply a country. The publisher resolves it locally.
    exit_ip: str = ""
