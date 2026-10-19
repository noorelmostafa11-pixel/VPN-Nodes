"""Transport hints for the cheap precheck, never a connection/config parser."""
from __future__ import annotations
import base64
import json
from urllib.parse import parse_qsl, unquote, urlsplit

UDP_TRANSPORTS = {"quic", "legacy-quic", "kcp", "mkcp", "hysteria", "hysteria2", "hy2"}


def _has_h3(value: object) -> bool:
    if isinstance(value, list):
        return any(_has_h3(v) for v in value)
    if isinstance(value, dict):
        return any((_has_h3(v) if str(k).lower() == "alpn" else
                    isinstance(v, (dict, list)) and _has_h3(v)) for k, v in value.items())
    return any(v.strip().lower().startswith("h3") for v in str(value).split(","))


def uses_udp_transport(uri: str) -> bool:
    try:
        scheme, body = uri.split("://", 1)
        if scheme.lower() == "vmess" and "@" not in body.split("#", 1)[0]:
            encoded = unquote(body.split("#", 1)[0])
            if len(encoded) > 256 * 1024:
                return False
            obj = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
            if not isinstance(obj, dict):
                return False
            # In VMess JSON, type describes the header; net/network is transport.
            fields = {str(k).lower(): v for k, v in obj.items() if str(k).lower() != "type"}
        else:
            fields = {str(k).lower(): v for k, v in parse_qsl(urlsplit(uri).query, keep_blank_values=True)}
        if any(str(fields.get(k, "")).strip().lower() in UDP_TRANSPORTS for k in ("type", "network", "net")):
            return True
        plugin = str(fields.get("plugin", "")).lower()
        if "mode=quic" in plugin.split(";"):
            return True
        # XHTTP can use HTTP/3 over UDP, including its nested download leg.
        if _has_h3(fields.get("alpn", "")):
            return True
        for key in ("extra", "xhttpExtra", "xhttpextra"):
            extra = fields.get(key)
            if isinstance(extra, str):
                try:
                    extra = json.loads(extra)
                except ValueError:
                    continue
            if isinstance(extra, dict) and _has_h3(extra):
                return True
    except (ValueError, TypeError, UnicodeError, RecursionError):
        pass
    return False
