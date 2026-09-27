from __future__ import annotations

import urllib.parse
from typing import Any

from ..models import Node
from ..source import protocol_uri_body
from .common import b64decode_ss, build_stream_settings, parse_query, qfirst, stream_from_query


def _plugin_parts(plugin: str) -> tuple[str, dict[str, str], set[str]]:
    parts = [part.strip() for part in plugin.split(";") if part.strip()]
    if not parts:
        return "", {}, set()
    name = parts[0].lower()
    if name == "simple-obfs":
        name = "obfs-local"
    values: dict[str, str] = {}
    flags: set[str] = set()
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            key = key.strip().lower()
            if key in values:
                raise ValueError(f"Duplicate Shadowsocks plugin option: {key}")
            values[key] = value
        else:
            key = part.strip().lower()
            if key in flags:
                raise ValueError(f"Duplicate Shadowsocks plugin flag: {key}")
            flags.add(key)
    return name, values, flags


def _v2ray_plugin_unescape(value: str) -> str:
    # Match v2rayN's v2ray-plugin share handling: path escapes backslash,
    # equals and comma inside the semicolon-separated plugin string.
    return value.replace(r"\=", "=").replace(r"\,", ",").replace(r"\\", "\\")


def _external_plugin_marker(plugin_name: str) -> dict[str, Any]:
    # Keep unsupported external plugin semantics visible to Xray instead of
    # silently testing a plain Shadowsocks node.
    return {
        "network": f"sip003-plugin:{plugin_name}",
        "security": "none",
    }


def _stream_from_plugin(plugin: str) -> dict[str, Any]:
    name, values, flags = _plugin_parts(plugin)
    if not name or name in {"none", "0", "false", "off"}:
        return {}

    if name == "v2ray-plugin":
        mode = values.get("mode", "websocket").strip().lower()
        # v2rayN maps only v2ray-plugin WebSocket mode to native Xray stream
        # settings.  Keep any other plugin mode explicit and unsupported.
        if mode != "websocket":
            return _external_plugin_marker(name)

        mux_text = values.get("mux", "").strip()
        if mux_text:
            try:
                if int(mux_text, 10) > 0:
                    return _external_plugin_marker(name)
            except ValueError:
                return _external_plugin_marker(name)

        host = values.get("host", "").strip()
        path = _v2ray_plugin_unescape(values.get("path", ""))
        use_tls = "tls" in flags
        stream, *_ = build_stream_settings(
            host="",
            transport="ws",
            security="tls" if use_tls else "none",
            path=path,
            host_header=host,
            sni=host if use_tls else "",
            sni_present=use_tls and bool(host),
        )

        cert_raw = values.get("certraw", "")
        if use_tls and cert_raw:
            cert_base64 = cert_raw.replace(r"\=", "=").strip()
            cert_pem = (
                "-----BEGIN CERTIFICATE-----\n"
                + cert_base64
                + "\n-----END CERTIFICATE-----"
            )
            tls = stream.setdefault("tlsSettings", {})
            tls["certificates"] = [{
                "certificate": cert_pem.split("\n"),
                "usage": "verify",
            }]
            tls["disableSystemRoot"] = True
        return stream

    return _external_plugin_marker(name)


def parse_ss(raw: str, index: int, _probe_url: str) -> Node:
    source_raw = raw
    _, body = protocol_uri_body("ss", raw)
    body = body.split("#", 1)[0]
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)
    q = parse_query(query)
    plugin = qfirst(q, "plugin")

    if "@" in body:
        userinfo, hp = body.rsplit("@", 1)
        plain_userinfo = urllib.parse.unquote(userinfo)
        if ":" in plain_userinfo:
            decoded_userinfo = plain_userinfo
        else:
            decoded_userinfo = b64decode_ss(userinfo).decode("utf-8")
    else:
        decoded = b64decode_ss(body).decode("utf-8")
        if "@" not in decoded:
            raise ValueError("Invalid Shadowsocks URI")
        decoded_userinfo, hp = decoded.rsplit("@", 1)

    if ":" not in decoded_userinfo:
        raise ValueError("Shadowsocks missing method:password")
    method, password = decoded_userinfo.split(":", 1)
    method = method.strip()
    if not method or not password:
        raise ValueError("Shadowsocks missing method/password")

    parsed_hp = urllib.parse.urlsplit("//" + hp)
    host = parsed_hp.hostname or ""
    try:
        port = int(parsed_hp.port or 0)
    except ValueError as e:
        raise ValueError("Invalid Shadowsocks port") from e
    if not host or not port:
        raise ValueError("Shadowsocks missing host/port")

    if plugin:
        stream_settings = _stream_from_plugin(plugin)
        insecure = False
        sni = ""
        alpn: tuple[str, ...] = ()
        udp_bypass = False
    elif q:
        # Xray's native share-link parser applies ordinary stream query fields
        # to Shadowsocks too (for example type=ws&security=tls).  Preserve that
        # path instead of silently testing the same credentials as plain SS.
        stream_settings, insecure, sni, alpn, udp_bypass = stream_from_query(
            host, q, default_security="none"
        )
    else:
        stream_settings = {}
        insecure = False
        sni = ""
        alpn = ()
        udp_bypass = False

    settings = {"method": method, "password": password}
    return Node(
        "ss", index, source_raw, host, port, settings, stream_settings,
        insecure, sni, alpn, udp_bypass,
    )
