#!/usr/bin/env python3
"""Semantic node identity used to remove source/cosmetic duplicates safely.

Credentials remain part of the identity.  This deliberately does not merge two
accounts that merely share an IP/port.  It does normalize representation details
that do not create a different server config, such as tcp vs raw, parameter order,
remarks, client fingerprint and explicit vs omitted VLESS encryption=none.
"""
from __future__ import annotations

import base64
import json
import urllib.parse


def _b64decode(value: str) -> bytes:
    value = value.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(value + "=" * (-len(value) % 4), validate=False)


def _first(query: dict[str, list[str]], *keys: str, default: str = "") -> str:
    for key in keys:
        values = query.get(key)
        if values:
            return urllib.parse.unquote(str(values[0])).strip()
    return default


def _network(value: str) -> str:
    value = (value or "").strip().lower()
    return {
        "": "tcp",
        "raw": "tcp",
        "websocket": "ws",
        "http-upgrade": "httpupgrade",
        "splithttp": "xhttp",
    }.get(value, value)


def _security(value: str, scheme: str) -> str:
    value = (value or "").strip().lower()
    if scheme == "trojan" and value in ("", "none"):
        return "tls"
    if value in ("", "none", "false", "0"):
        return "none"
    return value


def _decode_vmess(uri: str) -> dict:
    payload = urllib.parse.unquote(uri.split("vmess://", 1)[1].split("#", 1)[0].strip())
    obj = json.loads(_b64decode(payload).decode("utf-8-sig"))
    if not isinstance(obj, dict):
        raise ValueError("invalid-vmess")
    return obj


def _ss_parts(uri: str) -> tuple[str, str, int]:
    raw = uri.split("ss://", 1)[1].split("#", 1)[0]
    raw = raw.split("?", 1)[0]
    if "@" in raw:
        userinfo, hp = raw.rsplit("@", 1)
        try:
            decoded = _b64decode(userinfo).decode("utf-8")
            if ":" in decoded:
                userinfo = decoded
            else:
                userinfo = urllib.parse.unquote(userinfo)
        except Exception:
            userinfo = urllib.parse.unquote(userinfo)
    else:
        decoded = _b64decode(raw).decode("utf-8")
        userinfo, hp = decoded.rsplit("@", 1)
    parsed = urllib.parse.urlsplit("//" + hp)
    host = (parsed.hostname or "").lower()
    port = int(parsed.port or 0)
    if ":" in userinfo:
        method, password = userinfo.split(":", 1)
        credential = f"{method.strip().lower()}:{password}"
    else:
        credential = userinfo
    return credential, host, port


def dedup_key(uri: str) -> str:
    """Return one normalized identity for the same usable node configuration."""
    clean = uri.replace("&amp;", "&").strip()
    scheme = urllib.parse.urlsplit(clean).scheme.lower()
    if scheme == "ss":
        scheme = "shadowsocks"

    if scheme == "vmess":
        try:
            obj = _decode_vmess(clean)
            host = str(obj.get("add") or obj.get("address") or "").strip().lower()
            port = int(obj.get("port") or 0)
            credential = str(obj.get("id") or "").strip()
            network = _network(str(obj.get("net") or "tcp"))
            security = _security(str(obj.get("tls") or ""), "vmess")
            query = {
                "sni": [str(obj.get("sni") or "")],
                "host": [str(obj.get("host") or "")],
                "path": [str(obj.get("path") or "")],
                "serviceName": [str(obj.get("serviceName") or obj.get("service_name") or "")],
                "alterId": [str(obj.get("aid") or 0)],
                "encryption": [str(obj.get("scy") or "auto")],
            }
        except Exception:
            return clean.split("#", 1)[0]
    elif scheme == "shadowsocks":
        try:
            credential, host, port = _ss_parts(clean)
        except Exception:
            return clean.split("#", 1)[0]
        network = "tcp"
        security = "none"
        query = {}
    else:
        try:
            parsed = urllib.parse.urlsplit(clean)
            host = (parsed.hostname or "").strip().lower()
            port = int(parsed.port or 0)
            credential = urllib.parse.unquote(parsed.username or "").strip()
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            network = _network(_first(query, "type", "net", default="tcp"))
            security = _security(_first(query, "security", "tls"), scheme)
        except Exception:
            return clean.split("#", 1)[0]

    if not scheme or not host or not port:
        return clean.split("#", 1)[0]

    identity = [scheme, host, str(port)]
    if credential:
        identity.append(f"credential={credential}")
    identity.extend((f"network={network}", f"security={security}"))

    # SNI can select a different TLS/REALITY backend and must remain significant.
    sni = _first(query, "sni", "serverName", "servername").lower()
    if sni:
        identity.append(f"sni={sni}")

    if scheme == "vmess":
        alter_id = _first(query, "alterId", default="0") or "0"
        cipher = (_first(query, "encryption", default="auto") or "auto").lower()
        identity.extend((f"alterId={alter_id}", f"cipher={cipher}"))

    if security == "reality":
        pbk = _first(query, "pbk", "publicKey")
        sid = _first(query, "sid", "shortId").lower()
        flow = _first(query, "flow").lower()
        if pbk:
            identity.append(f"pbk={pbk}")
        if sid:
            identity.append(f"sid={sid}")
        if flow:
            identity.append(f"flow={flow}")

    # These fields can select different backends on multiplexed/CDN transports.
    if network in {"ws", "httpupgrade", "xhttp", "http", "h2", "grpc"}:
        transport_host = _first(query, "host").lower()
        if transport_host:
            identity.append(f"host={transport_host}")

    if network in {"ws", "httpupgrade", "xhttp", "http", "h2"}:
        path = _first(query, "path", default="/") or "/"
        if not path.startswith("/"):
            path = "/" + path
        identity.append(f"path={path}")

    if network == "grpc":
        service = _first(query, "serviceName", "service_name")
        authority = _first(query, "authority").lower()
        if service:
            identity.append(f"service={service}")
        if authority:
            identity.append(f"authority={authority}")

    if network == "xhttp":
        mode = _first(query, "mode").lower()
        if mode:
            identity.append(f"mode={mode}")

    # VLESS encryption defaults to none. Explicit/omitted forms are equivalent.
    if scheme == "vless":
        encryption = (_first(query, "encryption", default="none") or "none").lower()
        if encryption != "none":
            identity.append(f"encryption={encryption}")

    return "|".join(identity)
