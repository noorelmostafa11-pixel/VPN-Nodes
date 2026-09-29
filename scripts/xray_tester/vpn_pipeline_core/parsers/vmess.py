from __future__ import annotations

import urllib.parse

from ..models import Node, UnsupportedNode
from ..source import canonicalize_protocol_uri, protocol_uri_body
from .common import (
    _parse_json_for_xray, _parse_xhttp_extra,
    _parse_xray_bool, b64decode_loose, build_stream_settings,
    json_loads_unique, normalize_security, parse_query, qfirst, qhas, stream_from_query,
)


def _require_representable_alter_id(value: object) -> int:
    text = str(value if value is not None else "").strip()
    if text == "":
        return 0
    try:
        alter_id = int(text, 10)
    except ValueError as e:
        raise ValueError(f"Invalid VMess alterId: {text}") from e
    if alter_id != 0:
        raise UnsupportedNode(
            f"VMess alterId={alter_id} cannot be represented by target Xray without changing node semantics"
        )
    return 0


def parse_vmess(raw: str, index: int, _probe_url: str) -> Node:
    source_raw = raw
    canonical = canonicalize_protocol_uri("vmess", raw)

    # Modern Xray share-link format: vmess://UUID@host:port?... .  The older
    # ecosystem format vmess://BASE64(JSON) is intentionally retained below so
    # this production build expands compatibility instead of replacing it.
    modern_url = urllib.parse.urlsplit(canonical)
    modern_port = 0
    try:
        modern_port = int(modern_url.port or 0)
    except ValueError:
        modern_port = 0
    if modern_url.username is not None and modern_url.hostname and modern_port:
        user_id = urllib.parse.unquote(modern_url.username).strip()
        host = modern_url.hostname or ""
        if not user_id:
            raise ValueError("VMess missing id")
        q = parse_query(modern_url.query)
        raw_alter_id_values = [
            q[k][0]
            for k in ("aid", "alterid")
            if q.get(k)
        ]
        for value in raw_alter_id_values:
            _require_representable_alter_id(value)
        alter_id = 0
        stream, insecure, sni, alpn, udp_bypass = stream_from_query(
            host, q, default_security="none"
        )
        cipher = qfirst(q, "encryption") if qhas(q, "encryption") else "auto"
        settings = {"id": user_id, "security": cipher, "alterId": alter_id}
        return Node(
            "vmess", index, source_raw, host, modern_port, settings, stream,
            insecure, sni, alpn, udp_bypass,
        )

    # Legacy vmess://BASE64(JSON) remains common in public aggregations.
    _, body = protocol_uri_body("vmess", canonical)
    payload = body.split("#", 1)[0].strip()
    obj = json_loads_unique(b64decode_loose(payload).decode("utf-8-sig"))
    if not isinstance(obj, dict):
        raise ValueError("Invalid VMess payload")
    host = str(obj.get("add") or obj.get("address") or "").strip()
    try:
        port = int(obj.get("port") or 0)
    except (TypeError, ValueError) as e:
        raise ValueError("Invalid VMess port") from e
    user_id = str(obj.get("id") or "").strip()
    if not host or not port or not user_id:
        raise ValueError("VMess missing id/host/port")
    if "net" in obj:
        network = str(obj.get("net") if obj.get("net") is not None else "").strip()
    elif "network" in obj:
        network = str(obj.get("network") if obj.get("network") is not None else "").strip()
    else:
        network = "tcp"
    network_key = network.lower()
    tls_value = str(obj.get("tls") or "").strip()
    tls_key = tls_value.lower()
    if tls_key in ("", "0", "false", "off", "none"):
        fallback_security = str(obj.get("security") or "").strip()
        fallback_key = fallback_security.lower()
        security = normalize_security(fallback_security, default="none") if fallback_key in ("tls", "reality") else "none"
    else:
        security = normalize_security(tls_value, default="none")

    path_present = "path" in obj
    if path_present:
        path = str(obj.get("path") if obj.get("path") is not None else "")
    else:
        # Legacy share defaults use '/' for stream paths.  mKCP is different:
        # there the same legacy field is the seed, whose absent default is ''.
        path = "" if network_key in ("kcp", "mkcp") else "/"
    host_header = str(obj.get("host") or "")
    service_name_present = "serviceName" in obj or "service_name" in obj
    if "serviceName" in obj:
        service_name = str(obj.get("serviceName") if obj.get("serviceName") is not None else "")
    elif "service_name" in obj:
        service_name = str(obj.get("service_name") if obj.get("service_name") is not None else "")
    else:
        service_name = ""
    alpn_value = obj.get("alpn") or ""
    if isinstance(alpn_value, list):
        alpn = [str(x).strip() for x in alpn_value if str(x).strip()]
    else:
        alpn = [x.strip() for x in str(alpn_value).split(",") if x.strip()]

    if "fm" in obj:
        finalmask_value = obj.get("fm")
    elif "finalmask" in obj:
        finalmask_value = obj.get("finalmask")
    else:
        finalmask_value = None
    if finalmask_value is not None:
        if isinstance(finalmask_value, str):
            finalmask_value = _parse_json_for_xray(finalmask_value)

    extra_value = obj.get("extra") if "extra" in obj else None
    if isinstance(extra_value, str):
        extra_value = _parse_xhttp_extra(extra_value)

    raw_alter_id_values = [obj[key] for key in ("aid", "alterId") if key in obj]
    if len(raw_alter_id_values) > 1 and len({str(v) for v in raw_alter_id_values}) > 1:
        raise ValueError("Conflicting VMess alterId fields")
    alter_id = _require_representable_alter_id(raw_alter_id_values[0] if raw_alter_id_values else 0)

    legacy_mkcp = network_key in ("kcp", "mkcp") and finalmask_value is None
    stream, insecure, sni, alpn_tuple, udp_bypass = build_stream_settings(
        host=host,
        transport=network,
        security=security,
        path=path,
        host_header=host_header,
        service_name=service_name,
        service_name_present=service_name_present,
        authority=str(obj.get("authority") or ""),
        mode=str(obj.get("mode") or ""),
        header_type=str(obj.get("type") or obj.get("headerType") or ""),
        # In the legacy VMess share format, path is the mKCP seed.  Some feeds
        # also carry a newer explicit seed; prefer it only when it is present.
        kcp_seed=(
            str(obj.get("seed") if obj.get("seed") is not None else "")
            if "seed" in obj
            else (path if network_key in ("kcp", "mkcp") else "")
        ),
        kcp_mtu=str(obj.get("mtu") if obj.get("mtu") is not None else "") if "mtu" in obj else None,
        kcp_tti=str(obj.get("tti") if obj.get("tti") is not None else "") if "tti" in obj else None,
        kcp_uplink=str(obj.get("uplinkCapacity") if obj.get("uplinkCapacity") is not None else "") if "uplinkCapacity" in obj else None,
        kcp_downlink=str(obj.get("downlinkCapacity") if obj.get("downlinkCapacity") is not None else "") if "downlinkCapacity" in obj else None,
        kcp_cwnd_multiplier=str(obj.get("cwndMultiplier") if obj.get("cwndMultiplier") is not None else "") if "cwndMultiplier" in obj else None,
        kcp_max_sending_window=str(obj.get("maxSendingWindow") if obj.get("maxSendingWindow") is not None else "") if "maxSendingWindow" in obj else None,
        legacy_mkcp=legacy_mkcp,
        xhttp_extra=extra_value,
        hysteria_auth=str(obj.get("auth") or obj.get("hy2auth") or obj.get("hysteriaAuth") or ""),
        hysteria_version=(str(obj.get("version") if obj.get("version") is not None else "") if "version" in obj else (str(obj.get("hysteriaVersion") if obj.get("hysteriaVersion") is not None else "") if "hysteriaVersion" in obj else None)),
        hysteria_udp_idle_timeout=str(obj.get("udpIdleTimeout") if obj.get("udpIdleTimeout") is not None else "") if "udpIdleTimeout" in obj else None,
        sni=(str(obj.get("sni") if obj.get("sni") is not None else "") if "sni" in obj else str(obj.get("serverName") if obj.get("serverName") is not None else "") if "serverName" in obj else ""),
        sni_present=("sni" in obj or "serverName" in obj),
        fp=str(obj.get("fp") or obj.get("fingerprint") or ""),
        alpn=alpn,
        allow_insecure=_parse_xray_bool(next((
            obj[key] for key in ("allowInsecure", "insecure", "skip-cert-verify")
            if key in obj
        ), None)),
        pcs=str(obj.get("pcs") or obj.get("pinnedPeerCertSha256") or ""),
        vcn=str(obj.get("vcn") or obj.get("verifyPeerCertByName") or ""),
        pbk=str(obj.get("pbk") or obj.get("password") or obj.get("publicKey") or ""),
        sid=str(obj.get("sid") or obj.get("shortId") or ""),
        spx=str(obj.get("spx") or obj.get("spiderX") or ""),
        pqv=str(obj.get("pqv") or obj.get("mldsa65Verify") or ""),
        ech_config=str(obj.get("ech") or obj.get("echConfigList") or ""),
    )
    if finalmask_value is not None:
        stream["finalmask"] = finalmask_value

    legacy_security_present = "security" in obj
    legacy_security_field = (
        str(obj.get("security") if obj.get("security") is not None else "").strip()
        if legacy_security_present
        else ""
    )
    legacy_security_key = legacy_security_field.lower()
    if "scy" in obj:
        cipher = str(obj.get("scy") if obj.get("scy") is not None else "").strip()
        cipher_present = True
    elif "cipher" in obj:
        cipher = str(obj.get("cipher") if obj.get("cipher") is not None else "").strip()
        cipher_present = True
    elif legacy_security_present and legacy_security_key not in ("tls", "reality", "none"):
        # Older VMess payloads used `security` for the account cipher.  Preserve
        # an explicitly blank value too; Xray owns the final interpretation.
        cipher = legacy_security_field
        cipher_present = True
    else:
        cipher = ""
        cipher_present = False
    settings = {
        "id": user_id,
        "security": cipher if cipher_present else "auto",
        "alterId": alter_id,
    }
    return Node(
        "vmess", index, source_raw, host, port, settings, stream,
        insecure, sni, alpn_tuple, udp_bypass,
    )
