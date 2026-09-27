from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse
from typing import Any


_XHTTP_INTEGER_FIELDS = frozenset({
    "xPaddingBytes",
    "sessionIDLength",
    "uplinkChunkSize",
    "scMaxEachPostBytes",
    "scMinPostsIntervalMs",
    "scMaxBufferedPosts",
    "scStreamUpServerSecs",
    "serverMaxHeaderBytes",
    "maxConcurrency",
    "maxConnections",
    "cMaxReuseTimes",
    "hMaxRequestTimes",
    "hMaxReusableSecs",
    "hKeepAlivePeriod",
})


def parse_query(query: str) -> dict[str, list[str]]:
    """Parse one share-link query without silently collapsing repeated fields.

    The old implementation used ``parse_qs`` and later selected the first value.
    That made ``type=ws&type=grpc`` look like a normal WebSocket node.  A
    repeated field is ambiguous source data, so reject it instead of inventing
    one interpretation.  Lookups remain case-insensitive for compatibility with
    public feeds, but case variants of the same field are also treated as a
    duplicate rather than merged.
    """
    output: dict[str, list[str]] = {}
    for raw_key, value in urllib.parse.parse_qsl(query, keep_blank_values=True):
        key = raw_key.lower()
        if key in output:
            raise ValueError(f"Duplicate query field: {raw_key}")
        output[key] = [value]
    return output


def json_loads_unique(text: str) -> Any:
    """Decode JSON without silently accepting duplicate object member names."""
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if key in output:
                raise ValueError(f"Invalid JSON duplicate field: {key}")
            output[key] = value
        return output

    return json.loads(text, object_pairs_hook=unique_object)


def qfirst(q: dict[str, list[str]], *keys: str, default: str = "") -> str:
    for key in keys:
        values = q.get(key.lower())
        if values:
            return values[0]
    return default


def qhas(q: dict[str, list[str]], *keys: str) -> bool:
    """Return whether any named field is explicitly present, even if blank."""
    return any(key.lower() in q for key in keys)


def qbool(q: dict[str, list[str]], *keys: str) -> bool:
    return qfirst(q, *keys).lower() in ("1", "true", "yes", "on")


def b64decode_loose(value: str) -> bytes:
    value = urllib.parse.unquote(value.strip()).replace("-", "+").replace("_", "/")
    return base64.b64decode(value + "=" * (-len(value) % 4), validate=False)


def b64decode_ss(value: str) -> bytes:
    """Decode common SIP002 variants without enforcing a stricter alphabet."""
    normalized = urllib.parse.unquote(value.strip()).replace("-", "+").replace("_", "/")
    padded = normalized + "=" * (-len(normalized) % 4)
    try:
        return base64.b64decode(padded, validate=False)
    except (ValueError, binascii.Error) as e:
        raise ValueError("Invalid Shadowsocks Base64") from e


def normalize_transport(value: str) -> str:
    raw_value = str(value).strip()
    key = raw_value.lower()
    aliases = {
        "tcp": "raw",
        "raw": "raw",
        "ws": "websocket",
        "websocket": "websocket",
        "grpc": "grpc",
        "gun": "grpc",
        "httpupgrade": "httpupgrade",
        "http-upgrade": "httpupgrade",
        "xhttp": "xhttp",
        "splithttp": "xhttp",
        "kcp": "mkcp",
        "mkcp": "mkcp",
        "hysteria": "hysteria",
    }
    # Unknown and removed values are forwarded unchanged. The selected Xray
    # executable, not this parser, decides whether they are accepted.
    return aliases.get(key, raw_value)


def normalize_security(value: str | None, *, default: str) -> str:
    if value is None:
        raw_value = default
    else:
        raw_value = str(value).strip()
    key = raw_value.lower()
    aliases = {
        "0": "none",
        "false": "none",
        "off": "none",
        "none": "none",
        "1": "tls",
        "true": "tls",
        "on": "tls",
        "tls": "tls",
        "reality": "reality",
    }
    # Preserve unrecognised security values so Xray can issue the final verdict.
    return aliases.get(key, raw_value)


def _parse_xray_bool(value: Any) -> bool | Any | None:
    """Normalize known booleans and forward unknown values for Xray to judge."""
    if value is None:
        return None
    if value == "":
        # Explicitly blank is not the same as absent.  Preserve it so the JSON
        # type mismatch reaches Xray instead of silently becoming the default.
        return ""
    if isinstance(value, bool):
        return value
    text = str(value).strip()
    lowered = text.lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off"):
        return False
    return value


def _parse_xray_number(value: str | None) -> int | str | None:
    if value is None:
        return None
    text = str(value).strip()
    if text == "":
        # Preserve an explicitly present blank numeric value.  Omitting it
        # would silently convert malformed source data into Xray's default.
        return ""
    try:
        return int(text, 10)
    except ValueError:
        # A JSON string deliberately reaches Xray and fails there if the field
        # is not representable as the numeric type expected by that version.
        return text


def _normalize_legacy_kcp_header(value: str) -> str:
    raw_header = (value or "").strip()
    header = raw_header.lower().replace("_", "-")
    aliases = {
        "": "",
        "none": "",
        "srtp": "srtp",
        "utp": "utp",
        "wechat": "wechat",
        "wechat-video": "wechat",
        "wechatvideo": "wechat",
        "dtls": "dtls",
        "wireguard": "wireguard",
        "dns": "dns",
    }
    return aliases.get(header, raw_header)


def _legacy_mkcp_finalmask(*, header_type: str, seed: str, dns_domain: str) -> dict[str, Any]:
    """Translate old mKCP header/seed semantics to the target Xray FinalMask."""
    header = _normalize_legacy_kcp_header(header_type)
    seed = str(seed or "")

    # Xray's FinalMask manager reverses configured mask order internally.
    # Put the legacy security layer first in JSON and header layer second so
    # the effective wire format remains header + encrypted/authenticated data.
    masks: list[dict[str, Any]] = [{
        "type": "mkcp-legacy",
        "settings": {"header": "", "value": seed},
    }]
    if header:
        masks.append({
            "type": "mkcp-legacy",
            "settings": {
                "header": header,
                "value": dns_domain if header == "dns" else "",
            },
        })
    return {"udp": masks}


def _recover_json_plus_whitespace(text: str) -> str:
    """Replace non-JSON '+' whitespace corruption without touching string data."""
    output: list[str] = []
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            output.append(char)
        elif char == "+":
            output.append(" ")
        else:
            output.append(char)
    return "".join(output)


def _normalize_xhttp_integral_numbers(value: Any, key: str = "") -> Any:
    """Convert only XHTTP integer-schema fields from integral JSON floats."""
    if type(value) is float and key in _XHTTP_INTEGER_FIELDS and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {
            item_key: _normalize_xhttp_integral_numbers(item_value, item_key)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_normalize_xhttp_integral_numbers(item) for item in value]
    return value


def _parse_xhttp_extra(text: str) -> Any:
    """Decode exact JSON only; never repair the original node in-place."""
    try:
        return json_loads_unique(text)
    except json.JSONDecodeError:
        # A JSON string deliberately reaches Xray.  If the source needs a
        # recovery, repairs.py creates a separate derived candidate.
        return text


def _parse_json_for_xray(text: str) -> Any:
    """Return decoded JSON or a string that Xray itself will reject."""
    try:
        return json_loads_unique(text)
    except json.JSONDecodeError:
        return text


def _valid_reality_short_id(value: str) -> bool:
    """Used only by the optional, post-failure repair helper."""
    return len(value) <= 16 and len(value) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]*", value) is not None


def build_stream_settings(
    *,
    host: str,
    transport: str,
    security: str,
    path: str = "/",
    host_header: str = "",
    service_name: str = "",
    service_name_present: bool = False,
    authority: str = "",
    mode: str = "",
    header_type: str = "",
    kcp_seed: str = "",
    kcp_mtu: str | None = None,
    kcp_tti: str | None = None,
    kcp_uplink: str | None = None,
    kcp_downlink: str | None = None,
    kcp_cwnd_multiplier: str | None = None,
    kcp_max_sending_window: str | None = None,
    legacy_mkcp: bool = False,
    xhttp_extra: Any = None,
    hysteria_auth: str = "",
    hysteria_version: str | None = None,
    hysteria_udp_idle_timeout: str | None = None,
    sni: str = "",
    sni_present: bool = False,
    fp: str = "",
    alpn: list[str] | None = None,
    allow_insecure: Any = None,
    pcs: str = "",
    vcn: str = "",
    pbk: str = "",
    sid: str = "",
    spx: str = "",
    pqv: str = "",
    ech_config: str = "",
) -> tuple[dict[str, Any], bool, str, tuple[str, ...], bool]:
    method = normalize_transport(transport)
    security = normalize_security(security, default="none")
    # Do not turn an explicitly blank path into '/'.  Callers decide the
    # absent-field default before reaching this function.
    path = str(path)
    alpn = [x.strip() for x in (alpn or []) if x.strip()]

    stream: dict[str, Any] = {"network": method, "security": security}
    udp_prefilter_bypass = method in ("mkcp", "hysteria", "h3", "quic")

    if method == "websocket":
        settings: dict[str, Any] = {"path": path}
        if host_header:
            settings["host"] = host_header
        stream["wsSettings"] = settings
    elif method == "grpc":
        settings = {
            "serviceName": service_name if service_name_present else path.lstrip("/")
        }
        if authority or host_header:
            settings["authority"] = authority or host_header
        grpc_mode = (mode or "").lower()
        if grpc_mode in ("multi", "multi-mode", "multimode"):
            settings["multiMode"] = True
        elif grpc_mode not in ("", "gun", "0"):
            settings["multiMode"] = mode
        stream["grpcSettings"] = settings
    elif method == "httpupgrade":
        settings = {"path": path}
        if host_header:
            settings["host"] = host_header
        stream["httpupgradeSettings"] = settings
    elif method == "xhttp":
        settings = {"path": path, "mode": mode}
        if host_header:
            settings["host"] = host_header
        if xhttp_extra is not None:
            settings["extra"] = xhttp_extra
        stream["xhttpSettings"] = settings
        if alpn and {x.lower() for x in alpn} == {"h3"}:
            udp_prefilter_bypass = True
    elif method == "mkcp":
        settings: dict[str, Any] = {}
        numeric_fields = [
            ("mtu", kcp_mtu),
            ("tti", kcp_tti),
            ("uplinkCapacity", kcp_uplink),
            ("downlinkCapacity", kcp_downlink),
            ("cwndMultiplier", kcp_cwnd_multiplier),
            ("maxSendingWindow", kcp_max_sending_window),
        ]
        for field, raw_value in numeric_fields:
            parsed = _parse_xray_number(raw_value)
            if parsed is not None:
                settings[field] = parsed
        stream["kcpSettings"] = settings
        if legacy_mkcp:
            stream["finalmask"] = _legacy_mkcp_finalmask(
                header_type=header_type,
                seed=kcp_seed,
                dns_domain=host_header,
            )
    elif method == "hysteria":
        version_value = _parse_xray_number(hysteria_version)
        settings = {
            "version": 2 if version_value is None else version_value,
            "auth": hysteria_auth,
        }
        udp_idle = _parse_xray_number(hysteria_udp_idle_timeout)
        if udp_idle is not None:
            settings["udpIdleTimeout"] = udp_idle
        stream["hysteriaSettings"] = settings
    elif method == "raw" and header_type:
        header: dict[str, Any] = {"type": header_type}
        if header_type.lower() == "http":
            request: dict[str, Any] = {"path": [path]}
            if host_header:
                request["headers"] = {"Host": [host_header]}
            header["request"] = request
        stream["rawSettings"] = {"header": header}

    if security == "tls":
        tls: dict[str, Any] = {}
        if sni_present:
            tls["serverName"] = sni
        if fp:
            tls["fingerprint"] = fp
        if alpn:
            tls["alpn"] = alpn
        if ech_config:
            tls["echConfigList"] = ech_config
        if pcs:
            tls["pinnedPeerCertSha256"] = pcs
        if vcn:
            tls["verifyPeerCertByName"] = vcn
        if allow_insecure is True or (
            allow_insecure is not None and allow_insecure is not False
        ):
            tls["allowInsecure"] = allow_insecure
        stream["tlsSettings"] = tls
        return stream, allow_insecure is True, sni, tuple(alpn), udp_prefilter_bypass

    if security == "reality":
        reality: dict[str, Any] = {
            "serverName": sni if sni_present else host,
            "password": pbk,
            "shortId": sid,
            "spiderX": spx,
        }
        if fp:
            reality["fingerprint"] = fp
        if pqv:
            reality["mldsa65Verify"] = pqv
        stream["realitySettings"] = reality

    return stream, False, "", (), udp_prefilter_bypass


def stream_from_query(
    host: str,
    q: dict[str, list[str]],
    *,
    default_security: str,
) -> tuple[dict[str, Any], bool, str, tuple[str, ...], bool]:
    transport_present = qhas(q, "type", "network", "net")
    transport = qfirst(q, "type", "network", "net")
    if not transport_present and qbool(q, "ws"):
        transport = "ws"
        transport_present = True
    if not transport_present:
        transport = "tcp"

    security_present = qhas(q, "security", "tls")
    security = normalize_security(
        qfirst(q, "security", "tls") if security_present else None,
        default=default_security,
    )
    path = qfirst(q, "path", "wspath", default="/")
    alpn_text = qfirst(q, "alpn")
    alpn = [x.strip() for x in alpn_text.split(",") if x.strip()]

    finalmask_present = qhas(q, "fm", "finalmask")
    finalmask_text = qfirst(q, "fm", "finalmask")
    finalmask = _parse_json_for_xray(finalmask_text) if finalmask_present else None
    extra_present = qhas(q, "extra")
    extra_text = qfirst(q, "extra")
    xhttp_extra = _parse_xhttp_extra(extra_text) if extra_present else None
    legacy_kcp_fields = bool(qfirst(q, "headertype", "header-type", "seed"))

    stream, insecure, tls_sni, tls_alpn, udp_bypass = build_stream_settings(
        host=host,
        transport=transport,
        security=security,
        path=path,
        host_header=qfirst(q, "host", "authority"),
        service_name=qfirst(q, "servicename", "service-name", "grpc-service-name", "service_name"),
        service_name_present=qhas(q, "servicename", "service-name", "grpc-service-name", "service_name"),
        authority=qfirst(q, "authority"),
        mode=qfirst(q, "mode"),
        header_type=qfirst(q, "headertype", "header-type"),
        kcp_seed=qfirst(q, "seed"),
        kcp_mtu=qfirst(q, "mtu") if qhas(q, "mtu") else None,
        kcp_tti=qfirst(q, "tti") if qhas(q, "tti") else None,
        kcp_uplink=qfirst(q, "uplinkcapacity", "uplink-capacity") if qhas(q, "uplinkcapacity", "uplink-capacity") else None,
        kcp_downlink=qfirst(q, "downlinkcapacity", "downlink-capacity") if qhas(q, "downlinkcapacity", "downlink-capacity") else None,
        kcp_cwnd_multiplier=qfirst(q, "cwndmultiplier", "cwnd-multiplier") if qhas(q, "cwndmultiplier", "cwnd-multiplier") else None,
        kcp_max_sending_window=qfirst(q, "maxsendingwindow", "max-sending-window") if qhas(q, "maxsendingwindow", "max-sending-window") else None,
        legacy_mkcp=legacy_kcp_fields and finalmask is None,
        xhttp_extra=xhttp_extra,
        hysteria_auth=qfirst(q, "auth", "hy2auth", "hysteriaauth", "hysteria-auth"),
        hysteria_version=qfirst(q, "version", "hysteriaversion", "hysteria-version") if qhas(q, "version", "hysteriaversion", "hysteria-version") else None,
        hysteria_udp_idle_timeout=qfirst(q, "udpidletimeout", "udp-idle-timeout") if qhas(q, "udpidletimeout", "udp-idle-timeout") else None,
        sni=qfirst(q, "sni", "servername", "server-name", "peer"),
        sni_present=qhas(q, "sni", "servername", "server-name", "peer"),
        fp=qfirst(q, "fp", "fingerprint", "client-fingerprint"),
        alpn=alpn,
        allow_insecure=_parse_xray_bool(
            qfirst(
                q,
                "allowinsecure",
                "allow_insecure",
                "allow-insecure",
                "insecure",
                "skip-cert-verify",
                "skip_cert_verify",
            )
            if qhas(
                q,
                "allowinsecure",
                "allow_insecure",
                "allow-insecure",
                "insecure",
                "skip-cert-verify",
                "skip_cert_verify",
            )
            else None
        ),
        pcs=qfirst(q, "pcs", "pinnedpeercertsha256", "pinned-peer-cert-sha256"),
        vcn=qfirst(q, "vcn", "verifypeercertbyname", "verify-peer-cert-by-name"),
        pbk=qfirst(q, "pbk", "password", "publickey", "public-key"),
        sid=qfirst(q, "sid", "shortid", "short-id"),
        spx=qfirst(q, "spx", "spiderx"),
        pqv=qfirst(q, "pqv", "mldsa65verify"),
        ech_config=qfirst(q, "ech", "echconfiglist", "ech-config-list"),
    )
    if finalmask is not None:
        stream["finalmask"] = finalmask
    return stream, insecure, tls_sni, tls_alpn, udp_bypass
