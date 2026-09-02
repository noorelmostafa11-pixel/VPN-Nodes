#!/usr/bin/env python3
"""Fast full-pool transport validation without launching a proxy core.

Every TCP-reachable node is classified and syntax-validated. When the advertised
transport can be tested independently of protocol credentials, this module performs
that handshake directly against the server:

* TLS: real TLS ClientHello/SNI handshake (certificate verification intentionally off).
* WebSocket: Xray-like HTTP/1.1 WebSocket upgrade request.
* HTTPUpgrade: Xray-like fake WebSocket upgrade request, without WebSocket-only headers.
* gRPC / HTTP/2: TLS+ALPN h2 (when TLS is advertised) plus HTTP/2 preface/SETTINGS.
* REALITY, Shadowsocks and plain raw TCP cannot be authenticated without a protocol
  core, so they retain the already-proven TCP liveness after strict URI validation.

WebSocket and HTTPUpgrade failures are intentionally non-destructive. A generic
Python/OpenSSL probe cannot reproduce Xray's uTLS/browser fingerprint exactly and
CDNs/WAFs can reject the probe while Xray still works. HTTP 101 upgrades are marked
verified and ranked first; failed WS/HTTPUpgrade probes remain publishable at a lower
health score for the Android app's final Xray/runtime check.

A failed active handshake is retried once to reduce transient false negatives.
"""
from __future__ import annotations

import asyncio
import base64
import html
import json
import os
import ssl
import time
import urllib.parse
from collections import Counter
from typing import Any

HANDSHAKE_WORKERS = int(os.environ.get("TRANSPORT_HANDSHAKE_WORKERS", "256"))
HANDSHAKE_TIMEOUT = float(os.environ.get("TRANSPORT_HANDSHAKE_TIMEOUT", "2.5"))
HANDSHAKE_ROUNDS = 2

ACTIVE_MODES = {"tls", "websocket", "httpupgrade", "http2"}
SOFT_FAIL_MODES = {"websocket", "httpupgrade"}

# Xray currently applies browser-like headers to WS/HTTPUpgrade requests. We mirror
# the stable semantics that matter to CDNs; the TLS ClientHello itself still cannot
# reproduce Xray/uTLS exactly, which is why WS/HTTPUpgrade failure is non-gating.
_XRAY_WS_HEADERS = (
    ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"),
    ("Accept", "*/*"),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("Cache-Control", "no-cache"),
    ("Pragma", "no-cache"),
    ("Sec-Fetch-Dest", "empty"),
    ("Sec-Fetch-Mode", "websocket"),
    ("Sec-Fetch-Site", "same-origin"),
)


def _b64d(value: str) -> bytes:
    value = value.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(value + "=" * (-len(value) % 4))


def _first(query: dict[str, list[str]], *keys: str, default: str = "") -> str:
    for key in keys:
        values = query.get(key)
        if values:
            return urllib.parse.unquote(values[0])
    return default


def _split_host(value: str) -> str:
    return (value or "").split(",", 1)[0].strip()


def _clean_uri(uri: str) -> str:
    # Telegram/web scrapers sometimes preserve HTML entities inside query strings.
    # "&amp;security=tls" must become "&security=tls" before parse_qs().
    return html.unescape(str(uri or "").strip())


def _truthy(value: str) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "ws", "websocket"}


def _normal_network(value: str) -> str:
    value = str(value or "").strip().lower()
    return {
        "": "tcp",
        "raw": "tcp",
        "websocket": "ws",
        "http-upgrade": "httpupgrade",
    }.get(value, value)


def _normal_security(value: str, scheme: str, port: int) -> str:
    value = str(value or "").strip().lower()
    if value in {"1", "true"}:
        value = "tls"
    if scheme == "trojan" and value in {"", "none", "false", "0"}:
        return "tls"
    if value in {"", "none", "false", "0"}:
        return "none"
    return value


def parse_transport(uri: str) -> dict[str, Any]:
    """Parse only the fields needed for independent transport validation."""
    uri = _clean_uri(uri)
    scheme = urllib.parse.urlsplit(uri).scheme.lower()

    if scheme == "vmess":
        raw = uri.split("vmess://", 1)[1].split("#", 1)[0]
        obj = json.loads(_b64d(raw).decode("utf-8-sig"))
        server = str(obj.get("add") or obj.get("address") or "").strip()
        port = int(obj.get("port") or 0)
        uuid = str(obj.get("id") or "").strip()
        if not server or port <= 0 or len(uuid) < 10:
            raise ValueError("invalid-vmess-identity")
        network = _normal_network(str(obj.get("net") or obj.get("type") or "tcp"))
        tls_enabled = str(obj.get("tls") or "").strip().lower() not in ("", "none", "false", "0")
        host = _split_host(str(obj.get("host") or ""))
        sni = str(obj.get("sni") or host or server).strip()
        return {
            "scheme": "vmess",
            "server": server,
            "port": port,
            "network": network,
            "security": "tls" if tls_enabled else "none",
            "sni": sni,
            "host": host,
            "path": str(obj.get("path") or "/"),
            "service_name": str(obj.get("serviceName") or obj.get("service_name") or ""),
        }

    if scheme == "ss":
        raw = uri.split("ss://", 1)[1].split("#", 1)[0]
        raw_no_query = raw.split("?", 1)[0]
        if "@" in raw_no_query:
            userinfo, hp = raw_no_query.rsplit("@", 1)
            try:
                decoded_user = _b64d(userinfo).decode("utf-8")
                if ":" in decoded_user:
                    userinfo = decoded_user
                else:
                    userinfo = urllib.parse.unquote(userinfo)
            except Exception:
                userinfo = urllib.parse.unquote(userinfo)
        else:
            decoded = _b64d(raw_no_query).decode("utf-8")
            if "@" not in decoded:
                raise ValueError("invalid-shadowsocks-endpoint")
            userinfo, hp = decoded.rsplit("@", 1)

        hp_parsed = urllib.parse.urlsplit("//" + hp)
        server = hp_parsed.hostname or ""
        port = hp_parsed.port or 0
        if not server or port <= 0:
            raise ValueError("invalid-shadowsocks-endpoint")
        if ":" not in userinfo:
            raise ValueError("invalid-shadowsocks-credentials")
        method, password = userinfo.split(":", 1)
        if not method.strip() or not password:
            raise ValueError("invalid-shadowsocks-credentials")
        return {
            "scheme": "ss",
            "server": server,
            "port": port,
            "network": "tcp",
            "security": "none",
            "sni": server,
            "host": "",
            "path": "/",
            "service_name": "",
        }

    parsed = urllib.parse.urlsplit(uri)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    server = parsed.hostname or ""
    port = parsed.port or (443 if scheme in {"vless", "trojan"} else 0)
    if not server or port <= 0:
        raise ValueError("invalid-endpoint")

    security_value = _first(query, "security", "tls", default="")
    security = _normal_security(security_value, scheme, port)

    if scheme == "vless":
        identity = urllib.parse.unquote(parsed.username or "").strip()
        if len(identity) < 10:
            raise ValueError("invalid-vless-uuid")
        pbk = _first(query, "pbk", "publicKey")
        # Public-key/short-id fields are Reality-specific. Some public share links
        # incorrectly label them as security=tls; infer Reality rather than running
        # a destructive generic TLS probe against a Reality endpoint.
        if pbk:
            if len(pbk.strip()) < 20:
                raise ValueError("invalid-reality-public-key")
            security = "reality"
        elif security == "reality":
            raise ValueError("invalid-reality-public-key")
    elif scheme == "trojan":
        if not urllib.parse.unquote(parsed.username or "").strip():
            raise ValueError("invalid-trojan-password")
    else:
        raise ValueError("unsupported-protocol")

    host = _split_host(_first(query, "host", "wsHost", "ws-host"))
    sni = _first(query, "sni", "serverName", "servername", default=host or server).strip()

    network = _normal_network(_first(query, "type", "net", default="tcp"))
    legacy_ws = _truthy(_first(query, "ws")) or bool(_first(query, "wspath"))
    if network == "tcp" and legacy_ws:
        network = "ws"

    path = _first(query, "path", "wspath", default="/") or "/"
    return {
        "scheme": scheme,
        "server": server,
        "port": port,
        "network": network,
        "security": security,
        "sni": sni or server,
        "host": host,
        "path": path,
        "service_name": _first(query, "serviceName", "service_name"),
    }


def classify_mode(node: dict[str, Any]) -> str:
    network = _normal_network(str(node.get("network") or "tcp"))
    security = str(node.get("security") or "none").lower()
    scheme = str(node.get("scheme") or "").lower()

    if security == "reality":
        return "reality-tcp"
    if scheme == "ss":
        return "shadowsocks-tcp"
    if network == "ws":
        return "websocket"
    if network in {"grpc", "http", "h2"}:
        return "http2"
    if network == "httpupgrade":
        return "httpupgrade"
    if security == "tls" or scheme == "trojan":
        return "tls"
    return "plain-tcp"


def _ssl_context(alpn: list[str] | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(alpn)
    return ctx


async def _open(node: dict[str, Any], use_tls: bool, alpn: list[str] | None = None):
    kwargs: dict[str, Any] = {}
    if use_tls:
        kwargs.update(
            ssl=_ssl_context(alpn),
            server_hostname=str(node.get("sni") or node["server"]),
            ssl_handshake_timeout=HANDSHAKE_TIMEOUT,
        )
    return await asyncio.wait_for(
        asyncio.open_connection(str(node["server"]), int(node["port"]), **kwargs),
        timeout=HANDSHAKE_TIMEOUT,
    )


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


async def _probe_tls(node: dict[str, Any]) -> tuple[bool, str]:
    _, writer = await _open(node, True, ["h2", "http/1.1"])
    await _close(writer)
    return True, "tls-ok"


def _request_target(path: str) -> str:
    path = str(path or "/").strip() or "/"
    if not path.startswith("/"):
        path = "/" + path
    # The path may contain Xray early-data query parameters (e.g. ?ed=2560).
    # Preserve '%' to avoid double-encoding already escaped source paths.
    return urllib.parse.quote(path, safe="/?&=:%+,-._~!$'()*;@%")


def _upgrade_request(node: dict[str, Any], mode: str) -> bytes:
    host = _split_host(str(node.get("host") or "")) or str(node.get("sni") or node["server"])
    target = _request_target(str(node.get("path") or "/"))
    lines = [
        f"GET {target} HTTP/1.1",
        f"Host: {host}",
    ]
    lines.extend(f"{key}: {value}" for key, value in _XRAY_WS_HEADERS)
    lines.extend(("Connection: Upgrade", "Upgrade: websocket"))

    if mode == "websocket":
        # Standard WS requires these. Xray's HTTPUpgrade deliberately does not.
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        lines.extend(("Sec-WebSocket-Version: 13", f"Sec-WebSocket-Key: {key}"))

    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii", errors="ignore")


def _parse_http_head(header: bytes) -> tuple[int, dict[str, str]]:
    lines = header.decode("latin-1", errors="replace").split("\r\n")
    parts = lines[0].split()
    status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    fields: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip().lower()] = value.strip()
    return status, fields


async def _probe_upgrade(node: dict[str, Any], mode: str) -> tuple[bool, str]:
    use_tls = str(node.get("security") or "none").lower() == "tls" or node.get("scheme") == "trojan"
    reader, writer = await _open(node, use_tls, ["http/1.1"] if use_tls else None)
    try:
        writer.write(_upgrade_request(node, mode))
        await writer.drain()
        header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=HANDSHAKE_TIMEOUT)
        status, fields = _parse_http_head(header)
        if status == 101:
            connection = fields.get("connection", "").lower()
            upgrade = fields.get("upgrade", "").lower()
            if "upgrade" in connection and upgrade == "websocket":
                return True, f"{mode}-101"
            return False, f"{mode}-invalid-101"
        return False, f"{mode}-status-{status or 'none'}"
    finally:
        await _close(writer)


async def _probe_http2(node: dict[str, Any]) -> tuple[bool, str]:
    use_tls = str(node.get("security") or "none").lower() == "tls" or node.get("scheme") == "trojan"
    reader, writer = await _open(node, use_tls, ["h2"] if use_tls else None)
    try:
        if use_tls:
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj is None or ssl_obj.selected_alpn_protocol() != "h2":
                return False, "http2-alpn-mismatch"
        # HTTP/2 connection preface + empty SETTINGS frame.
        writer.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
        await writer.drain()
        frame_header = await asyncio.wait_for(reader.readexactly(9), timeout=HANDSHAKE_TIMEOUT)
        frame_type = frame_header[3]
        if frame_type == 4:
            return True, "http2-settings"
        return False, f"http2-frame-{frame_type}"
    finally:
        await _close(writer)


async def probe_transport(node: dict[str, Any], mode: str) -> tuple[bool, str, float]:
    started = time.perf_counter()
    try:
        if mode == "tls":
            ok, reason = await _probe_tls(node)
        elif mode == "websocket":
            ok, reason = await _probe_upgrade(node, "websocket")
        elif mode == "httpupgrade":
            ok, reason = await _probe_upgrade(node, "httpupgrade")
        elif mode == "http2":
            ok, reason = await _probe_http2(node)
        else:
            return True, mode, 0.0
        return ok, reason, round((time.perf_counter() - started) * 1000, 1)
    except asyncio.TimeoutError:
        return False, "timeout", round((time.perf_counter() - started) * 1000, 1)
    except ssl.SSLError as exc:
        return False, f"tls-error-{getattr(exc, 'reason', 'ssl')}", round((time.perf_counter() - started) * 1000, 1)
    except ConnectionResetError:
        return False, "connection-reset", round((time.perf_counter() - started) * 1000, 1)
    except ConnectionRefusedError:
        return False, "connection-refused", round((time.perf_counter() - started) * 1000, 1)
    except Exception as exc:
        return False, f"{type(exc).__name__.lower()}", round((time.perf_counter() - started) * 1000, 1)


async def _run_round(items: list[dict[str, Any]], round_no: int) -> dict[int, tuple[bool, str, float]]:
    semaphore = asyncio.Semaphore(HANDSHAKE_WORKERS)
    results: dict[int, tuple[bool, str, float]] = {}
    total = len(items)
    completed = 0

    async def one(entry: dict[str, Any]) -> None:
        nonlocal completed
        async with semaphore:
            result = await probe_transport(entry["node"], entry["mode"])
        results[entry["index"]] = result
        completed += 1
        if completed % 2000 == 0 or completed == total:
            passed = sum(1 for ok, _, _ in results.values() if ok)
            print(f"INFO handshake_round={round_no} progress={completed}/{total} passed={passed}")

    await asyncio.gather(*(one(entry) for entry in items))
    return results


async def run_transport_checks(rows: list[dict]) -> tuple[list[dict], dict]:
    """Validate all TCP-reachable rows and return the publishable subset + stats."""
    started = time.perf_counter()
    accepted: list[dict] = []
    active: list[dict[str, Any]] = []
    parse_failed = Counter()
    mode_counts = Counter()
    protocol_counts = Counter()
    syntax_only_count = 0

    for index, row in enumerate(rows):
        uri = str(row.get("uri") or "").strip()
        protocol = str(row.get("protocol") or "unknown").lower()
        try:
            node = parse_transport(uri)
            mode = classify_mode(node)
        except Exception as exc:
            parse_failed[str(exc) or type(exc).__name__] += 1
            continue

        protocol_counts[protocol] += 1
        mode_counts[mode] += 1
        if mode not in ACTIVE_MODES:
            syntax_only_count += 1
            accepted.append({
                **row,
                "handshake_mode": mode,
                "handshake_status": "tcp-plus-syntax",
                "handshake_latency_ms": None,
                "health_score": 60,
            })
        else:
            active.append({"index": index, "row": row, "node": node, "mode": mode, "protocol": protocol})

    first_round = await _run_round(active, 1) if active else {}
    retry_entries = [entry for entry in active if not first_round.get(entry["index"], (False, "missing", 0))[0]]
    second_round = await _run_round(retry_entries, 2) if retry_entries else {}

    failures = Counter()
    passed_by_mode = Counter()
    failed_by_mode = Counter()
    soft_failed_by_mode = Counter()
    hard_failed_by_mode = Counter()
    passed_by_protocol = Counter()
    failed_by_protocol = Counter()
    soft_publishable_by_protocol = Counter()
    retry_passed = 0
    soft_publishable = 0

    for entry in active:
        index = entry["index"]
        first = first_round.get(index, (False, "missing-result", 0.0))
        final = first
        if not first[0]:
            final = second_round.get(index, first)
            if final[0]:
                retry_passed += 1

        ok, reason, latency = final
        if ok:
            passed_by_mode[entry["mode"]] += 1
            passed_by_protocol[entry["protocol"]] += 1
            accepted.append({
                **entry["row"],
                "handshake_mode": entry["mode"],
                "handshake_status": reason,
                "handshake_latency_ms": latency,
                "health_score": 100,
            })
            continue

        failures[reason] += 1
        failed_by_mode[entry["mode"]] += 1
        failed_by_protocol[entry["protocol"]] += 1

        if entry["mode"] in SOFT_FAIL_MODES:
            # Preserve TCP-live, syntax-valid WS/HTTPUpgrade nodes. Generic OpenSSL
            # probes can be rejected by CDN/WAF/uTLS fingerprint policy even when
            # the same config succeeds through Xray on Android.
            soft_publishable += 1
            soft_failed_by_mode[entry["mode"]] += 1
            soft_publishable_by_protocol[entry["protocol"]] += 1
            accepted.append({
                **entry["row"],
                "handshake_mode": entry["mode"],
                "handshake_status": f"unverified-{reason}",
                "handshake_latency_ms": latency,
                "health_score": 50,
            })
        else:
            hard_failed_by_mode[entry["mode"]] += 1

    accepted.sort(key=lambda item: str(item.get("uri") or ""))
    active_passed = sum(passed_by_mode.values())
    active_failed = sum(failed_by_mode.values())
    hard_rejected = len(rows) - len(accepted)

    stats = {
        "schema": 2,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "input_tcp_reachable": len(rows),
        "checked_total": len(rows),
        "active_handshake_checked": len(active),
        "tcp_syntax_only": syntax_only_count,
        "active_handshake_verified": active_passed,
        "active_handshake_failed": active_failed,
        "soft_failed_publishable": soft_publishable,
        "hard_rejected": hard_rejected,
        "passed_total": len(accepted),
        "rejected_total": hard_rejected,
        "parse_rejected": sum(parse_failed.values()),
        "active_handshake_passed": active_passed,
        "retry_passed": retry_passed,
        "workers": HANDSHAKE_WORKERS,
        "timeout_seconds": HANDSHAKE_TIMEOUT,
        "rounds": HANDSHAKE_ROUNDS,
        "soft_fail_modes": sorted(SOFT_FAIL_MODES),
        "elapsed_seconds": round(time.perf_counter() - started, 2),
        "mode_counts": dict(sorted(mode_counts.items())),
        "passed_by_mode": dict(sorted(passed_by_mode.items())),
        "failed_by_mode": dict(sorted(failed_by_mode.items())),
        "soft_failed_by_mode": dict(sorted(soft_failed_by_mode.items())),
        "hard_failed_by_mode": dict(sorted(hard_failed_by_mode.items())),
        "protocol_counts": dict(sorted(protocol_counts.items())),
        "passed_by_protocol": dict(sorted(passed_by_protocol.items())),
        "failed_by_protocol": dict(sorted(failed_by_protocol.items())),
        "soft_publishable_by_protocol": dict(sorted(soft_publishable_by_protocol.items())),
        "parse_failure_reasons": [{"reason": k, "count": v} for k, v in parse_failed.most_common(10)],
        "top_failure_reasons": [{"reason": k, "count": v} for k, v in failures.most_common(10)],
    }
    print(
        f"INFO TRANSPORT_HANDSHAKE checked={stats['checked_total']} "
        f"active={stats['active_handshake_checked']} syntax_only={stats['tcp_syntax_only']} "
        f"verified={stats['active_handshake_verified']} soft_publishable={stats['soft_failed_publishable']} "
        f"published={stats['passed_total']} hard_rejected={stats['hard_rejected']} "
        f"retry_passed={stats['retry_passed']} elapsed={stats['elapsed_seconds']}s"
    )
    return accepted, stats
