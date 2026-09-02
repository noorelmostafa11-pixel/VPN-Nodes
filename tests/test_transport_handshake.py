#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import transport_handshake as th


def vmess_uri(**overrides) -> str:
    obj = {
        "v": "2",
        "ps": "test",
        "add": "example.com",
        "port": "443",
        "id": "11111111-1111-1111-1111-111111111111",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": "cdn.example.com",
        "path": "/ws",
        "tls": "tls",
        "sni": "cdn.example.com",
    }
    obj.update(overrides)
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return "vmess://" + base64.b64encode(raw).decode().rstrip("=")


def check(uri: str, expected: str) -> dict:
    node = th.parse_transport(uri)
    actual = th.classify_mode(node)
    assert actual == expected, (actual, expected, node)
    return node


def main() -> None:
    check(
        "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=cdn.example.com&type=tcp",
        "tls",
    )
    check(
        "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=cdn.example.com&type=ws&host=cdn.example.com&path=%2Fws",
        "websocket",
    )
    check(
        "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=cdn.example.com&type=grpc&serviceName=test",
        "http2",
    )
    check(
        "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&sni=www.example.com&pbk=abcdefghijklmnopqrstuvwxyzABCDE&type=tcp",
        "reality-tcp",
    )
    check("trojan://secret@example.com:443?sni=cdn.example.com&type=tcp", "tls")
    check("ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:443", "shadowsocks-tcp")
    check(vmess_uri(), "websocket")

    # HTML-escaped query separators must be normalized before transport parsing.
    escaped = check(
        "vless://11111111-1111-1111-1111-111111111111@example.com:443?"
        "type=ws&amp;security=tls&amp;sni=cdn.example.com&amp;host=cdn.example.com&amp;path=%2Fsocket",
        "websocket",
    )
    assert escaped["security"] == "tls"
    assert escaped["sni"] == "cdn.example.com"
    assert escaped["host"] == "cdn.example.com"
    assert escaped["path"] == "/socket"

    # Legacy share links that use ws=1 / wspath still need WS validation.
    legacy = check(
        "trojan://secret@example.com:443?ws=1&wspath=%2Flegacy&sni=cdn.example.com",
        "websocket",
    )
    assert legacy["path"] == "/legacy"

    # A Reality public key is authoritative even when a broken source says security=tls.
    inferred = check(
        "vless://11111111-1111-1111-1111-111111111111@example.com:443?"
        "security=tls&pbk=abcdefghijklmnopqrstuvwxyzABCDE&sid=1234&sni=www.example.com&type=raw",
        "reality-tcp",
    )
    assert inferred["security"] == "reality"

    # SIP002 Shadowsocks form with the entire method:password@endpoint base64 encoded.
    ss_full = base64.b64encode(b"aes-128-gcm:password@example.com:443").decode().rstrip("=")
    ss = check("ss://" + ss_full, "shadowsocks-tcp")
    assert ss["server"] == "example.com" and ss["port"] == 443

    # WebSocket and HTTPUpgrade intentionally have different wire headers in Xray.
    node = {
        "server": "203.0.113.7",
        "port": 443,
        "scheme": "vless",
        "security": "tls",
        "sni": "cdn.example.com",
        "host": "edge.example.com",
        "path": "/ws?ed=2560",
    }
    ws_request = th._upgrade_request(node, "websocket").decode("ascii")
    hup_request = th._upgrade_request(node, "httpupgrade").decode("ascii")
    assert "GET /ws?ed=2560 HTTP/1.1" in ws_request
    assert "Host: edge.example.com" in ws_request
    assert "Sec-WebSocket-Version: 13" in ws_request
    assert "Sec-WebSocket-Key:" in ws_request
    assert "Sec-WebSocket-Version:" not in hup_request
    assert "Sec-WebSocket-Key:" not in hup_request
    assert "Connection: Upgrade" in hup_request
    assert "Upgrade: websocket" in hup_request

    # WS/HTTPUpgrade active-probe failure is soft/non-destructive; TLS failure remains hard.
    original_probe = th.probe_transport

    async def always_fail(node, mode):
        return False, f"{mode}-synthetic-failure", 1.0

    th.probe_transport = always_fail
    try:
        rows = [
            {
                "uri": "vless://11111111-1111-1111-1111-111111111111@example.com:443?"
                       "type=ws&security=tls&sni=cdn.example.com&host=cdn.example.com&path=%2Fws",
                "protocol": "vless",
            },
            {
                "uri": "vless://22222222-2222-2222-2222-222222222222@example.net:443?"
                       "type=tcp&security=tls&sni=cdn.example.net",
                "protocol": "vless",
            },
        ]
        accepted, stats = asyncio.run(th.run_transport_checks(rows))
        assert len(accepted) == 1
        assert accepted[0]["handshake_mode"] == "websocket"
        assert accepted[0]["handshake_status"].startswith("unverified-")
        assert accepted[0]["health_score"] == 50
        assert stats["soft_failed_publishable"] == 1
        assert stats["hard_rejected"] == 1
    finally:
        th.probe_transport = original_probe

    try:
        th.parse_transport(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?"
            "security=reality&pbk=short&type=tcp"
        )
    except ValueError as exc:
        assert str(exc) == "invalid-reality-public-key"
    else:
        raise AssertionError("invalid REALITY public key was accepted")

    print("transport handshake parser/classifier/policy tests: PASS")


if __name__ == "__main__":
    main()
