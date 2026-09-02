#!/usr/bin/env python3
from __future__ import annotations

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


def check(uri: str, expected: str) -> None:
    node = th.parse_transport(uri)
    actual = th.classify_mode(node)
    assert actual == expected, (actual, expected, node)


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

    try:
        th.parse_transport(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&pbk=short&type=tcp"
        )
    except ValueError as exc:
        assert str(exc) == "invalid-reality-public-key"
    else:
        raise AssertionError("invalid REALITY public key was accepted")

    print("transport handshake parser/classifier tests: PASS")


if __name__ == "__main__":
    main()
