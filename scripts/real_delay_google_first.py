#!/usr/bin/env python3
"""Use a real Google TCP CONNECT through Xray as the sole health test."""
from __future__ import annotations

import json
import socket
import time
from pathlib import Path

import real_delay

GOOGLE_TCP_HOST = "www.google.com"
GOOGLE_TCP_PORT = 443


def socks_tcp_connect(port: int, host: str, remote_port: int, timeout: float):
    """Perform a real SOCKS5 CONNECT through Xray to host:remote_port."""
    started = time.perf_counter()
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2) != b"\x05\x00":
            return False, -1, "socks-auth"

        host_bytes = host.encode("idna")
        if len(host_bytes) > 255:
            return False, -1, "host-too-long"
        sock.sendall(
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + int(remote_port).to_bytes(2, "big")
        )

        reply = sock.recv(4)
        if len(reply) != 4:
            return False, -1, "short-socks-reply"
        if reply[0] != 5:
            return False, -1, "invalid-socks-version"
        if reply[1] != 0:
            return False, -1, f"socks-connect-failed-{reply[1]}"

        atyp = reply[3]
        if atyp == 1:
            remaining = 4
        elif atyp == 3:
            length = sock.recv(1)
            if len(length) != 1:
                return False, -1, "short-domain-length"
            remaining = length[0]
        elif atyp == 4:
            remaining = 16
        else:
            return False, -1, "invalid-socks-atyp"

        data = bytearray()
        while len(data) < remaining:
            chunk = sock.recv(remaining - len(data))
            if not chunk:
                return False, -1, "short-socks-address"
            data.extend(chunk)
        port_bytes = sock.recv(2)
        if len(port_bytes) != 2:
            return False, -1, "short-socks-port"

        return True, round((time.perf_counter() - started) * 1000, 1), "TCP CONNECT succeeded"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def probe(item: dict, timeout: float) -> dict:
    """Google TCP CONNECT is the complete and only health test."""
    try:
        google_ok, google_latency, google_detail = socks_tcp_connect(
            item["port"], GOOGLE_TCP_HOST, GOOGLE_TCP_PORT, timeout
        )
    except Exception as exc:
        google_ok = False
        google_latency = -1
        google_detail = str(exc)[:180]

    details = {
        "google_tcp": {
            "ok": google_ok,
            "latency_ms": google_latency if google_ok else -1,
            "detail": google_detail,
            "host": GOOGLE_TCP_HOST,
            "port": GOOGLE_TCP_PORT,
        }
    }

    return {
        "index": item["index"],
        "google_tcp_ok": google_ok,
        "msft_ok": False,
        "google_204_ok": False,
        "firefox_ok": False,
        "internet_healthy": google_ok,
        "delay_ms": google_latency if google_ok else -1,
        "details": details,
        "alive": google_ok,
    }


def main() -> None:
    # Disable the old HTTP probe loop completely. Google TCP is the sole gate.
    real_delay.PROBES = ()
    real_delay.probe = probe
    real_delay.main()

    report_path = Path(real_delay.OUT) / "metadata" / "real_delay.json"
    if report_path.is_file():
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        payload["health_gate"] = {
            "url": "tcp://www.google.com:443",
            "type": "real_socks5_tcp_connect_through_xray",
            "required": True,
            "description": "A node is Healthy only when a real SOCKS5 TCP CONNECT through Xray to www.google.com:443 succeeds.",
        }
        payload["probes"] = {
            "google_tcp": {
                "url": "tcp://www.google.com:443",
                "type": "SOCKS5 CONNECT",
                "required": True,
            }
        }
        report_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # Keep the generated metadata consistent with the sole Google health policy.
    for name in ("index.json", "health.json"):
        path = Path(real_delay.OUT) / "metadata" / name
        if not path.is_file():
            continue
        meta = json.loads(path.read_text(encoding="utf-8"))
        meta["health_policy"] = "Google TCP CONNECT only: real SOCKS5 CONNECT through Xray to www.google.com:443"
        path.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
