#!/usr/bin/env python3
"""Run the real-delay health scan with a real Google TCP gate first."""
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
        hello = sock.recv(2)
        if hello != b"\x05\x00":
            return False, -1, "socks-auth"

        host_bytes = host.encode("idna")
        if len(host_bytes) > 255:
            return False, -1, "host-too-long"
        request = (
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + int(remote_port).to_bytes(2, "big")
        )
        sock.sendall(request)

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
        if remaining:
            data = bytearray()
            while len(data) < remaining:
                chunk = sock.recv(remaining - len(data))
                if not chunk:
                    return False, -1, "short-socks-address"
                data.extend(chunk)
        port_bytes = sock.recv(2)
        if len(port_bytes) != 2:
            return False, -1, "short-socks-port"

        return True, round((time.perf_counter() - started) * 1000, 1), "TCP CONNECT 200"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def probe(item: dict, timeout: float) -> dict:
    """Google TCP is the gate; HTTP probes run only after it succeeds."""
    details = {}
    google_ok = False
    google_latency = -1
    try:
        google_ok, google_latency, google_detail = socks_tcp_connect(
            item["port"], GOOGLE_TCP_HOST, GOOGLE_TCP_PORT, timeout
        )
    except Exception as exc:
        google_detail = str(exc)[:180]

    details["google_tcp"] = {
        "ok": google_ok,
        "latency_ms": google_latency if google_ok else -1,
        "detail": google_detail,
        "host": GOOGLE_TCP_HOST,
        "port": GOOGLE_TCP_PORT,
    }

    if not google_ok:
        return {
            "index": item["index"],
            "google_tcp_ok": False,
            "msft_ok": False,
            "google_204_ok": False,
            "firefox_ok": False,
            "internet_healthy": False,
            "delay_ms": -1,
            "details": details,
            "alive": False,
        }

    delays = [google_latency]
    for name, host, path, tls, status, body in real_delay.PROBES:
        try:
            ok, lat, detail = real_delay.socks_http(
                item["port"], host, path, tls, status, body, timeout
            )
        except Exception as exc:
            ok, lat, detail = False, -1, str(exc)[:180]
        details[name] = {
            "ok": ok,
            "latency_ms": lat if ok else -1,
            "detail": detail,
        }
        if ok:
            delays.append(lat)

    healthy = all(details[name]["ok"] for name, *_ in real_delay.PROBES)
    return {
        "index": item["index"],
        "google_tcp_ok": True,
        "msft_ok": details["microsoft_connect_test"]["ok"],
        "google_204_ok": details["google_generate_204"]["ok"],
        "firefox_ok": details["firefox_success"]["ok"],
        "internet_healthy": healthy,
        "delay_ms": min(delays) if delays else -1,
        "details": details,
        "alive": True,
    }


def main() -> None:
    real_delay.probe = probe
    real_delay.main()

    report_path = Path(real_delay.OUT) / "metadata" / "real_delay.json"
    if report_path.is_file():
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        payload["health_gate"] = {
            "url": "tcp://www.google.com:443",
            "type": "real_socks5_tcp_connect_through_xray",
            "required": True,
            "description": "Every node must first establish a real TCP CONNECT through Xray to www.google.com:443; only then are the three HTTP health probes attempted.",
        }
        payload.setdefault("probes", {})["google_tcp"] = {
            "url": "tcp://www.google.com:443",
            "type": "SOCKS5 CONNECT",
            "required": True,
        }
        report_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
