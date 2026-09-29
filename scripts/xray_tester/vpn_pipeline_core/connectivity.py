from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import struct
import time
import urllib.parse

from . import config
from .config import (
    HTTP_TIMEOUT,
    REAL_PING_TARGETS,
)
from .models import Node, TestResult


def recv_exact(
    sock: socket.socket, amount: int, *, deadline: float | None = None,
) -> bytes:
    data = bytearray()
    while len(data) < amount:
        if deadline is not None:
            sock.settimeout(_remaining_timeout(deadline))
        chunk = sock.recv(amount - len(data))
        if not chunk:
            raise ConnectionError("Unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def socks_connect(
    socks_port: int,
    host: str,
    port: int,
    *,
    timeout: float,
    deadline: float | None = None,
) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        if deadline is not None:
            sock.settimeout(_remaining_timeout(deadline))
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2, deadline=deadline) != b"\x05\x00":
            raise ConnectionError("SOCKS authentication failed")

        try:
            ip = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            ip = None
        if ip is None:
            host_bytes = host.encode("idna")
            if len(host_bytes) > 255:
                raise ValueError("Hostname too long")
            address = b"\x03" + bytes([len(host_bytes)]) + host_bytes
        elif ip.version == 4:
            address = b"\x01" + ip.packed
        else:
            address = b"\x04" + ip.packed

        if deadline is not None:
            sock.settimeout(_remaining_timeout(deadline))
        sock.sendall(b"\x05\x01\x00" + address + struct.pack("!H", port))
        reply = recv_exact(sock, 4, deadline=deadline)
        if reply[0] != 5 or reply[1] != 0:
            raise ConnectionError(f"SOCKS connect failed code={reply[1]}")
        atyp = reply[3]
        if atyp == 1:
            recv_exact(sock, 4, deadline=deadline)
        elif atyp == 3:
            recv_exact(sock, recv_exact(sock, 1, deadline=deadline)[0], deadline=deadline)
        elif atyp == 4:
            recv_exact(sock, 16, deadline=deadline)
        else:
            raise ConnectionError("Invalid SOCKS ATYP")
        recv_exact(sock, 2, deadline=deadline)
        return sock
    except BaseException:
        sock.close()
        raise


def _https_read_limited(
    socks_port: int,
    url: str,
    max_bytes: int,
    *,
    max_redirects: int = 3,
    request_timeout: float = HTTP_TIMEOUT,
) -> tuple[int, bytes]:
    current_url = url
    for redirect_count in range(max_redirects + 1):
        parsed = urllib.parse.urlsplit(current_url)
        if parsed.scheme.lower() != "https":
            raise ValueError("Only HTTPS metadata endpoints are supported")
        host = parsed.hostname
        if not host:
            raise ValueError("Metadata URL missing hostname")
        port = parsed.port or 443
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query

        raw_sock = tls_sock = None
        try:
            raw_sock = socks_connect(socks_port, host, port, timeout=request_timeout)
            context = ssl.create_default_context()
            tls_sock = context.wrap_socket(raw_sock, server_hostname=host)
            raw_sock = None
            tls_sock.settimeout(request_timeout)
            request = (
                f"GET {target} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Accept: */*\r\n"
                "Accept-Encoding: identity\r\n"
                "Connection: close\r\n\r\n"
            )
            tls_sock.sendall(request.encode("ascii"))
            response = http.client.HTTPResponse(tls_sock, method="GET")
            response.begin()
            if response.status in (301, 302, 303, 307, 308) and redirect_count < max_redirects:
                location = response.getheader("Location")
                if location:
                    current_url = urllib.parse.urljoin(current_url, location)
                    continue
            return response.status, response.read(max_bytes)
        finally:
            try:
                if tls_sock is not None:
                    tls_sock.close()
                elif raw_sock is not None:
                    raw_sock.close()
            except Exception:
                pass
    raise RuntimeError("Too many metadata redirects")


def _public_ip(value: object) -> str:
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return ""
    return str(address) if address.is_global else ""


def lookup_country(socks_port: int) -> tuple[str, str, str]:
    if not config.COUNTRY_URL:
        return "XX", "COUNTRY_URL not configured", ""
    try:
        status, body = _https_read_limited(socks_port, config.COUNTRY_URL, 512)
        if status not in (200, 206):
            return "XX", f"country endpoint HTTP {status}", ""
        raw_text = body.decode("utf-8", errors="ignore").strip()
        exit_ip = ""

        if raw_text.startswith("{"):
            try:
                obj = json.loads(raw_text)
                if isinstance(obj, dict):
                    exit_ip = _public_ip(obj.get("ip"))
                    for key in ("country", "country_code", "countryCode", "country_iso", "cc"):
                        value = str(obj.get(key) or "").strip().upper()
                        if re.fullmatch(r"[A-Z]{2}", value):
                            return value, "", exit_ip
            except Exception:
                pass
            return "XX", "invalid country response", exit_ip

        clean_text = raw_text.replace('"', "").replace("'", "").strip().upper()
        if re.fullmatch(r"[A-Z]{2}", clean_text):
            return clean_text, "", exit_ip
        match = re.search(r"\b([A-Z]{2})\b", clean_text)
        if match:
            return match.group(1), "", exit_ip
        return "XX", f"invalid country response: {raw_text[:32]!r}", exit_ip
    except Exception as exc:
        return "XX", f"{type(exc).__name__}: {exc}", ""


def lookup_exit_ip(socks_port: int) -> tuple[str, str]:
    try:
        status, body = _https_read_limited(
            socks_port, config.COUNTRY_EXIT_URL, 128,
            max_redirects=0, request_timeout=config.COUNTRY_EXIT_TIMEOUT,
        )
        if status != 200:
            return "", f"exit endpoint HTTP {status}"
        response = json.loads(body.decode("utf-8"))
        if not isinstance(response, dict):
            return "", "invalid exit endpoint response"
        exit_ip = _public_ip(response.get("ip"))
        if not exit_ip:
            return "", "invalid exit address"
        return exit_ip, ""
    except Exception as exc:
        return "", f"{type(exc).__name__}: {exc}"


def _remaining_timeout(deadline: float, maximum: float | None = None) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Real Delay timeout")
    if maximum is not None:
        remaining = min(remaining, maximum)
    return max(0.001, remaining)


def _read_complete_http_headers(tls_sock: ssl.SSLSocket, deadline: float) -> int:
    """Require a final HTTP response and its complete header terminator.

    A peer can close directly after the headers, including a valid 204 with no
    response body.  EOF before the header terminator is not proof of a reply.
    """
    with tls_sock.makefile("rb") as stream:
        for _ in range(5):  # Ignore informational responses; require a final one.
            tls_sock.settimeout(_remaining_timeout(deadline))
            status_line = stream.readline(65537)
            if not status_line:
                raise ConnectionError("EOF before HTTP response")
            parts = status_line.strip().split(None, 2)
            if (
                len(status_line) > 65536 or len(parts) < 2
                or not parts[0].startswith(b"HTTP/1.")
                or len(parts[1]) != 3 or not parts[1].isdigit()
            ):
                raise ConnectionError("Invalid HTTP response status")
            status = int(parts[1])
            if not 100 <= status <= 599:
                raise ConnectionError("Invalid HTTP response status")

            header_bytes = 0
            for _ in range(1024):
                tls_sock.settimeout(_remaining_timeout(deadline))
                line = stream.readline(65537)
                if not line:
                    raise ConnectionError("EOF before HTTP headers completed")
                header_bytes += len(line)
                if header_bytes > 262144:
                    raise ConnectionError("HTTP headers too large")
                if line in (b"\r\n", b"\n"):
                    break
            else:
                raise ConnectionError("Too many HTTP headers")
            if status >= 200:
                return status
    raise ConnectionError("No final HTTP response")


def _real_ping_target(socks_port: int, url: str, timeout: float) -> int:
    """Make one verified HTTPS request through the node's own Xray SOCKS port."""
    if timeout <= 0:
        raise ValueError("Real Delay timeout must be positive")
    deadline = time.monotonic() + timeout
    started = time.monotonic()
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("Real Delay target must use HTTPS with a hostname")
    host = parsed.hostname
    port = parsed.port or 443
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query

    raw_sock = tls_sock = None
    try:
        raw_sock = socks_connect(
            socks_port, host, port,
            timeout=_remaining_timeout(deadline), deadline=deadline,
        )
        raw_sock.settimeout(_remaining_timeout(deadline))
        tls_sock = ssl.create_default_context().wrap_socket(raw_sock, server_hostname=host)
        raw_sock = None
        tls_sock.settimeout(_remaining_timeout(deadline))
        request = f"GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        tls_sock.sendall(request.encode("ascii"))
        _read_complete_http_headers(tls_sock, deadline)
        return max(1, int((time.monotonic() - started) * 1000))
    finally:
        try:
            if tls_sock is not None:
                tls_sock.close()
            elif raw_sock is not None:
                raw_sock.close()
        except OSError:
            pass


def v2rayn_real_ping(node: Node, socks_port: int) -> TestResult:
    """One real HTTPS response is enough; try Google, then Microsoft on failure."""
    response_time: int | None = None
    success_endpoint = ""
    target_errors: list[str] = []
    for endpoint_name, url, timeout in REAL_PING_TARGETS:
        try:
            response_time = _real_ping_target(socks_port, url, timeout)
            success_endpoint = endpoint_name
            break
        except Exception as exc:
            # Do not leak the secret test endpoint through exception text in
            # public GitHub Actions logs.  Record only the exception class;
            # this is diagnostics-only and does not alter the decision path.
            target_errors.append(f"test_endpoint: {type(exc).__name__}")

    if response_time is None:
        return TestResult(
            node.protocol,
            node.index,
            node.raw,
            node.host,
            node.port,
            False,
            "connectivity",
            " | ".join(target_errors) or "No Real Delay target succeeded",
        )

    country, country_error, exit_ip = lookup_country(socks_port)
    if country == "XX" and not exit_ip:
        exit_ip, exit_error = lookup_exit_ip(socks_port)
        if exit_error:
            country_error = "; ".join(filter(None, (country_error, exit_error)))
    return TestResult(
        protocol=node.protocol,
        index=node.index,
        raw=node.raw,
        host=node.host,
        port=node.port,
        ok=True,
        stage="ok",
        error="",
        http204_ms=float(response_time),
        country=country,
        country_error=country_error,
        success_endpoint=success_endpoint,
        exit_ip=exit_ip if country == "XX" else "",
    )
