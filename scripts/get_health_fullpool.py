#!/usr/bin/env python3
"""Full-pool protocol + HTTP health check.

Pipeline:
  parsed nodes -> TCP reachability in update_catalog.py -> protocol-aware Xray
  batch workers -> lightweight HTTPS GET -> HTTP success + latency -> ASC sort.

Xray is reused for a whole batch (multiple SOCKS inbounds/outbounds) instead of
starting one Xray process per node. Every TCP-reachable node supplied by the
catalog is eligible for the GET check; no sampling/quotas are applied here.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from real_delay_v2 import XRAY, outbound

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"

MAX_PER_COUNTRY = int(os.environ.get("GET_HEALTH_PUBLISH_PER_COUNTRY", "250"))
BATCH_SIZE = int(os.environ.get("GET_HEALTH_BATCH_SIZE", "256"))
WORKERS = int(os.environ.get("GET_HEALTH_WORKERS", "128"))
TIMEOUT = float(os.environ.get("GET_HEALTH_TIMEOUT", "6"))
SOCKS_BASE = int(os.environ.get("GET_HEALTH_SOCKS_BASE", "30000"))
STARTUP_TIMEOUT = float(os.environ.get("GET_HEALTH_STARTUP_TIMEOUT", "4"))
TEST_HOST = os.environ.get("GET_HEALTH_TEST_HOST", "www.gstatic.com")
TEST_PATH = os.environ.get("GET_HEALTH_TEST_PATH", "/generate_204")


def load_full_reachable_pool():
    """Load every node published by the preceding full TCP stage."""
    countries_dir = OUT / "countries"
    if not countries_dir.exists():
        raise SystemExit("Missing catalog output: output/countries")

    nodes = {}
    for path in sorted(countries_dir.glob("*.txt")):
        country = path.stem.upper()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            uri = line.strip()
            if not uri or not uri.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                continue
            nodes.setdefault(uri, {
                "uri": uri,
                "country": country or "UNKNOWN",
                "protocol": uri.split(":", 1)[0].lower(),
            })

    pool = list(nodes.values())
    if not pool:
        raise SystemExit("Full TCP-reachable catalog is empty")
    return pool


def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise RuntimeError("short SOCKS response")
        data.extend(chunk)
    return bytes(data)


def socks_connect(port: int):
    s = socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT)
    s.settimeout(TIMEOUT)
    s.sendall(b"\x05\x01\x00")
    if recv_exact(s, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS auth failed")

    host = TEST_HOST.encode("idna")
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + (443).to_bytes(2, "big"))
    head = recv_exact(s, 4)
    if head[1] != 0:
        raise RuntimeError(f"SOCKS connect failed: {head[1]}")

    atyp = head[3]
    if atyp == 1:
        recv_exact(s, 4)
    elif atyp == 3:
        ln = recv_exact(s, 1)[0]
        recv_exact(s, ln)
    elif atyp == 4:
        recv_exact(s, 16)
    else:
        raise RuntimeError("invalid SOCKS address type")
    recv_exact(s, 2)
    return s


def http_get_via_socks(port: int):
    started = time.perf_counter()
    s = socks_connect(port)
    try:
        tls = ssl.create_default_context().wrap_socket(s, server_hostname=TEST_HOST)
        request = (
            f"GET {TEST_PATH} HTTP/1.1\r\n"
            f"Host: {TEST_HOST}\r\n"
            "Connection: close\r\n"
            "User-Agent: VPN-Nodes-GET-Health/2.0\r\n"
            "Accept: */*\r\n\r\n"
        ).encode()
        tls.sendall(request)

        header = bytearray()
        while b"\r\n" not in header and len(header) < 4096:
            chunk = tls.recv(512)
            if not chunk:
                break
            header.extend(chunk)

        first_line = bytes(header).split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        fields = first_line.split()
        if len(fields) < 2 or not fields[0].startswith("HTTP/"):
            raise RuntimeError("invalid HTTP response")

        status = int(fields[1])
        delay_ms = round((time.perf_counter() - started) * 1000, 1)
        return status, delay_ms
    finally:
        try:
            s.close()
        except Exception:
            pass


def wait_for_port(port: int):
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.2)
            s.close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("xray startup timeout")


def run_batch(batch, batch_number):
    base = SOCKS_BASE + batch_number * BATCH_SIZE
    process = None
    results = []

    with tempfile.TemporaryDirectory(prefix="get-health-batch-", dir=str(OUT)) as td:
        config_path = Path(td) / "config.json"
        inbounds = []
        outbounds = []
        routing_rules = []

        for index, item in enumerate(batch):
            port = base + index
            in_tag = f"in-{index}"
            out_tag = f"out-{index}"
            inbounds.append({
                "tag": in_tag,
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {"udp": False},
            })
            outbounds.append({"tag": out_tag, **outbound(item["uri"])})
            routing_rules.append({
                "type": "field",
                "inboundTag": [in_tag],
                "outboundTag": out_tag,
            })

        config = {
            "log": {"loglevel": "error"},
            "inbounds": inbounds,
            "outbounds": outbounds,
            "routing": {
                "domainStrategy": "AsIs",
                "rules": routing_rules,
            },
        }
        config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")

        try:
            process = subprocess.Popen(
                [str(XRAY), "run", "-c", str(config_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            wait_for_port(base)

            def one(pair):
                idx, item = pair
                port = base + idx
                try:
                    status, delay = http_get_via_socks(port)
                    alive = 200 <= status < 300
                    return {
                        **item,
                        "alive": alive,
                        "http_status": status,
                        "delay_ms": delay if alive else -1,
                    }
                except Exception as exc:
                    return {
                        **item,
                        "alive": False,
                        "http_status": None,
                        "delay_ms": -1,
                        "error": str(exc)[:200],
                    }

            with ThreadPoolExecutor(max_workers=min(WORKERS, len(batch))) as executor:
                futures = [executor.submit(one, pair) for pair in enumerate(batch)]
                for future in as_completed(futures):
                    results.append(future.result())
        finally:
            if process is not None:
                try:
                    process.terminate()
                    process.wait(timeout=1.5)
                except Exception:
                    try:
                        process.kill()
                    except Exception:
                        pass

    return results


def publish(pool, results):
    countries_dir = OUT / "countries"
    protocols_dir = OUT / "protocols"
    metadata_dir = OUT / "metadata"
    countries_dir.mkdir(parents=True, exist_ok=True)
    protocols_dir.mkdir(parents=True, exist_ok=True)
    metadata_dir.mkdir(parents=True, exist_ok=True)

    alive = [r for r in results if r.get("alive") and r.get("delay_ms", -1) >= 0]
    by_country = {}
    for item in alive:
        by_country.setdefault(item.get("country", "UNKNOWN"), []).append(item)

    for items in by_country.values():
        items.sort(key=lambda r: (
            r.get("delay_ms", 10**9),
            r.get("protocol", ""),
            r.get("uri", ""),
        ))

    all_countries = sorted({x.get("country", "UNKNOWN") for x in pool})
    final_by_country = {
        country: by_country.get(country, [])[:MAX_PER_COUNTRY]
        for country in all_countries
    }

    for path in countries_dir.glob("*.txt"):
        path.unlink()
    for path in protocols_dir.glob("*.txt"):
        path.unlink()

    by_protocol = {}
    for country, items in final_by_country.items():
        (countries_dir / f"{country}.txt").write_text(
            "\n".join(x["uri"] for x in items) + ("\n" if items else ""),
            encoding="utf-8",
        )
        for item in items:
            by_protocol.setdefault(item.get("protocol", item["uri"].split(":", 1)[0].lower()), []).append(item)

    for protocol, items in by_protocol.items():
        items.sort(key=lambda r: (r.get("delay_ms", 10**9), r["uri"]))
        (protocols_dir / f"{protocol}.txt").write_text(
            "\n".join(x["uri"] for x in items) + "\n",
            encoding="utf-8",
        )

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload = {
        "schema": 3,
        "generated_at": now,
        "engine": "Xray-batched",
        "test": f"GET https://{TEST_HOST}{TEST_PATH} through Xray protocol-aware SOCKS batches",
        "reachable_pool": len(pool),
        "get_checked": len(results),
        "alive": len(alive),
        "dead": len(results) - len(alive),
        "batch_size": BATCH_SIZE,
        "workers_per_batch": WORKERS,
        "publish_limit_per_country": MAX_PER_COUNTRY,
        "results": sorted(
            results,
            key=lambda r: (
                r.get("country", "UNKNOWN"),
                0 if r.get("alive") else 1,
                r.get("delay_ms") if r.get("delay_ms", -1) >= 0 else 10**9,
                r.get("protocol", ""),
                r["uri"],
            ),
        ),
    }
    (metadata_dir / "get_health.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (metadata_dir / "get_health_summary.json").write_text(
        json.dumps({
            "generated_at": now,
            "reachable_pool": len(pool),
            "get_checked": len(results),
            "alive": len(alive),
            "dead": len(results) - len(alive),
            "untested_reachable": max(0, len(pool) - len(results)),
            "countries_published": len(final_by_country),
            "protocols_published": {p: len(v) for p, v in sorted(by_protocol.items())},
        }, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main():
    if not XRAY.exists():
        raise SystemExit(f"Xray binary not found: {XRAY}")
    pool = load_full_reachable_pool()
    print(
        f"INFO get_health_pool={len(pool)} workers={WORKERS} "
        f"batch_size={BATCH_SIZE} test=https://{TEST_HOST}{TEST_PATH}"
    )

    all_results = []
    total_batches = (len(pool) + BATCH_SIZE - 1) // BATCH_SIZE

    for batch_number in range(total_batches):
        start = batch_number * BATCH_SIZE
        batch = pool[start:start + BATCH_SIZE]
        batch_results = run_batch(batch, batch_number)
        all_results.extend(batch_results)
        alive = sum(1 for r in all_results if r.get("alive"))
        checked = len(all_results)
        print(
            f"INFO get_health_progress={checked}/{len(pool)} "
            f"batches={batch_number + 1}/{total_batches} alive={alive}"
        )

    publish(pool, all_results)
    alive = sum(1 for r in all_results if r.get("alive"))
    print(
        f"OK get_health selected={len(all_results)} alive={alive} "
        f"dead={len(all_results)-alive} "
        f"ranked_by_get_delay=true published_from_full_reachable=true"
    )


if __name__ == "__main__":
    main()
