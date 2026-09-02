#!/usr/bin/env python3
"""Non-gating Xray pilot using operator-owned HTTP 204 endpoints.

The pilot consumes output/metadata/tcp_reachable.json, samples evenly across the
parseable TCP pool, and runs real traffic through Xray. It never rewrites country
or protocol feeds.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import real_delay as rd

ROOT = Path(__file__).resolve().parents[1]
POOL_FILE = ROOT / "output" / "metadata" / "tcp_reachable.json"
REPORT_FILE = ROOT / "output" / "metadata" / "xray_probe_experiment.json"
XRAY = Path(os.environ.get("XRAY_BIN", "/opt/hostedtoolcache/xray/xray"))

DEFAULT_SAMPLE = 5000
DEFAULT_BATCH_SIZE = 1000
DEFAULT_WORKERS = 256
DEFAULT_TIMEOUT = 3.0
RETRY_ROUNDS = 2
BASE_PORT = int(os.environ.get("OWNED_204_SOCKS_BASE", "31000"))
ALLOWED_PORTS = {80, 443}

ENDPOINT_URLS = (
    ("oracle_1", "http://84.235.244.28/node-health-204"),
    ("oracle_2", "http://145.241.120.1/node-health-204"),
    ("cloudflare_worker", "https://node-health-probe.noorelmostafa11.workers.dev/node-health-204"),
)


def endpoint_from_url(name: str, url: str) -> dict:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"invalid probe URL: {url}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise ValueError(f"probe endpoint must use port 80 or 443: {url}")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return {
        "name": name,
        "url": url,
        "host": parsed.hostname,
        "port": port,
        "path": path,
        "tls": parsed.scheme == "https",
    }


ENDPOINTS = tuple(endpoint_from_url(name, url) for name, url in ENDPOINT_URLS)


def load_parseable_pool() -> tuple[int, list[dict], Counter]:
    if not POOL_FILE.is_file():
        raise SystemExit(f"TCP pool not found: {POOL_FILE}")
    payload = json.loads(POOL_FILE.read_text(encoding="utf-8"))
    raw_rows = list(payload.get("nodes", []))
    parse_failures: Counter = Counter()
    parsed_rows: list[dict] = []

    for pool_index, row in enumerate(raw_rows):
        uri = str(row.get("uri") or "").strip()
        if not uri:
            parse_failures["missing-uri"] += 1
            continue
        try:
            node = rd.parse_uri(uri)
        except Exception as exc:
            parse_failures[f"parse-{type(exc).__name__}"] += 1
            continue
        if int(node.get("port") or 0) not in ALLOWED_PORTS:
            parse_failures["port-not-allowed"] += 1
            continue
        parsed_rows.append({
            **row,
            "uri": uri,
            "node": node,
            "pool_index": pool_index,
        })

    return len(raw_rows), parsed_rows, parse_failures


def evenly_spaced_sample(items: list[dict], limit: int) -> list[dict]:
    if limit <= 0 or not items:
        return []
    if len(items) <= limit:
        return list(items)
    if limit == 1:
        return [items[len(items) // 2]]

    last = len(items) - 1
    indexes = [round(i * last / (limit - 1)) for i in range(limit)]
    return [items[index] for index in indexes]


def write_and_test_config(root: Path, items: list[dict], label: str) -> tuple[bool, str]:
    path = root / f"{label}.json"
    rd.write_cfg(path, items)
    try:
        result = subprocess.run(
            [str(XRAY), "-test", "-config", str(path)],
            text=True,
            capture_output=True,
            timeout=max(30, len(items) // 4 + 30),
        )
    except subprocess.TimeoutExpired:
        return False, "xray-config-timeout"
    if result.returncode == 0:
        return True, ""
    detail = (result.stderr or result.stdout).strip().splitlines()
    suffix = detail[-1][:300] if detail else "unknown"
    return False, f"xray-config-rejected:{suffix}"


def isolate_invalid_configs(root: Path, items: list[dict], batch_no: int) -> tuple[list[dict], list[dict]]:
    if not items:
        return [], []

    ok, detail = write_and_test_config(root, items, f"batch-{batch_no}-full-test")
    if ok:
        return list(items), []

    valid: list[dict] = []
    rejected: list[dict] = []
    stack: list[list[dict]] = [list(items)]
    test_no = 0

    while stack:
        chunk = stack.pop()
        test_no += 1
        ok, chunk_detail = write_and_test_config(
            root, chunk, f"batch-{batch_no}-isolate-{test_no}"
        )
        if ok:
            valid.extend(chunk)
            continue
        if len(chunk) == 1:
            item = chunk[0]
            rejected.append({
                "sample_index": item["sample_index"],
                "pool_index": item["pool_index"],
                "reason": chunk_detail or detail,
            })
            continue
        middle = len(chunk) // 2
        stack.append(chunk[:middle])
        stack.append(chunk[middle:])

    valid.sort(key=lambda item: item["sample_index"])
    rejected.sort(key=lambda item: item["sample_index"])
    return valid, rejected


def wait_batch_ready(items: list[dict], timeout: float = 10.0) -> bool:
    if not items:
        return False
    positions = sorted({0, len(items) // 2, len(items) - 1})
    return all(rd.wait_port(items[pos]["port"], timeout=timeout) for pos in positions)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def recv_socks_reply(sock: socket.socket) -> tuple[bool, str]:
    header = recv_exact(sock, 4)
    if len(header) != 4 or header[0] != 5:
        return False, "socks-invalid-reply"
    if header[1] != 0:
        return False, f"socks-connect-{header[1]}"
    atyp = header[3]
    if atyp == 1:
        if len(recv_exact(sock, 4)) != 4:
            return False, "socks-short-ipv4-reply"
    elif atyp == 3:
        size = recv_exact(sock, 1)
        if not size:
            return False, "socks-invalid-domain-reply"
        if len(recv_exact(sock, size[0])) != size[0]:
            return False, "socks-short-domain-reply"
    elif atyp == 4:
        if len(recv_exact(sock, 16)) != 16:
            return False, "socks-short-ipv6-reply"
    else:
        return False, "socks-invalid-atyp"
    if len(recv_exact(sock, 2)) != 2:
        return False, "socks-short-port-reply"
    return True, ""


def owned_204_probe(socks_port: int, endpoint: dict, timeout: float) -> tuple[bool, float, str]:
    started = time.perf_counter()
    sock: socket.socket | ssl.SSLSocket | None = None
    try:
        raw = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
        raw.settimeout(timeout)
        sock = raw

        raw.sendall(b"\x05\x01\x00")
        if raw.recv(2) != b"\x05\x00":
            return False, -1.0, "socks-auth"

        host_bytes = endpoint["host"].encode("idna")
        if len(host_bytes) > 255:
            return False, -1.0, "endpoint-host-too-long"
        raw.sendall(
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + int(endpoint["port"]).to_bytes(2, "big")
        )
        ok, reason = recv_socks_reply(raw)
        if not ok:
            return False, -1.0, reason

        if endpoint["tls"]:
            context = ssl.create_default_context()
            sock = context.wrap_socket(raw, server_hostname=endpoint["host"])
            sock.settimeout(timeout)

        request = (
            f"GET {endpoint['path']} HTTP/1.1\r\n"
            f"Host: {endpoint['host']}\r\n"
            "Connection: close\r\n"
            "User-Agent: VPN-Nodes-Owned204-Pilot/1.0\r\n"
            "\r\n"
        ).encode("ascii")
        sock.sendall(request)

        data = bytearray()
        while b"\r\n\r\n" not in data and len(data) < 16384:
            chunk = sock.recv(min(4096, 16384 - len(data)))
            if not chunk:
                break
            data.extend(chunk)

        head = bytes(data).split(b"\r\n\r\n", 1)[0]
        lines = head.split(b"\r\n")
        if not lines:
            return False, -1.0, "no-http-response"

        match = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0])
        if not match:
            return False, -1.0, "no-http-status"
        status = int(match.group(1))
        if status != 204:
            return False, -1.0, f"unexpected-status-{status}"

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if b":" not in line:
                continue
            key, value = line.split(b":", 1)
            headers[key.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()

        probe_header = headers.get("x-node-probe")
        if probe_header is None:
            return False, -1.0, "missing-x-node-probe"
        if probe_header.lower() != "ok":
            return False, -1.0, "invalid-x-node-probe"

        return True, round((time.perf_counter() - started) * 1000, 1), "HTTP 204 + X-Node-Probe: ok"
    except socket.timeout:
        return False, -1.0, "timeout"
    except ssl.SSLError:
        return False, -1.0, "tls-error"
    except OSError as exc:
        return False, -1.0, f"socket-error-{exc.errno}" if exc.errno is not None else "socket-error"
    except Exception as exc:
        return False, -1.0, f"probe-{type(exc).__name__}"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def probe_node(item: dict, timeout: float) -> dict:
    attempts: list[dict] = []
    for round_no in range(1, RETRY_ROUNDS + 1):
        for endpoint in ENDPOINTS:
            ok, latency_ms, reason = owned_204_probe(item["port"], endpoint, timeout)
            attempts.append({
                "round": round_no,
                "endpoint": endpoint["name"],
                "ok": ok,
                "latency_ms": latency_ms if ok else -1.0,
                "reason": reason,
            })
            if ok:
                return {
                    "sample_index": item["sample_index"],
                    "pool_index": item["pool_index"],
                    "passed": True,
                    "passed_endpoint": endpoint["name"],
                    "passed_round": round_no,
                    "latency_ms": latency_ms,
                    "attempts": attempts,
                }

    return {
        "sample_index": item["sample_index"],
        "pool_index": item["pool_index"],
        "passed": False,
        "passed_endpoint": None,
        "passed_round": None,
        "latency_ms": -1.0,
        "attempts": attempts,
    }


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 1)
    position = (len(ordered) - 1) * pct
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    value = ordered[lower] * (1.0 - weight) + ordered[upper] * weight
    return round(value, 1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", type=int, default=DEFAULT_SAMPLE)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = parser.parse_args()

    if not XRAY.is_file():
        raise SystemExit(f"Xray binary not found: {XRAY}")

    sample_limit = max(1, args.sample)
    batch_size = max(1, min(args.batch_size, 1000))
    workers = max(1, args.workers)
    timeout = max(0.5, args.timeout)

    pool_total, parseable, parse_failures = load_parseable_pool()
    sampled = evenly_spaced_sample(parseable, min(sample_limit, len(parseable)))
    for sample_index, item in enumerate(sampled):
        item["sample_index"] = sample_index

    print(
        f"INFO owned_204_pool={pool_total} parseable={len(parseable)} "
        f"sampled={len(sampled)} strategy=evenly_spaced workers={workers} "
        f"batch_size={batch_size} timeout={timeout}s rounds={RETRY_ROUNDS}"
    )

    started = time.perf_counter()
    all_results: list[dict] = []
    config_failures: list[dict] = []
    failure_reasons: Counter = Counter()
    endpoint_attempts: Counter = Counter()
    endpoint_successes: Counter = Counter()
    passed_by_endpoint: Counter = Counter()
    batch_results: list[dict] = []
    endpoint_names = {endpoint["name"] for endpoint in ENDPOINTS}

    for batch_no, offset in enumerate(range(0, len(sampled), batch_size), 1):
        batch_started = time.perf_counter()
        source_batch = sampled[offset:offset + batch_size]
        prepared: list[dict] = []

        for local_index, item in enumerate(source_batch):
            candidate = {
                **item,
                "index": local_index,
                "port": BASE_PORT + local_index,
            }
            try:
                rd.xray_outbound(candidate["node"], f"node-{candidate['sample_index'] + 1}")
            except Exception as exc:
                config_failures.append({
                    "sample_index": candidate["sample_index"],
                    "pool_index": candidate["pool_index"],
                    "reason": f"outbound-conversion-{type(exc).__name__}",
                })
                continue
            prepared.append(candidate)

        batch_checked_before = len(all_results)
        batch_config_before = len(config_failures)

        with tempfile.TemporaryDirectory(prefix=f"owned-204-batch-{batch_no}-") as td:
            root = Path(td)
            valid, rejected = isolate_invalid_configs(root, prepared, batch_no)
            config_failures.extend(rejected)

            if valid:
                cfg = root / f"batch-{batch_no}.json"
                rd.write_cfg(cfg, valid)
                ok, detail = write_and_test_config(root, valid, f"batch-{batch_no}-final-test")
                if not ok:
                    for item in valid:
                        config_failures.append({
                            "sample_index": item["sample_index"],
                            "pool_index": item["pool_index"],
                            "reason": detail,
                        })
                    valid = []

            if valid:
                log_path = root / "xray.log"
                with log_path.open("w+", encoding="utf-8") as log_file:
                    proc = subprocess.Popen(
                        [str(XRAY), "run", "-c", str(cfg)],
                        stdout=log_file,
                        stderr=log_file,
                    )
                    try:
                        if not wait_batch_ready(valid):
                            log_file.flush()
                            proc.poll()
                            reason = "xray-batch-start-failed"
                            for item in valid:
                                result = {
                                    "sample_index": item["sample_index"],
                                    "pool_index": item["pool_index"],
                                    "passed": False,
                                    "passed_endpoint": None,
                                    "passed_round": None,
                                    "latency_ms": -1.0,
                                    "attempts": [{
                                        "round": 0,
                                        "endpoint": "xray",
                                        "ok": False,
                                        "latency_ms": -1.0,
                                        "reason": reason,
                                    }],
                                }
                                all_results.append(result)
                        else:
                            with ThreadPoolExecutor(max_workers=workers) as executor:
                                futures = {
                                    executor.submit(probe_node, item, timeout): item
                                    for item in valid
                                }
                                for number, future in enumerate(as_completed(futures), 1):
                                    item = futures[future]
                                    try:
                                        result = future.result()
                                    except Exception as exc:
                                        reason = f"worker-{type(exc).__name__}"
                                        result = {
                                            "sample_index": item["sample_index"],
                                            "pool_index": item["pool_index"],
                                            "passed": False,
                                            "passed_endpoint": None,
                                            "passed_round": None,
                                            "latency_ms": -1.0,
                                            "attempts": [{
                                                "round": 0,
                                                "endpoint": "worker",
                                                "ok": False,
                                                "latency_ms": -1.0,
                                                "reason": reason,
                                            }],
                                        }
                                    all_results.append(result)
                                    if number % 250 == 0 or number == len(valid):
                                        passed_now = sum(
                                            1 for row in all_results[batch_checked_before:]
                                            if row["passed"]
                                        )
                                        print(
                                            f"INFO owned_204_batch={batch_no} "
                                            f"progress={number}/{len(valid)} pass={passed_now}"
                                        )
                    finally:
                        proc.terminate()
                        try:
                            proc.wait(5)
                        except subprocess.TimeoutExpired:
                            proc.kill()

        batch_slice = all_results[batch_checked_before:]
        for result in batch_slice:
            for attempt in result["attempts"]:
                endpoint = attempt["endpoint"]
                if endpoint in endpoint_names:
                    endpoint_attempts[endpoint] += 1
                    if attempt["ok"]:
                        endpoint_successes[endpoint] += 1
                if not attempt["ok"]:
                    failure_reasons[attempt["reason"]] += 1
            if result["passed"]:
                passed_by_endpoint[result["passed_endpoint"]] += 1

        batch_passed = sum(1 for result in batch_slice if result["passed"])
        batch_retry_passed = sum(
            1 for result in batch_slice
            if result["passed"] and result["passed_round"] == 2
        )
        batch_results.append({
            "batch": batch_no,
            "sampled": len(source_batch),
            "xray_config_failed": len(config_failures) - batch_config_before,
            "checked": len(batch_slice),
            "passed": batch_passed,
            "failed": len(batch_slice) - batch_passed,
            "retry_passed": batch_retry_passed,
            "elapsed_seconds": round(time.perf_counter() - batch_started, 2),
        })

    all_results.sort(key=lambda row: row["sample_index"])
    checked = len(all_results)
    passed = sum(1 for result in all_results if result["passed"])
    failed = checked - passed
    retry_passed = sum(
        1 for result in all_results
        if result["passed"] and result["passed_round"] == 2
    )
    successful_latencies = [
        float(result["latency_ms"])
        for result in all_results
        if result["passed"] and result["latency_ms"] >= 0
    ]

    top_failure_reasons = [
        {"reason": reason, "count": count}
        for reason, count in failure_reasons.most_common(20)
    ]
    endpoint_names_ordered = [endpoint["name"] for endpoint in ENDPOINTS]
    report = {
        "schema": 2,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": "non_gating_xray_owned_204_pilot",
        "publishes_catalog": False,
        "sample_strategy": "evenly_spaced_across_parseable_tcp_reachable_pool",
        "pool_total": pool_total,
        "parseable_total": len(parseable),
        "sampled": len(sampled),
        "checked": checked,
        "passed": passed,
        "failed": failed,
        "pass_rate_pct": round((passed / checked) * 100, 2) if checked else 0.0,
        "xray_config_failed": len(config_failures),
        "retry_passed": retry_passed,
        "elapsed_seconds": round(time.perf_counter() - started, 2),
        "workers": workers,
        "batch_size": batch_size,
        "timeout_seconds": timeout,
        "retry_rounds_total": RETRY_ROUNDS,
        "allowed_ports": sorted(ALLOWED_PORTS),
        "success_policy": "first endpoint with HTTP 204 and X-Node-Probe: ok; retry full endpoint chain once only",
        "endpoints": [
            {"name": endpoint["name"], "url": endpoint["url"]}
            for endpoint in ENDPOINTS
        ],
        "passed_by_endpoint": {
            name: passed_by_endpoint.get(name, 0) for name in endpoint_names_ordered
        },
        "endpoint_attempts": {
            name: endpoint_attempts.get(name, 0) for name in endpoint_names_ordered
        },
        "endpoint_successes": {
            name: endpoint_successes.get(name, 0) for name in endpoint_names_ordered
        },
        "latency_ms": {
            "min": round(min(successful_latencies), 1) if successful_latencies else None,
            "p50": percentile(successful_latencies, 0.50),
            "p95": percentile(successful_latencies, 0.95),
            "p99": percentile(successful_latencies, 0.99),
            "max": round(max(successful_latencies), 1) if successful_latencies else None,
        },
        "top_failure_reasons": top_failure_reasons,
        "parse_failure_reasons": [
            {"reason": reason, "count": count}
            for reason, count in parse_failures.most_common(20)
        ],
        "batch_results": batch_results,
    }

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        f"INFO OWNED_204_PILOT checked={checked} passed={passed} failed={failed} "
        f"pass_rate_pct={report['pass_rate_pct']} retry_passed={retry_passed} "
        f"xray_config_failed={len(config_failures)} report={REPORT_FILE}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())