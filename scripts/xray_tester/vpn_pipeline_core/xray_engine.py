from __future__ import annotations

import binascii
import concurrent.futures
import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .config import (
    REAL_PING_BATCH_DELAY,
    REAL_PING_CORE_START_DELAY,
    REAL_PING_ISOLATION_CONCURRENCY,
    REAL_PING_PAGE_SIZE,
    REAL_PING_PROCESS_CHECK_DELAY,
    TMP_DIR,
    WORKERS,
)
from .connectivity import v2rayn_real_ping
from .models import Node, TestResult, UnsupportedNode
from .storage import atomic_write_text, log, redact_error, temporary_work_dir
from .xray_binary import subprocess_flags


XRAY_PROTOCOL_NAMES = {
    "vless": "vless",
    "vmess": "vmess",
    "trojan": "trojan",
    "ss": "shadowsocks",
}

_XRAY_SOURCE_INVALID_MARKERS = (
    "vless without tls or other encryption is prohibited",
    "trojan without tls",
    'unknown "fingerprint"',
    'invalid "fingerprint"',
    'invalid "shortid"',
    'too long "shortid"',
    'invalid "spiderx"',
    'unsupported "encryption"',
    "invalid xhttp mode",
    "unsupported mode:",
    "invalid uuid",
    "unknown cipher method",
    "flow doesn't support",
    '"flow" doesn\'t support',
    "failed to build tls config",
    "failed to build reality config",
    "failed to build xhttp config",
)


def select_free_ports(count: int) -> list[int]:
    """Choose distinct loopback ports without holding hundreds of descriptors.

    v2rayN selects unused ports from the current network table rather than
    reserving every port with an open socket.  Binding one port at a time and
    immediately releasing it keeps the same low-descriptor property, which is
    important on the small Linux workers.
    """
    if count < 0:
        raise ValueError("Port count must be non-negative")
    ports: list[int] = []
    seen: set[int] = set()
    attempts = 0
    limit = max(100, count * 30)
    while len(ports) < count:
        attempts += 1
        if attempts > limit:
            raise RuntimeError(f"Could not find {count} distinct local ports")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        if port in seen:
            continue
        seen.add(port)
        ports.append(port)
    return ports


def make_xray_config(items: list[tuple[Node, int]]) -> dict[str, Any]:
    """Build a shared Xray batch with one local inbound per node."""
    inbounds: list[dict[str, Any]] = []
    outbounds: list[dict[str, Any]] = []
    routing_rules: list[dict[str, Any]] = []

    for node, local_port in items:
        inbound_tag = f"mixed{local_port}"
        outbound_tag = f"proxy{local_port}"
        inbounds.append({
            "tag": inbound_tag,
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "mixed",
            "settings": {"auth": "noauth", "udp": True},
        })

        if node.protocol == "vless":
            user: dict[str, Any] = {
                "id": node.outbound_settings.get("id", ""),
                "email": "t@t.tt",
                "encryption": (
                    node.outbound_settings["encryption"]
                    if "encryption" in node.outbound_settings
                    else "none"
                ),
            }
            if "flow" in node.outbound_settings:
                user["flow"] = node.outbound_settings.get("flow", "")
            settings: dict[str, Any] = {
                "vnext": [{"address": node.host, "port": node.port, "users": [user]}]
            }
        elif node.protocol == "vmess":
            settings = {
                "vnext": [{
                    "address": node.host,
                    "port": node.port,
                    "users": [{
                        "id": node.outbound_settings.get("id", ""),
                        "alterId": node.outbound_settings.get("alterId", 0),
                        "email": "t@t.tt",
                        "security": (
                            node.outbound_settings["security"]
                            if "security" in node.outbound_settings
                            else "auto"
                        ),
                    }],
                }]
            }
        elif node.protocol == "trojan":
            server: dict[str, Any] = {
                "address": node.host,
                "port": node.port,
                "password": node.outbound_settings.get("password", ""),
                "email": "t@t.tt",
            }
            if "flow" in node.outbound_settings:
                server["flow"] = node.outbound_settings.get("flow", "")
            settings = {
                "servers": [server]
            }
        elif node.protocol == "ss":
            settings = {
                "servers": [{
                    "address": node.host,
                    "port": node.port,
                    "method": node.outbound_settings.get("method", ""),
                    "password": node.outbound_settings.get("password", ""),
                }]
            }
        else:
            raise ValueError(f"Unsupported Xray protocol: {node.protocol}")

        outbound: dict[str, Any] = {
            "tag": outbound_tag,
            "protocol": XRAY_PROTOCOL_NAMES[node.protocol],
            "settings": settings,
            "mux": {"enabled": False, "concurrency": -1},
        }
        if node.stream_settings:
            outbound["streamSettings"] = node.stream_settings
        outbounds.append(outbound)
        routing_rules.append({
            "type": "field",
            "inboundTag": [inbound_tag],
            "outboundTag": outbound_tag,
        })

    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": routing_rules},
    }


def stop_xray(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=2)
    except Exception:
        try:
            process.kill()
            process.wait(timeout=2)
        except Exception:
            pass


def classify_xray_config_failure(error: str) -> str:
    """Classify one isolated Xray rejection without hiding unknown program bugs."""
    reason = (error or "").lower()
    # A share link can carry a malformed finalmask value.  Its JSON string
    # reaches Xray unchanged, which then reports the exact source field that
    # cannot be decoded.  This is a source/config failure, not a worker bug.
    if "streamsettings.finalmask" in reason and "cannot unmarshal" in reason:
        return "source_invalid"
    if "streamsettings.tlssettings.allowinsecure" in reason and "cannot unmarshal" in reason:
        return "source_invalid"
    if any(marker in reason for marker in _XRAY_SOURCE_INVALID_MARKERS):
        return "source_invalid"
    if "mkcp-aes128gcm" in reason and "unknown config id" in reason:
        return "source_invalid"
    if any(marker in reason for marker in (
        "unsupported transport",
        "unsupported security",
        "not supported",
        "unknown transport",
        "unknown security",
        "unknown config id",
        "has been removed",
        "removed feature",
        "allowinsecure",
    )):
        return "unsupported"
    return "internal_error"


def classify_parser_failure(error: Exception) -> str:
    """Separate malformed source data from unexpected parser/programming errors."""
    if isinstance(error, UnsupportedNode):
        return "unsupported"
    if isinstance(error, (UnicodeError, binascii.Error, json.JSONDecodeError)):
        return "source_invalid"
    if not isinstance(error, ValueError):
        return "internal_error"
    reason = str(error).strip().lower()
    if (
        reason.startswith(("not ", "invalid ", "malformed ", "duplicate "))
        or " missing " in f" {reason} "
        or " must decode to an object" in reason
        or " must be an object" in reason
        or "would crash xray config parser" in reason
    ):
        return "source_invalid"
    return "internal_error"


def _append_group_log(group_log: Path, xray_log: Path) -> str:
    try:
        text = group_log.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    if text:
        xray_log.parent.mkdir(parents=True, exist_ok=True)
        with xray_log.open("a", encoding="utf-8", errors="replace") as output:
            output.write(text)
            if not text.endswith("\n"):
                output.write("\n")
    return redact_error(text.strip()[-3000:])


def _xray_exit_reason(
    process: subprocess.Popen,
    group_log: Path,
    log_file: Any,
    phase: str,
) -> str:
    """Return the Xray error text for a core that exited unexpectedly."""
    try:
        log_file.flush()
    except Exception:
        pass
    try:
        core_error = group_log.read_text(
            encoding="utf-8", errors="replace"
        ).strip()[-3000:]
    except OSError:
        core_error = ""
    code = process.poll()
    return redact_error(core_error) or f"Xray exited {phase} with code {code}"


def _wait_for_xray_startup(process: subprocess.Popen) -> bool:
    """Monitor Xray for the complete v2rayN-style startup delay.

    The old implementation checked the process only once after 100 ms and then
    slept for another second.  A bad large config can survive that first check
    and exit a few milliseconds later.  Poll through the full delay so that a
    dead core is treated as a failed batch and goes through reduction/isolation.
    """
    first_delay = max(0.0, REAL_PING_PROCESS_CHECK_DELAY)
    if first_delay:
        time.sleep(first_delay)
    if process.poll() is not None:
        return False

    remaining = max(0.0, REAL_PING_CORE_START_DELAY)
    interval = max(0.01, min(REAL_PING_PROCESS_CHECK_DELAY or 0.1, 0.1))
    while remaining > 0:
        step = min(interval, remaining)
        time.sleep(step)
        remaining -= step
        if process.poll() is not None:
            return False
    return process.poll() is None


def _run_real_ping_group(
    batch_items: list[Node],
    xray: Path,
    xray_log: Path,
) -> tuple[bool, list[TestResult], str]:
    """Start one shared Xray core and test the batch through mixed inbounds."""
    if not batch_items:
        return True, [], ""

    ports = select_free_ports(len(batch_items))
    config = make_xray_config(list(zip(batch_items, ports)))
    work_dir = temporary_work_dir() if os.environ.get("VPN_ROUND_TMP_DIR") else TMP_DIR
    config_fd, config_name = tempfile.mkstemp(
        prefix="xray_real_delay_", suffix=".json", dir=work_dir
    )
    os.close(config_fd)
    config_file = Path(config_name)
    log_fd, log_name = tempfile.mkstemp(
        prefix="xray_real_delay_", suffix=".log", dir=work_dir
    )
    os.close(log_fd)
    group_log = Path(log_name)
    atomic_write_text(
        config_file,
        json.dumps(config, indent=2, ensure_ascii=False),
        mode=0o600,
    )

    process = None
    started = False
    reason = ""
    results: list[TestResult] = []
    try:
        with group_log.open("a", encoding="utf-8", errors="replace") as log_file:
            try:
                process = subprocess.Popen(
                    [str(xray), "run", "-c", str(config_file)],
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    creationflags=subprocess_flags(),
                )
            except Exception as exc:
                reason = redact_error(f"{type(exc).__name__}: {exc}")
                return False, [], reason

            # Keep the same v2rayN-style startup budget (100 ms process check
            # plus the core-start delay), but monitor the process throughout it.
            # A malformed node in a large config can make Xray exit after the
            # first 100 ms check but before requests begin.
            if not _wait_for_xray_startup(process):
                reason = _xray_exit_reason(
                    process, group_log, log_file, "during startup"
                )
                return False, [], reason
            started = True

            # v2rayN uses asynchronous tasks for all nodes.  Python's network
            # implementation is blocking, so retain the already-proven server
            # concurrency ceiling instead of creating up to 1000 OS threads.
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(WORKERS, len(batch_items))
            ) as pool:
                futures = {
                    pool.submit(v2rayn_real_ping, node, port): node
                    for node, port in zip(batch_items, ports)
                }
                for future in concurrent.futures.as_completed(futures):
                    node = futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = TestResult(
                            node.protocol,
                            node.index,
                            node.raw,
                            node.host,
                            node.port,
                            False,
                            "internal_error",
                            redact_error(f"{type(exc).__name__}: {exc}"),
                        )
                    results.append(result)

            # Never accept per-node connectivity results from a core that died
            # while the group was being tested.  Discard the entire group so the
            # caller reduces the batch and eventually isolates the bad node.
            if process.poll() is not None:
                reason = _xray_exit_reason(
                    process, group_log, log_file, "during Real Delay testing"
                )
                return False, [], reason

            for result in results:
                if result.ok:
                    delay = (
                        f"{result.http204_ms}ms"
                        if result.http204_ms is not None
                        else "unavailable"
                    )
                    log(
                        f"[OK:{result.protocol}] {result.host}:{result.port} | "
                        f"REAL {delay} | {result.country}"
                    )
                else:
                    log(
                        f"[FAIL:{result.protocol}:{result.stage}] "
                        f"{result.host}:{result.port} | {redact_error(result.error)}"
                    )
            return True, results, ""
    finally:
        stop_xray(process)
        logged = _append_group_log(group_log, xray_log)
        if not started and not reason and logged:
            reason = logged
        config_file.unlink(missing_ok=True)
        group_log.unlink(missing_ok=True)


def _isolated_real_ping(
    items: list[Node],
    xray: Path,
    xray_log: Path,
) -> list[TestResult]:
    """Use one core per node, up to five at a time, for failed-core isolation."""
    results: list[TestResult] = []

    def run_one(node: Node) -> TestResult:
        started, rows, reason = _run_real_ping_group([node], xray, xray_log)
        if started and rows:
            return rows[0]
        return TestResult(
            node.protocol,
            node.index,
            node.raw,
            node.host,
            node.port,
            False,
            classify_xray_config_failure(reason),
            reason or "Xray could not create or start the isolated node config",
        )

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(REAL_PING_ISOLATION_CONCURRENCY, len(items))
    ) as pool:
        futures = {pool.submit(run_one, node): node for node in items}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    return results


def run_v2rayn_real_ping_batch(
    items: list[Node],
    xray: Path,
    xray_log: Path,
    *,
    page_size: int = 0,
) -> list[TestResult]:
    """Use v2rayN-style page sizing and failed-core isolation semantics."""
    if not items:
        return []
    if page_size <= 0:
        page_size = min(len(items), REAL_PING_PAGE_SIZE)
    if page_size <= 0:
        raise ValueError("Real Delay page size must be positive")

    current: dict[int, TestResult] = {}
    failed_to_start: list[Node] = []
    for start in range(0, len(items), page_size):
        group = items[start:start + page_size]
        started, rows, _reason = _run_real_ping_group(group, xray, xray_log)
        if started:
            current.update({row.index: row for row in rows})
        else:
            failed_to_start.extend(group)
        # A rejected configuration generated no node traffic, so delaying it
        # only makes engine-led isolation slower. Keep the established pause
        # strictly between successful pages, never after the final page.
        if started and start + page_size < len(items):
            time.sleep(REAL_PING_BATCH_DELAY)

    next_page_size = page_size // 2
    if failed_to_start and next_page_size > 0:
        if next_page_size > REAL_PING_ISOLATION_CONCURRENCY:
            retries = run_v2rayn_real_ping_batch(
                failed_to_start,
                xray,
                xray_log,
                page_size=next_page_size,
            )
        else:
            # Only unresolved nodes enter single-node isolation. Successful
            # groups already have authoritative results and must never be
            # tested again merely because a different group failed to start.
            retries = _isolated_real_ping(failed_to_start, xray, xray_log)
        current.update({row.index: row for row in retries})

    for node in items:
        if node.index not in current:
            current[node.index] = TestResult(
                node.protocol,
                node.index,
                node.raw,
                node.host,
                node.port,
                False,
                "internal_error",
                "Xray batch did not produce a result for this node",
            )
    return [current[node.index] for node in items]
