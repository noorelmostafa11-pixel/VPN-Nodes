#!/usr/bin/env python3
"""VPN Gate CSV -> real OpenVPN tunnel -> HTTPS verification.

This path is intentionally independent from the Xray tester. It consumes
output/metadata/openvpn_candidates.json produced by update_catalog.py,
starts one OpenVPN client per candidate, waits for a completed tunnel, then
performs a real HTTPS request through the tunnel.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
CANDIDATES = OUT / "metadata" / "openvpn_candidates.json"
DEFAULT_TIMEOUT = float(os.environ.get("OPENVPN_NODE_TIMEOUT", "25"))
DEFAULT_WORKERS = int(os.environ.get("OPENVPN_WORKERS", "4"))
TEST_HOST = "www.gstatic.com"
TEST_PATH = "/generate_204"


def public_test_ip() -> str:
    infos = socket.getaddrinfo(TEST_HOST, 443, type=socket.SOCK_STREAM)
    for info in infos:
        ip = str(info[4][0])
        if ":" not in ip:
            return ip
    raise RuntimeError(f"no IPv4 address resolved for {TEST_HOST}")


def wait_for_log(log_path: Path, needle: str, timeout: float, proc: subprocess.Popen) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log_path.exists():
            text = log_path.read_text(encoding="utf-8", errors="replace")
            if needle in text:
                return True, text
        if proc.poll() is not None:
            break
        time.sleep(0.25)
    text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    return needle in text, text


def stop_openvpn(proc: subprocess.Popen, pidfile: Path | None) -> None:
    if pidfile and pidfile.exists():
        try:
            pid = int(pidfile.read_text(encoding="utf-8").strip())
            subprocess.run(["sudo", "-n", "kill", str(pid)], capture_output=True, text=True, timeout=5)
        except Exception:
            pass
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def test_candidate(item: dict, index: int, timeout: float, test_ip: str) -> dict:
    started = time.perf_counter()
    result = {
        "index": index,
        "server": item.get("server", ""),
        "port": item.get("port"),
        "country": item.get("country", "UNKNOWN"),
        "country_short": item.get("country_short", "UNKNOWN"),
        "score": item.get("score"),
        "ping": item.get("ping"),
        "speed": item.get("speed"),
        "status": "FAILED",
        "latency_ms": -1.0,
        "detail": "",
    }

    config_b64 = str(item.get("config_b64") or "").strip()
    if not config_b64:
        result["detail"] = "missing OpenVPN config"
        return result

    work = Path(tempfile.mkdtemp(prefix=f"vpngate-{index}-"))
    config_path = work / "client.ovpn"
    cred_path = work / "auth.txt"
    log_path = work / "openvpn.log"
    pid_path = work / "openvpn.pid"
    process = None

    try:
        import base64
        raw = base64.b64decode(config_b64 + "=" * (-len(config_b64) % 4))
        config = raw.decode("utf-8", errors="replace")
        remotes = re.findall(r"^\s*remote\s+(\S+)\s+(\d+)\b", config, flags=re.MULTILINE)
        if not remotes:
            result["detail"] = "no remote directive in config"
            return result
        if not any(int(p) in {80, 443} for _, p in remotes):
            result["detail"] = "OpenVPN remote port is not 80/443"
            return result

        # VPN Gate public profiles normally authenticate with vpn/vpn. Supplying
        # the credential file also overrides a bare auth-user-pass directive.
        cred_path.write_text("vpn\nvpn\n", encoding="utf-8")
        extra = [
            "auth-user-pass", str(cred_path),
            "connect-retry-max", "1",
            "connect-timeout", "10",
            "resolv-retry", "5",
            "auth-nocache",
            "route-nopull",
            "route", test_ip, "255.255.255.255",
            "verb", "3",
            "writepid", str(pid_path),
        ]
        config_path.write_text(config.rstrip() + "\n" + "\n".join(extra) + "\n", encoding="utf-8")

        process = subprocess.Popen(
            ["sudo", "-n", "openvpn", "--config", str(config_path), "--log", str(log_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        ready, log_text = wait_for_log(log_path, "Initialization Sequence Completed", timeout, process)
        if not ready:
            result["detail"] = "tunnel did not initialize"
            tail = log_text[-1000:]
            if tail:
                result["detail"] += f"; {tail.replace(chr(10), ' ')[:700]}"
            return result

        curl = subprocess.run(
            [
                "curl", "--fail", "--silent", "--show-error",
                "--noproxy", "*",
                "--connect-timeout", "8", "--max-time", "12",
                "--resolve", f"{TEST_HOST}:443:{test_ip}",
                "-o", "/dev/null", "-w", "%{http_code}",
                f"https://{TEST_HOST}{TEST_PATH}",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        code = curl.stdout.strip()
        if code == "204":
            result["status"] = "PASS"
            result["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)
            result["detail"] = "OpenVPN tunnel + HTTPS 204"
        else:
            result["detail"] = f"HTTPS status={code or 'none'} stderr={curl.stderr.strip()[:400]}"
        return result
    except Exception as exc:
        result["detail"] = str(exc)[:800]
        return result
    finally:
        if process is not None:
            stop_openvpn(process, pid_path)
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = parser.parse_args()

    if not shutil.which("openvpn"):
        raise SystemExit("openvpn is not installed")
    if not CANDIDATES.is_file():
        print("INFO vpngate_candidates=0 (no candidate file)")
        return 0

    payload = json.loads(CANDIDATES.read_text(encoding="utf-8"))
    candidates = [x for x in payload.get("nodes", []) if int(x.get("port", 0)) in {80, 443}]
    if not candidates:
        print("INFO vpngate_candidates=0")
        return 0

    workers = max(1, min(args.workers, 8))
    test_ip = public_test_ip()
    print(f"INFO openvpn_candidates={len(candidates)} workers={workers} timeout_s={args.timeout} test={TEST_HOST} test_ip={test_ip}")

    results = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(test_candidate, item, index, max(5.0, args.timeout), test_ip): item
            for index, item in enumerate(candidates, start=1)
        }
        for n, future in enumerate(as_completed(futures), start=1):
            result = future.result()
            results.append(result)
            print(f"[{n}/{len(candidates)}] OpenVPN {result['server']}:{result['port']} {result['status']} {result['latency_ms']} ms | {result['detail']}", flush=True)

    passed = [r for r in results if r["status"] == "PASS"]
    results.sort(key=lambda r: (r.get("latency_ms", 10**9) if r.get("latency_ms", -1) >= 0 else 10**9, r.get("index", 10**9)))

    verified_dir = OUT / "openvpn"
    meta_dir = OUT / "metadata"
    verified_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)
    (verified_dir / "verified.json").write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (verified_dir / "verified.txt").write_text(
        "\n".join(f"{r['server']}:{r['port']} # {r['country_short']}" for r in passed) + ("\n" if passed else ""),
        encoding="utf-8",
    )
    summary = {
        "schema": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "protocol": "openvpn",
        "candidates": len(candidates),
        "pass": len(passed),
        "failed": len(results) - len(passed),
        "workers": workers,
        "timeout_s": args.timeout,
        "allowed_ports": [80, 443],
        "health_path": "VPNGate CSV -> OpenVPN client -> tunnel initialization -> routed HTTPS /generate_204 -> HTTP 204",
        "test_host": TEST_HOST,
        "results": results,
    }
    (meta_dir / "openvpn_health.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"INFO OPENVPN FINAL PASS={len(passed)} FAILED={len(results)-len(passed)} TOTAL={len(results)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
