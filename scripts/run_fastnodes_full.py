#!/usr/bin/env python3
"""Run the upstream FastNodes pipeline unchanged except for project gates.

Project gates are applied after FastNodes parsing and before its normal pipeline:
- protocols: VLESS, VMess, Trojan, Shadowsocks only
- endpoint ports: 80 and 443 only
Reality remains supported through VLESS security=reality/pbk.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FASTNODES_DIR = Path("/tmp/FastNodes")
FASTNODES_REF = "9edbcb06e506e9e0b56f8e2e9cfb79f2685a88a9"
ALLOWED_PROTOCOLS = {"vless", "vmess", "trojan", "ss", "shadowsocks"}
ALLOWED_PORTS = {80, 443}


def run(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    print("INFO exec:", " ".join(args))
    subprocess.run(args, cwd=cwd, env=env, check=True)


def patch_fastnodes_source() -> None:
    path = FASTNODES_DIR / "ProxyCollector" / "Collector" / "ProxyCollector.cs"
    text = path.read_text(encoding="utf-8")

    # Keep the complete FastNodes parser/collector, but narrow accepted URI schemes.
    pattern = re.compile(
        r'private static readonly HashSet<string> ValidProtocols = new\(StringComparer\.OrdinalIgnoreCase\)\s*\{.*?\n\s*\};',
        re.S,
    )
    replacement = '''private static readonly HashSet<string> ValidProtocols = new(StringComparer.OrdinalIgnoreCase)\n        {\n            "vmess", "vless", "trojan", "ss", "shadowsocks"\n        };'''
    text, count = pattern.subn(replacement, text, count=1)
    if count != 1:
        raise RuntimeError("FastNodes protocol whitelist patch target not found")

    # Apply the project's port/protocol gate once, immediately after FastNodes parsing.
    anchor = '                var p = ParseProxyLine(t);\n                if (p == null) continue;\n'
    gate = '''                var p = ParseProxyLine(t);\n                if (p == null) continue;\n                if (!ProjectAccepts(p)) continue;\n'''
    if anchor not in text:
        raise RuntimeError("FastNodes parser insertion point not found")
    text = text.replace(anchor, gate, 1)

    helper_anchor = '        // ====================== DEAD-NODE FILTERS ======================\n'
    helper = '''        // ====================== PROJECT SAFETY GATE ======================\n        // Keep the complete FastNodes pipeline, but enforce Ahmed VPN's exact scope.\n        // Reality is represented as VLESS security=reality and therefore remains valid.\n        private static bool ProjectAccepts(ParsedProxy p)\n        {\n            string proto = NormalizeProto(p.Protocol);\n            return ALLOWED_PROJECT_PROTOCOLS.Contains(proto)\n                && int.TryParse(p.Port, out var port)\n                && ALLOWED_PROJECT_PORTS.Contains(port);\n        }\n\n        private static readonly HashSet<string> ALLOWED_PROJECT_PROTOCOLS = new(StringComparer.OrdinalIgnoreCase)\n        { "vless", "vmess", "trojan", "ss" };\n\n        private static readonly HashSet<int> ALLOWED_PROJECT_PORTS = new() { 80, 443 };\n\n'''
    if helper_anchor not in text:
        raise RuntimeError("FastNodes helper insertion point not found")
    text = text.replace(helper_anchor, helper + helper_anchor, 1)
    path.write_text(text, encoding="utf-8")


def build_sources() -> str:
    source_path = ROOT / "sources" / "sources.json"
    telegram_path = ROOT / "sources" / "telegram_channels.json"
    source_doc = json.loads(source_path.read_text(encoding="utf-8"))
    telegram_doc = json.loads(telegram_path.read_text(encoding="utf-8"))

    urls: list[str] = []
    seen: set[str] = set()
    for item in source_doc.get("sources", []):
        url = str(item.get("url") or "").strip()
        if url and url.lower() not in seen:
            seen.add(url.lower())
            urls.append(url)

    for channel in telegram_doc.get("channels", []):
        name = str(channel).strip().lstrip("@")
        if not name:
            continue
        url = f"https://t.me/s/{name}"
        if url.lower() not in seen:
            seen.add(url.lower())
            urls.append(url)
    print(f"INFO fastnodes_sources={len(urls)}")
    return "\n".join(urls)


def main() -> None:
    if not shutil.which("git"):
        raise SystemExit("git executable not found")

    shutil.rmtree(FASTNODES_DIR, ignore_errors=True)
    run("git", "clone", "--depth", "1", "https://github.com/rtwo2/FastNodes.git", str(FASTNODES_DIR))
    run("git", "fetch", "--depth", "1", "origin", FASTNODES_REF, cwd=FASTNODES_DIR)
    run("git", "checkout", FASTNODES_REF, cwd=FASTNODES_DIR)
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=FASTNODES_DIR, text=True).strip()
    if actual != FASTNODES_REF:
        raise RuntimeError(f"FastNodes ref mismatch: expected {FASTNODES_REF}, got {actual}")

    patch_fastnodes_source()

    # Feed the complete current source set from this repository into FastNodes.
    env = os.environ.copy()
    env["Sources"] = build_sources()
    env["XRAY_BIN"] = os.environ.get("XRAY_BIN", "/opt/hostedtoolcache/xray/xray")
    if "WORKER_URL" in os.environ:
        env["WORKER_URL"] = os.environ["WORKER_URL"]
    if "WORKER_AUTH" in os.environ:
        env["WORKER_AUTH"] = os.environ["WORKER_AUTH"]

    # Carry stability history across runs; FastNodes itself owns/updates the file.
    repo_history = ROOT / "state" / "history.json"
    fast_history = FASTNODES_DIR / "state" / "history.json"
    fast_history.parent.mkdir(parents=True, exist_ok=True)
    if repo_history.is_file():
        shutil.copy2(repo_history, fast_history)

    run("dotnet", "run", "--configuration", "Release", "--project", "ProxyCollector", cwd=FASTNODES_DIR, env=env)

    generated = FASTNODES_DIR / "sub"
    if not generated.is_dir():
        raise RuntimeError("FastNodes completed without generating sub/")

    output = ROOT / "output"
    if output.exists():
        shutil.rmtree(output)
    shutil.copytree(generated, output)

    # Persist FastNodes' stability state in this repository.
    if fast_history.is_file():
        repo_history.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(fast_history, repo_history)

    # Add explicit machine-readable project policy metadata without changing FastNodes feeds.
    meta = output / "metadata"
    meta.mkdir(parents=True, exist_ok=True)
    (meta / "project_policy.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "engine": "FastNodes",
                "engine_commit": FASTNODES_REF,
                "allowed_ports": sorted(ALLOWED_PORTS),
                "allowed_protocols": ["vless", "vmess", "trojan", "ss"],
                "reality": "supported through VLESS security=reality/publicKey",
                "country_policy": "automatic FastNodes country resolution; no fixed 23-country allowlist",
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print("INFO fastnodes_full_complete=true")
    print(f"INFO output={output}")


if __name__ == "__main__":
    main()
