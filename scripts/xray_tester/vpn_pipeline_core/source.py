from __future__ import annotations

import hashlib
import json
import re
import socket
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import PROTOCOL_SOURCES, PUBLIC_BRANCH, PUBLIC_REPO, ROLE_SLOTS, SCHEMES, SNAPSHOT_DIR
from .storage import atomic_write_bytes, atomic_write_text, log, redact_error


def raw_url(commit_sha: str, protocol: str) -> str:
    path = PROTOCOL_SOURCES[protocol]
    return f"https://raw.githubusercontent.com/{PUBLIC_REPO}/{commit_sha}/{path}"

def canonicalize_protocol_uri(protocol: str, raw: str) -> str:
    """Normalize only the URI scheme and preserve all node-specific data."""
    if protocol not in SCHEMES:
        raise ValueError(f"Unknown protocol: {protocol}")
    value = raw.strip()
    prefix = SCHEMES[protocol]
    if value[:len(prefix)].lower() != prefix:
        raise ValueError(f"Not {protocol.upper()} URI")
    return prefix + value[len(prefix):]

def protocol_uri_body(protocol: str, raw: str) -> tuple[str, str]:
    canonical = canonicalize_protocol_uri(protocol, raw)
    return canonical, canonical[len(SCHEMES[protocol]):]

def normalize_protocol_text(protocol: str, text: str) -> list[str]:
    prefix = SCHEMES[protocol]
    nodes: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        # The line itself is the node identity. Do not canonicalize the scheme
        # or decode HTML entities here: parser/repair work must never rewrite
        # the source identity that is later published or validated.
        line = line.strip()
        if line[:len(prefix)].lower() != prefix:
            continue
        # Deduplicate only exact raw strings. Same semantic URI with different
        # bytes/casing is still a different source node.
        if line in seen:
            continue
        seen.add(line)
        nodes.append(line)
    return nodes

def resolve_source_sha(explicit_sha: str = "") -> str:
    explicit_sha = explicit_sha.strip()
    if explicit_sha:
        if not re.fullmatch(r"[0-9a-fA-F]{40}", explicit_sha):
            raise ValueError("--source-sha must be a full 40-character Git commit SHA")
        return explicit_sha.lower()

    url = f"https://api.github.com/repos/{PUBLIC_REPO}/commits/{PUBLIC_BRANCH}"
    req = urllib.request.Request(url, headers={"User-Agent": "VPN-Nodes-Tester/2.0"})
    with urllib.request.urlopen(req, timeout=30) as response:
        if getattr(response, "status", 200) != 200:
            raise RuntimeError(f"GitHub commit API HTTP {response.status}")
        obj = json.loads(response.read(2_000_000).decode("utf-8"))
    sha = str(obj.get("sha") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise RuntimeError("Unable to resolve a valid public-repo source SHA")
    return sha

def download_snapshot(commit_sha: str, protocols: list[str]) -> tuple[dict[str, list[str]], dict[str, Any]]:
    snapshot_path = SNAPSHOT_DIR / commit_sha
    snapshot_path.mkdir(parents=True, exist_ok=True)
    all_nodes: dict[str, list[str]] = {}
    manifest: dict[str, Any] = {
        "source_repo": PUBLIC_REPO,
        "source_sha": commit_sha,
        "downloaded_at_utc": datetime.now(timezone.utc).isoformat(),
        "protocols": {},
    }

    for protocol in protocols:
        url = raw_url(commit_sha, protocol)
        local_file = snapshot_path / Path(PROTOCOL_SOURCES[protocol]).name
        log(f"[DOWNLOAD:{protocol}] {url}")
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "VPN-Nodes-Tester/2.0", "Cache-Control": "no-cache"},
            )
            with urllib.request.urlopen(req, timeout=60) as response:
                data = response.read(50_000_000)
                status = getattr(response, "status", 200)
            if status != 200:
                raise RuntimeError(f"HTTP {status}")
            text = data.decode("utf-8-sig", errors="replace")
            nodes = normalize_protocol_text(protocol, text)
            if not nodes:
                raise RuntimeError(f"Source contains zero {protocol} nodes")
            atomic_write_bytes(local_file, data)
        except (urllib.error.URLError, TimeoutError, socket.timeout) as e:
            if not local_file.exists():
                raise
            data = local_file.read_bytes()
            text = data.decode("utf-8-sig", errors="replace")
            nodes = normalize_protocol_text(protocol, text)
            if not nodes:
                raise RuntimeError(f"Cached snapshot contains zero {protocol} nodes")
            log(
                f"[DOWNLOAD:{protocol}] {type(e).__name__}: {redact_error(str(e))}; "
                "using cached bytes for SAME SHA"
            )

        all_nodes[protocol] = nodes
        manifest["protocols"][protocol] = {
            "count": len(nodes),
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "url": url,
        }
        log(f"[DOWNLOAD:{protocol}] OK {len(nodes):,} unique nodes")

    atomic_write_text(snapshot_path / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    return all_nodes, manifest

def split_nodes(nodes: list[str], role: str) -> list[tuple[int, str]]:
    """Return deterministic global source indexes assigned to one worker role."""
    if role == "both":
        return list(enumerate(nodes))
    if role not in ROLE_SLOTS:
        raise ValueError(f"Unknown role: {role}")
    slot = ROLE_SLOTS[role]
    return [(index, raw) for index, raw in enumerate(nodes) if index % 2 == slot]
