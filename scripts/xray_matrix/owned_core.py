"""Shared contract for the owner-built VPN-Core-Test checker and catalog."""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path

CORE_REPOSITORY = "noorelmostafa11-pixel/VPN-Core-Test"
MATRIX_SHARDS = 8
WORKERS = 64
PROTOCOL_ORDER = ("vless", "vmess", "trojan", "ss")
PUBLIC_PROTOCOL = {"vless": "vless", "vmess": "vmess", "trojan": "trojan", "shadowsocks": "ss"}
TARGET_LABELS = {
    "https://www.gstatic.com/generate_204": "google",
    "https://www.microsoft.com/robots.txt": "microsoft",
    "https://www.cloudflare.com/cdn-cgi/trace": "cloudflare",
    "https://example.com/": "example",
}
SUCCESS_ENDPOINTS = frozenset(TARGET_LABELS.values())


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


def validate_manifest(manifest: dict) -> None:
    if (manifest.get("repository") != CORE_REPOSITORY
            or not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("revision", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("binary_sha256", "")))
            or manifest.get("source_modified") is not False):
        raise ValueError("Expected a clean, pinned build of the owner's core")


def verify_binary(binary: Path, manifest: dict) -> None:
    validate_manifest(manifest)
    if digest(binary) != manifest["binary_sha256"]:
        raise ValueError("Owned core binary SHA256 mismatch")


def verified_attempt(result: dict) -> dict:
    for attempt in result.get("attempts", []):
        status = attempt.get("http_status")
        if (attempt.get("verified_tls") is True and isinstance(status, int)
                and 200 <= status <= 599 and not attempt.get("failure")
                and attempt.get("target") in TARGET_LABELS):
            return attempt
    raise ValueError("PASS lacks authenticated HTTPS evidence from a checker target")
