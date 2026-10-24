"""Authenticated, run-bound transport of private core tools between owned jobs."""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import zipfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from xray_matrix.owned_core import validate_manifest

MAGIC = b"VPNCORE\x01"
NAMES = frozenset(("vpn-core", "node-input", "node-speed", "core-build.json"))
HASH_FIELDS = {"vpn-core": "binary_sha256", "node-input": "input_binary_sha256",
               "node-speed": "speed_binary_sha256"}
MAX_BYTES = 512 * 1024 * 1024
SECRET = "VPN_CORE_ARTIFACT_KEY_B64"


def key_from_environment() -> bytes:
    try:
        key = base64.b64decode(os.environ[SECRET], validate=True)
        if len(key) != 32:
            raise ValueError()
    except (KeyError, ValueError, UnicodeError):
        raise ValueError(SECRET + " must contain a base64-encoded 32-byte key") from None
    return key


def context(repository: str, run_id: str) -> bytes:
    if repository != "noorelmostafa11-pixel/VPN-Nodes" or not re.fullmatch(r"[1-9][0-9]*", run_id):
        raise ValueError("Expected this repository and a valid workflow run ID")
    return MAGIC + json.dumps([repository, run_id], separators=(",", ":")).encode("ascii")


def validate_files(files: dict[str, bytes]) -> None:
    if set(files) != NAMES or sum(map(len, files.values())) > MAX_BYTES:
        raise ValueError("Expected only the three owned tools and their build manifest")
    try:
        manifest = json.loads(files["core-build.json"])
        validate_manifest(manifest)
        for name, field in HASH_FIELDS.items():
            if not files[name] or hashlib.sha256(files[name]).hexdigest() != manifest.get(field):
                raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Private core build identity or tool checksum mismatch") from None


def seal(source: Path, destination: Path, key: bytes, aad: bytes) -> None:
    entries = list(source.iterdir())
    if ({p.name for p in entries} != NAMES
            or any(p.is_symlink() or not p.is_file() for p in entries)
            or sum(p.stat().st_size for p in entries) > MAX_BYTES):
        raise ValueError("Unexpected private build contents")
    files = {p.name: p.read_bytes() for p in entries}
    validate_files(files)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name in sorted(files):
            bundle.writestr(name, files[name])
    nonce = os.urandom(12)
    encrypted = MAGIC + nonce + AESGCM(key).encrypt(nonce, archive.getvalue(), aad)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as output:
        output.write(encrypted)
    destination.chmod(0o600)


def unseal(source: Path, destination: Path, key: bytes, aad: bytes) -> None:
    if source.stat().st_size > MAX_BYTES + 1024 * 1024:
        raise ValueError("Private core envelope exceeds size limit")
    data = source.read_bytes()
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 12 + 16:
        raise ValueError("Expected an encrypted private core envelope")
    offset = len(MAGIC)
    try:
        plain = AESGCM(key).decrypt(data[offset:offset + 12], data[offset + 12:], aad)
    except InvalidTag:
        raise ValueError("Private core authentication failed for this key and run") from None
    try:
        with zipfile.ZipFile(io.BytesIO(plain)) as bundle:
            infos = bundle.infolist()
            if (len(infos) != len(NAMES) or {i.filename for i in infos} != NAMES
                    or sum(i.file_size for i in infos) > MAX_BYTES
                    or any(i.is_dir() or stat.S_ISLNK(i.external_attr >> 16) for i in infos)):
                raise ValueError("Unexpected encrypted archive contents")
            files = {i.filename: bundle.read(i) for i in infos}
    except (zipfile.BadZipFile, RuntimeError):
        raise ValueError("Invalid encrypted archive") from None
    validate_files(files)
    if destination.exists():
        raise ValueError("Private core destination must not already exist")
    destination.parent.mkdir(parents=True, exist_ok=True)
    parent = destination.parent.resolve()
    if destination.resolve().parent != parent:
        raise ValueError("Private core destination must be a direct child of its parent")
    stage = Path(tempfile.mkdtemp(prefix=".core-unseal-", dir=parent)).resolve()
    try:
        stage.chmod(0o700)
        for name, content in files.items():
            path = stage / name
            path.write_bytes(content)
            path.chmod(0o600 if name.endswith(".json") else 0o700)
        stage.rename(destination)
    finally:
        if stage.exists():
            if stage.parent != parent or not stage.name.startswith(".core-unseal-") or stage.is_symlink():
                raise ValueError("Unsafe temporary directory cleanup")
            shutil.rmtree(stage)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("seal", "unseal"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    try:
        key = key_from_environment()
        aad = context(os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("GITHUB_RUN_ID", ""))
        {"seal": seal, "unseal": unseal}[args.operation](args.source, args.destination, key, aad)
    except (OSError, ValueError):
        # Do not echo secrets, private file contents, or decrypted manifests.
        raise SystemExit("Private core transport failed; check secrets, run identity and build integrity") from None
    print("Private core transport complete")


if __name__ == "__main__":
    main()
