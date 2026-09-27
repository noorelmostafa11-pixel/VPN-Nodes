from __future__ import annotations

import os
import platform
import re
import subprocess
import urllib.request
import zipfile
from pathlib import Path

from .config import (
    AUTO_DOWNLOAD_XRAY,
    BASE_DIR,
    BIN_DIR,
    XRAY_ASSETS,
    XRAY_BINARY_SHA256,
    XRAY_SOURCE_COMMIT,
    XRAY_VERSION,
    XRAY_WINDOWS,
)
from .models import XrayProbeError
from .storage import atomic_write_bytes, file_sha256, log, redact_error, temporary_work_dir


def normalize_arch(machine: str) -> str:
    value = machine.lower()
    if value in ("amd64", "x86_64", "x64"):
        return "x86_64"
    if value in ("arm64", "aarch64"):
        return "arm64"
    return value

def subprocess_flags() -> int:
    return subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

def xray_version(path: Path) -> str:
    try:
        p = subprocess.run(
            [str(path), "version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=8, creationflags=subprocess_flags(),
        )
    except FileNotFoundError as e:
        raise XrayProbeError(f"Xray binary not found: {path}") from e
    except PermissionError as e:
        raise XrayProbeError(f"Permission denied while executing Xray: {path}") from e
    except subprocess.TimeoutExpired as e:
        raise XrayProbeError(f"Timed out while reading Xray version: {path}") from e
    except OSError as e:
        raise XrayProbeError(f"Unable to execute Xray {path}: {type(e).__name__}: {e}") from e
    output = (p.stdout or "").strip()
    if p.returncode != 0:
        raise XrayProbeError(
            f"Xray version command exited {p.returncode}: {redact_error(output[-1000:]) or '<no output>'}"
        )
    lines = output.splitlines()
    if not lines:
        raise XrayProbeError(f"Xray version command returned no output: {path}")
    return lines[0]

def download_xray() -> Path:
    system = platform.system().lower()
    arch = normalize_arch(platform.machine())
    key = (system, arch)
    if key not in XRAY_ASSETS:
        raise RuntimeError(f"Auto Xray download unsupported: {system}/{arch}")
    asset = XRAY_ASSETS[key]
    name = asset["name"]
    url = f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/{name}"
    zip_path = temporary_work_dir() / name
    req = urllib.request.Request(url, headers={"User-Agent": "VPN-Nodes-Tester/2.0"})
    log(f"[XRAY] Downloading official Xray {XRAY_VERSION}")
    with urllib.request.urlopen(req, timeout=60) as response:
        data = response.read(80_000_000)
    atomic_write_bytes(zip_path, data)
    if file_sha256(zip_path).lower() != asset["sha256"].lower():
        zip_path.unlink(missing_ok=True)
        raise RuntimeError("Downloaded Xray SHA256 mismatch")
    executable_name = "xray.exe" if system == "windows" else "xray"
    target = BIN_DIR / executable_name
    with zipfile.ZipFile(zip_path) as z:
        member = next((n for n in z.namelist() if Path(n).name.lower() == executable_name.lower()), None)
        if not member:
            raise RuntimeError("xray executable not found inside official ZIP")
        atomic_write_bytes(target, z.read(member))
    zip_path.unlink(missing_ok=True)
    if system != "windows":
        target.chmod(0o755)
    version = xray_version(target)
    if not xray_is_required_build(target, version):
        raise RuntimeError(
            f"Downloaded Xray build mismatch: expected {XRAY_VERSION} "
            f"from {XRAY_SOURCE_COMMIT[:7]}, got {version}"
        )
    return target

def xray_is_required_version(path: Path, version: str | None = None) -> bool:
    version = version if version is not None else xray_version(path)
    return bool(re.search(rf"\b{re.escape(XRAY_VERSION)}\b", version))


def xray_version_is_required_build(version: str) -> bool:
    """Verify release number and embedded source revision in Xray's banner."""
    if not re.search(rf"\b{re.escape(XRAY_VERSION)}\b", version):
        return False
    short_commit = XRAY_SOURCE_COMMIT[:7]
    return bool(re.search(rf"\b{re.escape(short_commit)}[0-9a-fA-F]*\b", version))


def xray_expected_binary_sha256() -> str | None:
    key = (platform.system().lower(), normalize_arch(platform.machine()))
    return XRAY_BINARY_SHA256.get(key)


def xray_binary_hash_is_required(path: Path) -> bool:
    expected = xray_expected_binary_sha256()
    return bool(expected and path.is_file() and file_sha256(path).lower() == expected.lower())


def xray_is_required_build(path: Path, version: str | None = None) -> bool:
    """Authenticate the exact official target build, not just its printed version."""
    version = version if version is not None else xray_version(path)
    return xray_version_is_required_build(version) and xray_binary_hash_is_required(path)

def find_xray() -> Path:
    executable_name = "xray.exe" if os.name == "nt" else "xray"
    candidates = [
        BIN_DIR / executable_name,
        BASE_DIR / executable_name,
    ]
    if os.name == "nt":
        candidates.append(XRAY_WINDOWS)

    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            version = xray_version(candidate)
        except XrayProbeError as e:
            log(f"[XRAY] Unusable private binary {candidate}: {e}")
            continue
        if xray_is_required_build(candidate, version):
            log(f"[XRAY] Using pipeline-owned binary: {candidate}")
            log(f"[XRAY] {version}")
            log(f"[XRAY] binary_sha256={file_sha256(candidate)}")
            return candidate
        log(
            f"[XRAY] Ignoring incompatible/unverified private binary {candidate}: "
            f"{version}; sha256={file_sha256(candidate)}"
        )

    if AUTO_DOWNLOAD_XRAY:
        path = download_xray()
        version = xray_version(path)
        if not xray_is_required_build(path, version):
            raise RuntimeError(
                f"Downloaded Xray build mismatch: expected {XRAY_VERSION} "
                f"from {XRAY_SOURCE_COMMIT[:7]}, got {version}"
            )
        log(f"[XRAY] Using pipeline-owned binary: {path}")
        log(f"[XRAY] {version}")
        return path
    raise FileNotFoundError(f"Pipeline-owned Xray {XRAY_VERSION} was not found")
