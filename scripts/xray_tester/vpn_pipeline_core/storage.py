from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .config import (
    BIN_DIR, LOG_DIR, PREVIOUS_DIR, PRINT_LOCK, PUBLISHED_DIR, RUNS_DIR,
    RUN_ID_PATTERN, RUN_LOGS_DIR, SNAPSHOT_DIR, TMP_DIR,
)


_ACTIVE_RUN_LOG: tuple[str, str, Path] | None = None


def temporary_work_dir() -> Path:
    """Use a private worker-attempt directory for temporary engine files."""
    value = os.environ.get("VPN_ROUND_TMP_DIR")
    if not value:
        return TMP_DIR
    root = TMP_DIR.resolve()
    path = Path(value).resolve()
    if path == root or not path.is_relative_to(root) or not path.is_dir():
        raise RuntimeError("Invalid or missing worker temporary directory")
    return path


@contextmanager
def isolated_worker_temp(run_id: str, role: str):
    """Remove this worker's transient files after the attempt has closed."""
    run_id = require_safe_run_id(run_id)
    if role not in ("server1", "server2"):
        raise ValueError("Invalid worker role")
    path = safe_child(TMP_DIR, "runs", run_id, role)
    if path.exists():
        safe_rmtree(path, TMP_DIR)
    path.mkdir(parents=True, exist_ok=False)
    previous = os.environ.get("VPN_ROUND_TMP_DIR")
    os.environ["VPN_ROUND_TMP_DIR"] = str(path)
    try:
        yield path
    finally:
        if previous is None:
            os.environ.pop("VPN_ROUND_TMP_DIR", None)
        else:
            os.environ["VPN_ROUND_TMP_DIR"] = previous
        safe_rmtree(path, TMP_DIR)


def cleanup_uploaded_transients(run_id: str, role: str, run_dir: Path) -> None:
    """Finish an interrupted cleanup after a remote upload was confirmed."""
    run_id = require_safe_run_id(run_id)
    if role not in ("server1", "server2"):
        raise ValueError("Invalid worker role")
    staging = safe_child(run_dir, "private_upload")
    if staging.exists():
        safe_rmtree(staging, run_dir)
    temp = safe_child(TMP_DIR, "runs", run_id, role)
    if temp.exists():
        safe_rmtree(temp, TMP_DIR)


def prepare_dirs() -> None:
    for path in (SNAPSHOT_DIR, RUNS_DIR, BIN_DIR, TMP_DIR, LOG_DIR, RUN_LOGS_DIR):
        path.mkdir(parents=True, exist_ok=True)
    recover_tree_replacement(PUBLISHED_DIR)
    recover_tree_replacement(PREVIOUS_DIR)
    PUBLISHED_DIR.mkdir(parents=True, exist_ok=True)

def log(msg: str) -> None:
    with PRINT_LOCK:
        now = datetime.now().strftime("%H:%M:%S")
        print(f"[{now}] {msg}", flush=True)
        if _ACTIVE_RUN_LOG is not None:
            timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            with _ACTIVE_RUN_LOG[2].open("a", encoding="utf-8", errors="strict") as output:
                output.write(f"[{timestamp}] {msg}\n")
                output.flush()


def start_run_log(run_id: str, role: str) -> Path:
    """Start one worker-attempt log after the daemon accepts an active run."""
    global _ACTIVE_RUN_LOG
    run_id = require_safe_run_id(run_id)
    if role not in ("server1", "server2"):
        raise ValueError(f"Invalid worker role for run log: {role!r}")
    path = safe_child(RUN_LOGS_DIR, run_id, f"{role}.log")
    path.parent.mkdir(parents=True, exist_ok=True)
    with PRINT_LOCK:
        if _ACTIVE_RUN_LOG is not None:
            raise RuntimeError(
                f"Run log already active for {_ACTIVE_RUN_LOG[0]}/{_ACTIVE_RUN_LOG[1]}"
            )
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        with path.open("a", encoding="utf-8", errors="strict") as output:
            output.write(f"[{timestamp}] RUN_START run_id={run_id} role={role}\n")
            output.flush()
        _ACTIVE_RUN_LOG = (run_id, role, path)
    return path


def finish_run_log(run_id: str, role: str, state: str) -> None:
    """Close the accepted-run log only after final worker files are written."""
    global _ACTIVE_RUN_LOG
    run_id = require_safe_run_id(run_id)
    with PRINT_LOCK:
        active = _ACTIVE_RUN_LOG
        if active is None:
            raise RuntimeError("No active run log")
        if active[0] != run_id or active[1] != role:
            raise RuntimeError(
                f"Run log identity mismatch: active={active[0]}/{active[1]} "
                f"requested={run_id}/{role}"
            )
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        try:
            with active[2].open("a", encoding="utf-8", errors="strict") as output:
                output.write(
                    f"[{timestamp}] RUN_END run_id={run_id} role={role} state={state}\n"
                )
                output.flush()
        finally:
            _ACTIVE_RUN_LOG = None

def atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, filename = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp = Path(filename)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
        try:
            path.chmod(mode)
        except OSError:
            if os.name != "nt":
                raise
    except Exception:
        if fd >= 0:
            os.close(fd)
        temp.unlink(missing_ok=True)
        raise

def atomic_write_text(path: Path, text: str, *, mode: int = 0o644) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), mode=mode)

def write_lines(path: Path, lines: list[str]) -> None:
    atomic_write_text(path, "\n".join(lines) + ("\n" if lines else ""))

def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def redact_error(value: str) -> str:
    value = re.sub(r"(?:vless|vmess|trojan|ss)://\S+", "<redacted-uri>", value or "", flags=re.I)
    return value.replace("\r", " ").replace("\n", " ")[:1500]

def node_fingerprint(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()

def require_exact(obj: dict[str, Any], key: str, expected_type: type, context: str) -> Any:
    value = obj.get(key)
    if type(value) is not expected_type:
        raise RuntimeError(
            f"{context}.{key} must be {expected_type.__name__}, got {type(value).__name__}"
        )
    return value

def require_safe_run_id(value: Any) -> str:
    if type(value) is not str or RUN_ID_PATTERN.fullmatch(value) is None:
        raise RuntimeError("Invalid or unsafe run_id")
    return value

def parse_utc_timestamp(value: Any, field: str) -> datetime:
    if type(value) is not str or not value:
        raise RuntimeError(f"{field} must be a non-empty UTC timestamp string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as e:
        raise RuntimeError(f"Invalid {field}: {value!r}") from e
    if parsed.tzinfo is None:
        raise RuntimeError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)

def age_exceeds(value: Any, field: str, hours: float) -> bool:
    if hours <= 0:
        raise RuntimeError(f"{field} expiry hours must be positive")
    created = parse_utc_timestamp(value, field)
    return datetime.now(timezone.utc) - created >= timedelta(hours=hours)

def safe_child(root: Path, *parts: str) -> Path:
    root_resolved = root.resolve()
    candidate = root.joinpath(*parts)
    resolved = candidate.resolve(strict=False)
    if resolved == root_resolved or not resolved.is_relative_to(root_resolved):
        raise RuntimeError(f"Unsafe path outside {root_resolved}: {candidate}")
    return candidate

def safe_rmtree(path: Path, root: Path) -> None:
    checked = safe_child(root, str(path.relative_to(root)))
    if checked.is_symlink():
        raise RuntimeError(f"Refusing to remove symlink tree: {checked}")
    if checked.exists():
        shutil.rmtree(checked)

def read_json_file(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise RuntimeError(f"JSON object expected: {path}")
    return obj

def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig", errors="strict") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception as e:
                raise RuntimeError(f"Invalid JSONL {path}:{line_no}: {e}") from e
            if not isinstance(obj, dict):
                raise RuntimeError(f"JSON object expected {path}:{line_no}")
            rows.append(obj)
    return rows

def fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def replacement_marker(destination: Path) -> Path:
    return destination.parent / f".replace_{destination.name}.json"

def recover_tree_replacement(destination: Path) -> None:
    """Finish or roll back a directory replacement interrupted by process death."""
    marker = replacement_marker(destination)
    if not marker.exists():
        return
    if marker.is_symlink() or not marker.is_file():
        raise RuntimeError(f"Unsafe replacement marker: {marker}")
    transaction = read_json_file(marker)
    if transaction.get("destination") != destination.name:
        raise RuntimeError(f"Replacement marker destination mismatch: {marker}")
    backup_name = require_exact(transaction, "backup", str, str(marker))
    candidate_name = require_exact(transaction, "candidate", str, str(marker))
    if Path(backup_name).name != backup_name or Path(candidate_name).name != candidate_name:
        raise RuntimeError(f"Unsafe replacement transaction paths: {marker}")
    backup = safe_child(destination.parent, backup_name)
    candidate = safe_child(destination.parent, candidate_name)

    if not destination.exists():
        if candidate.exists():
            os.replace(candidate, destination)
        elif backup.exists():
            os.replace(backup, destination)
        else:
            raise RuntimeError(f"Cannot recover interrupted replacement: {marker}")
    if backup.exists():
        safe_rmtree(backup, destination.parent)
    if candidate.exists():
        safe_rmtree(candidate, destination.parent)
    marker.unlink(missing_ok=True)
    fsync_directory(destination.parent)

def replace_tree(destination: Path, source: Path) -> None:
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)
    recover_tree_replacement(destination)
    if source.is_symlink() or not source.is_dir():
        raise RuntimeError(f"Replacement source must be a real directory: {source}")

    nonce = f"{os.getpid()}_{time.time_ns()}"
    candidate = parent / f".candidate_{destination.name}_{nonce}"
    backup = parent / f".backup_{destination.name}_{nonce}"
    if source.resolve() != candidate.resolve(strict=False):
        os.replace(source, candidate)

    marker = replacement_marker(destination)
    atomic_write_text(
        marker,
        json.dumps(
            {
                "destination": destination.name,
                "candidate": candidate.name,
                "backup": backup.name,
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
            },
            indent=2,
        ) + "\n",
        mode=0o600,
    )
    fsync_directory(parent)

    try:
        if destination.exists():
            os.replace(destination, backup)
            fsync_directory(parent)
        os.replace(candidate, destination)
        fsync_directory(parent)
        if backup.exists():
            safe_rmtree(backup, parent)
        marker.unlink(missing_ok=True)
        fsync_directory(parent)
    except Exception:
        if not destination.exists() and backup.exists():
            os.replace(backup, destination)
            fsync_directory(parent)
        raise
