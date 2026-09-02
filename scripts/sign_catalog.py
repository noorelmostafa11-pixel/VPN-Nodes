#!/usr/bin/env python3
"""Build a deterministic SHA-256 catalog manifest and ECDSA-sign it.

The signing key is never read from the repository. GitHub Actions supplies a
base64-encoded PEM key via CATALOG_SIGNING_PRIVATE_KEY_B64. Publication must fail
closed when that secret is unavailable so a release client never sees a silently
unsigned catalog generation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
META = OUT / "metadata"
MANIFEST = META / "catalog_manifest.json"
SIGNATURE = META / "catalog_manifest.sig"
PUBLIC_KEY = ROOT / "data" / "catalog_signing_public_key.pem"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def included_files() -> list[Path]:
    required = [META / "countries.json", META / "app_pool.json"]
    missing = [str(p.relative_to(ROOT)) for p in required if not p.is_file()]
    if missing:
        raise SystemExit(f"Missing required catalog file(s): {', '.join(missing)}")

    files = required[:]
    handshake = META / "transport_handshake.json"
    if handshake.is_file():
        files.append(handshake)

    country_files = sorted((OUT / "countries").glob("*.txt"))
    shard_files = sorted((OUT / "country_shards").glob("*/*.txt"))
    protocol_files = sorted((OUT / "protocols").glob("*.txt"))
    if not country_files:
        raise SystemExit("No country feeds were generated")
    if not shard_files:
        raise SystemExit("No country shards were generated")

    files.extend(country_files)
    files.extend(shard_files)
    files.extend(protocol_files)
    return files


def main() -> int:
    META.mkdir(parents=True, exist_ok=True)
    app_meta = json.loads((META / "app_pool.json").read_text(encoding="utf-8"))
    generated_at = str(app_meta.get("generated_at") or "")
    files = {path.relative_to(ROOT).as_posix(): digest(path) for path in included_files()}
    payload = {
        "schema": 2,
        "algorithm": "ECDSA_P256_SHA256",
        "generated_at": generated_at,
        "files": dict(sorted(files.items())),
    }
    MANIFEST.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )

    encoded_key = os.environ.get("CATALOG_SIGNING_PRIVATE_KEY_B64", "").strip()
    if not encoded_key:
        raise SystemExit("CATALOG_SIGNING_PRIVATE_KEY_B64 is required; refusing unsigned catalog publication")

    try:
        private_pem = base64.b64decode(encoded_key, validate=True)
    except Exception as exc:
        raise SystemExit(f"Invalid CATALOG_SIGNING_PRIVATE_KEY_B64: {exc}")
    if b"BEGIN PRIVATE KEY" not in private_pem and b"BEGIN EC PRIVATE KEY" not in private_pem:
        raise SystemExit("Catalog signing secret is not a PEM private key")
    if not PUBLIC_KEY.is_file():
        raise SystemExit(f"Public key missing: {PUBLIC_KEY.relative_to(ROOT)}")

    with tempfile.TemporaryDirectory(prefix="catalog-sign-") as tmp:
        key_path = Path(tmp) / "key.pem"
        sig_path = Path(tmp) / "signature.der"
        key_path.write_bytes(private_pem)
        key_path.chmod(0o600)
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(key_path), "-out", str(sig_path), str(MANIFEST)],
            check=True,
        )
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(PUBLIC_KEY), "-signature", str(sig_path), str(MANIFEST)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        SIGNATURE.write_text(base64.b64encode(sig_path.read_bytes()).decode("ascii") + "\n", encoding="ascii")

    print(f"OK signed catalog manifest files={len(files)} signature={SIGNATURE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
