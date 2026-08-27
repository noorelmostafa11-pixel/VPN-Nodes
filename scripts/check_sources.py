from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "sources" / "sources.json"
STATE = ROOT / ".github" / "source_state.json"
PENDING = ROOT / ".github" / "source_state.pending.json"
MAX_SOURCE_BYTES = 2_000_000
CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 8.0

session = requests.Session()
session.headers.update({"User-Agent": "Ahmed-VPN-Nodes/2.1-source-watch"})
if os.getenv("GITHUB_TOKEN"):
    session.headers.update({"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"})


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_digest(value) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return digest_bytes(encoded)


def fingerprint(item: dict) -> str:
    url = item["url"]
    response = session.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), stream=True)
    response.raise_for_status()

    content_type = response.headers.get("content-type", "")
    if "api.github.com/" in url or url.startswith("https://api.github.com/"):
        payload = response.json()
        # GitHub directory/tree responses are normalized so harmless ordering changes
        # do not trigger a refresh.
        if isinstance(payload, list):
            normalized = []
            for entry in payload:
                if isinstance(entry, dict):
                    normalized.append({k: entry.get(k) for k in ("name", "path", "type", "sha", "size", "download_url")})
                else:
                    normalized.append(entry)
            normalized.sort(key=lambda x: (str(x.get("path", x.get("name", ""))), str(x.get("sha", ""))) if isinstance(x, dict) else str(x))
            return "github:" + canonical_digest(normalized)
        if isinstance(payload, dict) and isinstance(payload.get("tree"), list):
            normalized = [
                {"path": e.get("path"), "type": e.get("type"), "sha": e.get("sha"), "size": e.get("size")}
                for e in payload["tree"]
                if isinstance(e, dict)
            ]
            normalized.sort(key=lambda x: (str(x["path"]), str(x["sha"])))
            return "github:" + canonical_digest(normalized)
        return "github:" + canonical_digest(payload)

    # For raw feeds prefer server validators. This avoids downloading large feeds
    # on every polling cycle. If validators are unavailable, hash the bounded body.
    etag = response.headers.get("etag")
    last_modified = response.headers.get("last-modified")
    length = response.headers.get("content-length")
    if etag or last_modified:
        return "http:" + canonical_digest({"etag": etag, "last_modified": last_modified, "length": length})

    data = bytearray()
    for chunk in response.iter_content(8192):
        data.extend(chunk)
        if len(data) >= MAX_SOURCE_BYTES:
            break
    return "body:" + digest_bytes(bytes(data[:MAX_SOURCE_BYTES]))


def load_state() -> dict:
    if not STATE.exists():
        return {}
    try:
        value = json.loads(STATE.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def main() -> int:
    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    previous = load_state()
    current = {}
    changed = not bool(previous)
    errors = 0

    for item in cfg["sources"]:
        name = item["name"]
        try:
            fp = fingerprint(item)
            current[name] = {"fingerprint": fp, "url": item["url"]}
            if previous.get(name, {}).get("fingerprint") != fp:
                changed = True
                print(f"CHANGED {name}")
            else:
                print(f"UNCHANGED {name}")
        except Exception as exc:
            errors += 1
            # An unreachable source is not considered changed. The collector's
            # existing snapshot fallback remains responsible for source outages.
            print(f"WARN {name}: {exc}")

    # Never replace the committed state before a successful catalog refresh.
    # The workflow promotes this pending state only after the collector succeeds.
    if changed and current:
        PENDING.parent.mkdir(parents=True, exist_ok=True)
        PENDING.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
        out.write(f"changed={'true' if changed else 'false'}\n")
        out.write(f"errors={errors}\n")

    print(f"SOURCE_CHANGED={'true' if changed else 'false'} SOURCE_ERRORS={errors}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
