#!/usr/bin/env python3
"""Independent fallback updater for a private Oracle server.

Run from a checked-out VPN-Nodes repository on Oracle. It updates the catalog only
when the published catalog is older than MAX_STALENESS_MINUTES, or when metadata
is missing. GitHub remains the canonical public repository; Oracle is a secondary
publisher used only when scheduled GitHub Actions has not refreshed the catalog.

Required environment:
  GITHUB_TOKEN   GitHub token with contents:write for noorelmostafa11-pixel/VPN-Nodes

Optional environment:
  MAX_STALENESS_MINUTES (default 75)
  REPO_DIR (default: directory containing this script's parent repository)

Safety:
  Create the tracked .oracle_updates_paused file at the repository root to pause
  all automatic Oracle fallback refreshes during catalog experiments. Remove the
  file to re-enable the fallback updater.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

MAX_STALENESS_MINUTES = int(os.getenv("MAX_STALENESS_MINUTES", "75"))
REPO_DIR = Path(os.getenv("REPO_DIR", Path(__file__).resolve().parents[1])).resolve()
REMOTE = "https://github.com/noorelmostafa11-pixel/VPN-Nodes.git"
PAUSE_FILE = REPO_DIR / ".oracle_updates_paused"


def run(*args: str) -> None:
    subprocess.run(args, cwd=REPO_DIR, check=True)


def catalog_age_minutes() -> float | None:
    path = REPO_DIR / "output" / "metadata" / "index.json"
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        generated = datetime.fromisoformat(payload["generated_at"].replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - generated).total_seconds() / 60.0
    except Exception:
        return None


def main() -> int:
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("ERROR GITHUB_TOKEN is required", file=sys.stderr)
        return 2

    run("git", "remote", "set-url", "origin", REMOTE)
    run("git", "fetch", "origin", "main", "--prune")
    run("git", "reset", "--hard", "origin/main")

    if PAUSE_FILE.exists():
        print("INFO Oracle fallback updates are paused by .oracle_updates_paused")
        return 0

    age = catalog_age_minutes()
    print(f"INFO catalog_age_minutes={age}")
    if age is not None and age <= MAX_STALENESS_MINUTES:
        print("INFO catalog is fresh; fallback update not required")
        return 0

    print("INFO catalog is stale or missing; running full catalog update")
    run(sys.executable, "scripts/update_catalog.py")

    run("git", "config", "user.name", "oracle-catalog-bot")
    run("git", "config", "user.email", "oracle-catalog-bot@users.noreply.github.com")
    run("git", "add", "output")
    diff = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=REPO_DIR)
    if diff.returncode == 0:
        print("INFO no catalog changes produced")
        return 0

    run("git", "commit", "-m", "chore: Oracle fallback catalog refresh")

    # Retry after rebasing in case GitHub Actions or another writer updated main.
    for attempt in range(1, 4):
        try:
            run("git", "fetch", "origin", "main")
            run("git", "rebase", "origin/main")
            authenticated_remote = REMOTE.replace(
                "https://github.com/", f"https://x-access-token:{token}@github.com/", 1
            )
            subprocess.run(
                ["git", "push", authenticated_remote, "HEAD:main"],
                cwd=REPO_DIR,
                check=True,
            )
            print(f"OK Oracle fallback push succeeded on attempt {attempt}")
            return 0
        except subprocess.CalledProcessError:
            if attempt == 3:
                raise
            run("git", "rebase", "--abort")
            time.sleep(attempt * 5)
            run("git", "fetch", "origin", "main")
            run("git", "rebase", "origin/main")

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
