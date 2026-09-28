from __future__ import annotations

import os
import re
import threading
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
PUBLIC_REPO = "noorelmostafa11-pixel/VPN-Nodes"
PUBLIC_BRANCH = "main"
PRIVATE_REPO = os.environ.get("VPN_PRIVATE_REPO", "noorelmostafa11-pixel/VPN-Nodes-Private").strip()
PRIVATE_BRANCH = os.environ.get("VPN_PRIVATE_BRANCH", "main").strip() or "main"
GITHUB_TOKEN = (os.environ.get("VPN_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN") or "").strip()

ROLE_SLOTS = {"server1": 0, "server2": 1}
ACTIVE_CONTROL_PATH = "control/active.json"
CURRENT_MANIFEST_PATH = "current/manifest.json"
COORDINATOR_POLL_SECONDS = int(os.environ.get("VPN_POLL_SECONDS", "60"))
ACTIVE_RUN_MAX_HOURS = float(os.environ.get("VPN_ACTIVE_RUN_MAX_HOURS", "24"))
REJECTED_RUN_RETRY_HOURS = float(os.environ.get("VPN_REJECTED_RUN_RETRY_HOURS", "1"))
REPOSITORY_HISTORY_KEEP = 2
LOCAL_WORKER_HISTORY_KEEP = 2

PROTOCOL_SOURCES = {
    "vless": "output/protocols/vless.txt",
    "vmess": "output/protocols/vmess.txt",
    "trojan": "output/protocols/trojan.txt",
    "ss": "output/protocols/shadowsocks.txt",
}

SCHEMES = {
    "vless": "vless://",
    "vmess": "vmess://",
    "trojan": "trojan://",
    "ss": "ss://",
}

XRAY_WINDOWS = Path(r"C:\Users\admin\Downloads\v2rayN-windows-64\bin\xray\xray.exe")

# Keep the established server-side concurrency ceiling.  The Real Delay engine
# can place up to REAL_PING_PAGE_SIZE nodes in one Xray process, but Python
# performs at most WORKERS blocking HTTP tests concurrently.  This preserves
# the proven resource ceiling on the ~1 GB E2 workers while removing repeated
# Xray startup/probe work.
WORKERS = 40
HTTP_TIMEOUT = 12.0

# One verified HTTPS response through each node's Xray SOCKS port.
# The primary Google target is supplied only at runtime through a GitHub Actions
# secret.  Microsoft is a public fallback and is tried only after the primary
# target fails, so nodes that pass Google incur no extra request or runner time.
REAL_PING_URL = (
    os.environ.get("VPN_TEST_URL", "").strip()
    or os.environ.get("VPN_REAL_PING_URL", "").strip()
)
MICROSOFT_FALLBACK_URL = "https://www.microsoft.com/robots.txt"
REAL_PING_TARGETS = (
    ("google", REAL_PING_URL, float(os.environ.get("VPN_REAL_PING_GOOGLE_TIMEOUT", "9"))),
    (
        "microsoft",
        MICROSOFT_FALLBACK_URL,
        float(os.environ.get("VPN_REAL_PING_MICROSOFT_TIMEOUT", "5")),
    ),
)
REAL_PING_PAGE_SIZE = int(os.environ.get("VPN_REAL_PING_PAGE_SIZE", "1000"))
REAL_PING_ISOLATION_CONCURRENCY = int(os.environ.get("VPN_REAL_PING_ISOLATION_CONCURRENCY", "5"))
REAL_PING_PROCESS_CHECK_DELAY = 0.1
REAL_PING_CORE_START_DELAY = 1.0
REAL_PING_BATCH_DELAY = 1.0

# This name remains only because the repository-side GeoIP fallback passes a
# structurally required URL into the parsers.  It is not a fallback test URL.
CONNECTIVITY_URL = REAL_PING_URL

COUNTRY_URL = os.environ.get("VPN_COUNTRY_URL", "").strip()
XRAY_VERSION = "26.9.9"
XRAY_SOURCE_COMMIT = "52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120"
AUTO_DOWNLOAD_XRAY = True
TESTER_SCHEMA = 5

RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")

# SHA256 of the executable files produced by the official v26.9.9 GitHub
# Actions release run for commit XRAY_SOURCE_COMMIT.  ZIP hashes above protect
# auto-download; these executable hashes also authenticate a pre-existing local
# binary before the pipeline trusts it.
XRAY_BINARY_SHA256 = {
    ("windows", "x86_64"): "0d0fc0ea2b05641acb78c01fc36ad694e7b029861b2d5eb93da0e3e9fda9a98f",
    ("linux", "x86_64"): "c4ae6798c38e0e5343b192406746333cd0ba7ff3eb984f8c4b9939dcb68c3f8a",
    ("linux", "arm64"): "c1defe42b6db958a97c5e049a02a00a4baaedaca7b51c1c229f0830e288acef5",
}

XRAY_ASSETS = {
    ("windows", "x86_64"): {
        "name": "Xray-windows-64.zip",
        "sha256": "244deaba2098c2964e49bba90df3707777e5f5f428a82d2f29604015f24beec2",
    },
    ("linux", "x86_64"): {
        "name": "Xray-linux-64.zip",
        "sha256": "1eb9175d0f0a8f8149c9230a7fc5ae66ce332ed20a53155ce61fe62e3f58b7df",
    },
    ("linux", "arm64"): {
        "name": "Xray-linux-arm64-v8a.zip",
        "sha256": "3e38d72dfc5eb65c91df0e5583e9b6676c32232041da47de6ae73946b526d66c",
    },
}

PRINT_LOCK = threading.Lock()

DATA_DIR = BASE_DIR / "data"
SNAPSHOT_DIR = DATA_DIR / "snapshots"
RESULTS_DIR = BASE_DIR / "results"
RUNS_DIR = RESULTS_DIR / "runs"
PUBLISHED_DIR = RESULTS_DIR / "published"
PREVIOUS_DIR = RESULTS_DIR / "previous"
BIN_DIR = BASE_DIR / "bin"
TMP_DIR = BASE_DIR / "tmp"
LOG_DIR = BASE_DIR / "logs"
RUN_LOGS_DIR = LOG_DIR / "runs"
GEOIP_HELPER = BASE_DIR / "tools" / "geoip_xx.js"
