#!/usr/bin/env python3
"""Rate-limit-aware FreeProxyDB adapter with a rolling repository cache.

The public search API returns at most 100 records per request and limits the
total records returned to one client IP over time. Request all supported
protocols together, continue from a different page on the next workflow run,
and retain recently seen nodes when the upstream returns HTTP 429.
"""

from __future__ import annotations

import json
import math
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CACHE_FILE = ROOT / "output" / "metadata" / "freeproxydb_cache.json"
BASE_URL = "https://freeproxydb.com/api/proxy/search"
PROTOCOLS = ("vless", "vmess", "trojan", "ss")
SUPPORTED_PREFIXES = tuple(f"{protocol}://" for protocol in PROTOCOLS)

PAGE_SIZE = 100
MAX_REQUESTS_PER_RUN = max(
    1,
    int(os.environ.get("FREEPROXYDB_REQUESTS_PER_RUN", "20")),
)
PAGE_DELAY = max(
    0.0,
    float(os.environ.get("FREEPROXYDB_PAGE_DELAY", "2")),
)
CACHE_MAX_AGE_HOURS = max(
    1,
    int(os.environ.get("FREEPROXYDB_CACHE_MAX_AGE_HOURS", "72")),
)
MAX_CACHE_NODES = max(
    PAGE_SIZE,
    int(os.environ.get("FREEPROXYDB_MAX_CACHE_NODES", "20000")),
)
MAX_RETRIES = 3


class RateLimited(RuntimeError):
    """The public API record quota has been reached for this runner IP."""


def fetch_json(url: str) -> dict:
    for attempt in range(1, MAX_RETRIES + 1):
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "VPN-Nodes-Catalog/1.0",
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                # Sleeping for a few seconds cannot reset the hourly/record
                # quota. Preserve the cache and resume on the next workflow.
                raise RateLimited("public API record quota reached") from exc
            if 500 <= exc.code < 600 and attempt < MAX_RETRIES:
                time.sleep(attempt * 5)
                continue
            raise
        except (OSError, json.JSONDecodeError):
            if attempt >= MAX_RETRIES:
                raise
            time.sleep(attempt * 5)

    raise RuntimeError("FreeProxyDB request failed")


def build_url(page: int) -> str:
    params = {
        "protocol": ",".join(PROTOCOLS),
        "speed": "0,60",
        "page_index": page,
        "page_size": PAGE_SIZE,
        "order_by": "id",
        "order_dir": "desc",
    }
    return BASE_URL + "?" + urllib.parse.urlencode(params)


def extract_uri(item) -> str:
    if isinstance(item, str):
        value = item.strip()
        return value if value.startswith(SUPPORTED_PREFIXES) else ""

    if not isinstance(item, dict):
        return ""

    for key in (
        "connect_string",
        "uri",
        "config",
        "link",
        "url",
        "v2ray",
        "subscription",
    ):
        value = item.get(key)
        if isinstance(value, str):
            value = value.strip()
            if value.startswith(SUPPORTED_PREFIXES):
                return value

    return ""


def _positive_int(*values) -> int:
    for value in values:
        try:
            number = int(value)
        except (TypeError, ValueError):
            continue
        if number > 0:
            return number
    return 0


def extract_data(payload: dict) -> tuple[list, int]:
    if not isinstance(payload, dict):
        return [], 0

    container = payload.get("data", [])
    if isinstance(container, dict):
        rows = (
            container.get("data")
            or container.get("items")
            or container.get("list")
            or []
        )
        total = _positive_int(
            container.get("total_count"),
            container.get("total"),
            container.get("count"),
            payload.get("total_count"),
            payload.get("total"),
        )
        return (rows if isinstance(rows, list) else []), total

    total = _positive_int(payload.get("total_count"), payload.get("total"))
    return (container if isinstance(container, list) else []), total


def _load_cache(now: int) -> tuple[dict[str, int], int]:
    if not CACHE_FILE.is_file():
        return {}, 1

    try:
        payload = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}, 1

    cutoff = now - CACHE_MAX_AGE_HOURS * 3600
    nodes: dict[str, int] = {}

    for item in payload.get("nodes", []):
        if not isinstance(item, dict):
            continue

        uri = str(item.get("uri") or "").strip()
        try:
            seen_at = int(item.get("last_seen_at") or 0)
        except (TypeError, ValueError):
            continue

        if uri.startswith(SUPPORTED_PREFIXES) and seen_at >= cutoff:
            nodes[uri] = max(nodes.get(uri, 0), seen_at)

    try:
        next_page = max(1, int(payload.get("next_page") or 1))
    except (TypeError, ValueError):
        next_page = 1

    return nodes, next_page


def _save_cache(
    nodes: dict[str, int],
    *,
    next_page: int,
    total_count: int,
    pages_fetched: int,
    rate_limited: bool,
    now: int,
) -> dict[str, int]:
    cutoff = now - CACHE_MAX_AGE_HOURS * 3600
    ordered = sorted(
        (
            (uri, seen_at)
            for uri, seen_at in nodes.items()
            if uri.startswith(SUPPORTED_PREFIXES) and seen_at >= cutoff
        ),
        key=lambda row: (-row[1], row[0]),
    )[:MAX_CACHE_NODES]
    kept = dict(ordered)

    payload = {
        "schema": 1,
        "generated_at": now,
        "protocols": list(PROTOCOLS),
        "page_size": PAGE_SIZE,
        "requests_per_run": MAX_REQUESTS_PER_RUN,
        "cache_max_age_hours": CACHE_MAX_AGE_HOURS,
        "total_count_reported": total_count,
        "pages_fetched": pages_fetched,
        "rate_limited": rate_limited,
        "next_page": max(1, next_page),
        "nodes": [
            {"uri": uri, "last_seen_at": seen_at}
            for uri, seen_at in ordered
        ],
    }

    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = CACHE_FILE.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    temporary.replace(CACHE_FILE)
    return kept


def collect_freeproxydb() -> list[dict]:
    now = int(time.time())
    nodes, start_page = _load_cache(now)
    previous_count = len(nodes)
    next_page = start_page
    total_count = 0
    pages_fetched = 0
    rate_limited = False

    for offset in range(MAX_REQUESTS_PER_RUN):
        page = start_page + offset

        try:
            payload = fetch_json(build_url(page))
        except RateLimited as exc:
            rate_limited = True
            next_page = page
            print(
                f"INFO FreeProxyDB page {page}: {exc}; "
                f"retaining {len(nodes)} cached nodes"
            )
            break
        except Exception as exc:
            next_page = page
            print(
                f"WARN FreeProxyDB page {page}: {exc}; "
                f"retaining {len(nodes)} cached nodes"
            )
            break

        data, reported_total = extract_data(payload)
        total_count = max(total_count, reported_total)

        if not data:
            next_page = 1
            print(f"INFO FreeProxyDB page {page}: empty; restarting at page 1")
            break

        pages_fetched += 1
        for item in data:
            uri = extract_uri(item)
            if uri:
                nodes[uri] = now

        total_pages = (
            math.ceil(total_count / PAGE_SIZE)
            if total_count
            else 0
        )
        reached_end = (
            len(data) < PAGE_SIZE
            or (total_pages and page >= total_pages)
        )
        next_page = 1 if reached_end else page + 1

        print(
            f"FreeProxyDB page {page}: records={len(data)} "
            f"cache={len(nodes)} total={total_count or 'unknown'}"
        )

        if reached_end:
            break
        if offset + 1 < MAX_REQUESTS_PER_RUN:
            time.sleep(PAGE_DELAY)

    nodes = _save_cache(
        nodes,
        next_page=next_page,
        total_count=total_count,
        pages_fetched=pages_fetched,
        rate_limited=rate_limited,
        now=now,
    )

    counts = Counter(uri.split("://", 1)[0].lower() for uri in nodes)
    rows = [
        {
            "name": f"FreeProxyDB-{uri.split('://', 1)[0].lower()}",
            "source": "FreeProxyDB-api",
            "url": uri,
            "protocol": uri.split("://", 1)[0].lower(),
        }
        for uri in sorted(nodes)
    ]

    details = ", ".join(
        f"{protocol}={counts.get(protocol, 0)}"
        for protocol in PROTOCOLS
    )
    print(
        f"OK source FreeProxyDB-api: cached={len(rows)} "
        f"previous={previous_count} pages={pages_fetched} "
        f"next_page={next_page} ({details})"
    )
    return rows

