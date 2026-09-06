#!/usr/bin/env python3
"""ClashXW daily dated subscription adapter."""

from __future__ import annotations

import datetime
import urllib.request


BASE_URL = "https://clashxw.github.io/uploads"
FILE_INDEXES = range(0, 20)


def fetch_text(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "VPN-Nodes-Catalog/1.0"},
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        return response.read().decode("utf-8", errors="ignore")


def build_daily_urls() -> list[str]:
    now = datetime.datetime.utcnow()
    year = now.strftime("%Y")
    month = now.strftime("%m")
    date = now.strftime("%Y%m%d")

    return [
        f"{BASE_URL}/{year}/{month}/{index}-{date}.txt"
        for index in FILE_INDEXES
    ]


def extract_nodes(text: str) -> list[dict]:
    rows = []
    seen = set()

    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("vless://", "vmess://", "trojan://", "ss://")):
            if line not in seen:
                seen.add(line)
                rows.append({
                    "name": "ClashXW-Daily",
                    "source": "clashxw-daily",
                    "url": line,
                })

    return rows


def collect_clashxw_daily() -> list[dict]:
    rows = []

    for url in build_daily_urls():
        try:
            rows.extend(extract_nodes(fetch_text(url)))
            print(f"OK source ClashXW-Daily: {url}")
        except Exception:
            continue

    print(f"OK source ClashXW-Daily total: {len(rows)}")
    return rows
