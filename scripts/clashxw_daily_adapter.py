#!/usr/bin/env python3
"""ClashXW daily dated subscription adapter."""

from __future__ import annotations

import base64
import datetime
import re
import urllib.request


BASE_URL = "https://clashxw.github.io/uploads"
FILE_INDEXES = range(0, 20)
PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://")


def fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "VPN-Nodes-Catalog/1.0"})
    with urllib.request.urlopen(req, timeout=20) as response:
        return response.read().decode("utf-8", errors="ignore")


def build_daily_urls() -> list[str]:
    now = datetime.datetime.utcnow()
    date = now.strftime("%Y%m%d")
    return [
        f"{BASE_URL}/{now.strftime('%Y')}/{now.strftime('%m')}/{i}-{date}.txt"
        for i in FILE_INDEXES
    ]


def decode_base64(text: str) -> str:
    try:
        raw = "".join(text.split())
        raw += "=" * (-len(raw) % 4)
        return base64.b64decode(raw).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def extract_nodes(text: str) -> list[dict]:
    rows = []
    seen = set()

    for content in (text, decode_base64(text)):
        for node in re.findall(r"(?:vless|vmess|trojan|ss)://[^\s]+", content):
            node = node.strip()
            if node not in seen:
                seen.add(node)
                rows.append({
                    "name": "ClashXW-Daily",
                    "source": "clashxw-daily",
                    "url": node,
                })

    return rows


def collect_clashxw_daily() -> list[dict]:
    rows = []
    seen = set()

    for url in build_daily_urls():
        try:
            found = extract_nodes(fetch_text(url))
            for item in found:
                if item["url"] not in seen:
                    seen.add(item["url"])
                    rows.append(item)
            if found:
                print(f"OK ClashXW file: {url} nodes={len(found)}")
        except Exception:
            continue

    print(f"OK source ClashXW-Daily total: {len(rows)}")
    return rows
