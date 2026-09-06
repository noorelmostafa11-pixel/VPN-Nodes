#!/usr/bin/env python3
"""Extract V2Ray style links from HTML sources.

Handles normal HTML, embedded JavaScript/JSON, href attributes and base64 blobs.
"""
from __future__ import annotations

import base64
import re
import urllib.request

PATTERNS = (
    r"vless://[^\s\"'<>\\]+",
    r"vmess://[^\s\"'<>\\]+",
    r"trojan://[^\s\"'<>\\]+",
    r"ss://[^\s\"'<>\\]+",
)


def _clean(value: str) -> str:
    return value.replace("&amp;", "&").strip(" '\"<>),;\\")


def extract_links(text: str) -> list[str]:
    found: list[str] = []
    for pattern in PATTERNS:
        found.extend(_clean(x) for x in re.findall(pattern, text, flags=re.I))

    # Decode common base64 blocks found in node pages.
    for block in re.findall(r"[A-Za-z0-9+/]{80,}={0,2}", text):
        try:
            decoded = base64.b64decode(block + "===").decode("utf-8", errors="ignore")
            for pattern in PATTERNS:
                found.extend(_clean(x) for x in re.findall(pattern, decoded, flags=re.I))
        except Exception:
            pass

    return list(dict.fromkeys(x for x in found if "://" in x))


def fetch_html(url: str, timeout: int = 20) -> str:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="ignore")


def collect_html_source(name: str, url: str) -> list[dict]:
    html = fetch_html(url)
    return [{"name": name, "url": url, "link": link} for link in extract_links(html)]
