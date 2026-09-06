#!/usr/bin/env python3
"""Extract V2Ray style links from HTML sources.

Supports pages that publish VLESS/VMess/Trojan/SS links in normal HTML.
"""
from __future__ import annotations

import re
import urllib.request

PATTERNS = (
    r"vless://[^\s\"'<>]+",
    r"vmess://[^\s\"'<>]+",
    r"trojan://[^\s\"'<>]+",
    r"ss://[^\s\"'<>]+",
)


def extract_links(text: str) -> list[str]:
    found = []
    for pattern in PATTERNS:
        found.extend(re.findall(pattern, text, flags=re.I))
    return list(dict.fromkeys(found))


def fetch_html(url: str, timeout: int = 15) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="ignore")


def collect_html_source(name: str, url: str) -> list[dict]:
    html = fetch_html(url)
    return [{"name": name, "url": url, "link": link} for link in extract_links(html)]
