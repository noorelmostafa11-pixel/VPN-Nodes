#!/usr/bin/env python3
"""Extract V2Ray style links from HTML sources.

Handles normal HTML, embedded JavaScript/JSON, href attributes and base64 blobs.
"""
from __future__ import annotations

import base64
import re
import urllib.request
from share_link_extractor import ExtractedURI, extract_uri_records

PATTERNS = (
    r"vless://[^\s\"'<>\\]+",
    r"vmess://[^\s\"'<>\\]+",
    r"trojan://[^\s\"'<>\\]+",
    r"ss://[^\s\"'<>\\]+",
)


def _clean(value: str) -> str:
    return value.replace("&amp;", "&").strip(" '\"<>),;\\")


def extract_links(text: str) -> list[str]:
    return list(dict.fromkeys(item.uri for item in _extract_records(text)))


def _extract_records(text: str) -> list:
    found = extract_uri_records(text, html_source=True)

    # Decode common base64 blocks found in node pages.
    for block in re.findall(r"[A-Za-z0-9+/]{80,}={0,2}", text):
        try:
            decoded = base64.b64decode(block + "===").decode("utf-8", errors="ignore")
            found.extend(extract_uri_records(decoded))
        except Exception:
            pass

    # Preserve the old punctuation cleanup on simple links, while keeping all
    # delimiters belonging to a newly supported structured query value.
    return list(dict.fromkeys(item if item.structured else ExtractedURI(
        item.uri.rstrip(" '\"<>),;\\"), item.original_uri, item.literal)
        for item in found))


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
    return [{"name": name, "url": url, "link": item.uri, **item.source_fields()} for item in _extract_records(html)]
