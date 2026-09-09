#!/usr/bin/env python3
"""Discover hidden node endpoints from V2Ray source pages."""
from __future__ import annotations

import re
import urllib.request

ENDPOINT_PATTERNS = (
    r"https?://[^\"'<>\s]+(?:\.json|\.yaml|\.yml|/api/|/sub[^\"'<>\s]*)",
    r"[\"']([^\"']*(?:clash|base64|subscription|sub|config)[^\"']*)[\"']",
)


def fetch_page(url: str, timeout: int = 20) -> str:
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0",
        "Accept": "text/html,application/json,*/*",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")


def discover_endpoints(url: str) -> list[str]:
    html = fetch_page(url)
    found = []
    for pattern in ENDPOINT_PATTERNS:
        for item in re.findall(pattern, html, flags=re.I):
            if isinstance(item, tuple):
                item = item[0]
            if item.startswith("/"):
                base = url.rstrip("/")
                item = base + item
            found.append(item)
    return list(dict.fromkeys(found))


def discover_source(name: str, url: str) -> dict:
    try:
        endpoints = discover_endpoints(url)
        return {"name": name, "url": url, "endpoints": endpoints, "ok": True}
    except Exception as exc:
        return {"name": name, "url": url, "endpoints": [], "ok": False, "error": str(exc)}
