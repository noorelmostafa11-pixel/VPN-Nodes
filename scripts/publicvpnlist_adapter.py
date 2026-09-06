#!/usr/bin/env python3
"""PublicVPNList API adapter.

Collects PublicVPNList API records and converts them into catalog candidates.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request


BASE_URL = "https://publicvpnlist.com/api/v1/servers"

PROTOCOLS = (
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
)

PER_PAGE = 200
MAX_PAGES = 50


def build_url(protocol: str, page: int) -> str:
    params = {
        "protocol": protocol,
        "status": "online",
        "sort": "last_checked",
        "order": "desc",
        "per_page": PER_PAGE,
        "page": page,
    }

    return BASE_URL + "?" + urllib.parse.urlencode(params)


def fetch_json(url: str) -> dict:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "VPN-Nodes-Catalog/1.0",
        },
    )

    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def extract_url(item: dict) -> str:
    fields = (
        "uri",
        "config",
        "subscription",
        "config_url",
        "config_download_url",
        "server_page_url",
        "url",
    )

    for field in fields:
        value = item.get(field)

        if isinstance(value, str) and value.strip():
            return value.strip()

    return ""


def fetch_protocol(protocol: str) -> list[dict]:
    rows = []
    seen = set()

    for page in range(1, MAX_PAGES + 1):
        url = build_url(protocol, page)

        try:
            payload = fetch_json(url)
        except Exception as exc:
            print(f"WARN PublicVPNList-{protocol} page={page}: {exc}")
            break

        data = payload.get("data", [])

        if not data:
            break

        for item in data:
            config_url = extract_url(item)

            if not config_url:
                continue

            fingerprint = config_url.strip()

            if fingerprint in seen:
                continue

            seen.add(fingerprint)

            rows.append(
                {
                    "name": f"PublicVPNList-{protocol}",
                    "source": "PublicVPNList-api",
                    "url": config_url,
                    "protocol": protocol,
                    "metadata": item,
                }
            )

        if len(data) < PER_PAGE:
            break

    print(f"OK source PublicVPNList-{protocol}: {len(rows)}")

    return rows


def collect_publicvpnlist() -> list[dict]:
    rows = []

    for protocol in PROTOCOLS:
        rows.extend(fetch_protocol(protocol))

    print(f"OK source PublicVPNList-api: {len(rows)}")

    return rows
