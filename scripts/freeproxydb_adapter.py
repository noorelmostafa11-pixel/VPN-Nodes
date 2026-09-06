#!/usr/bin/env python3
"""FreeProxyDB API adapter.

Collects V2Ray nodes from FreeProxyDB search API using pagination.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request


BASE_URL = "https://freeproxydb.com/api/proxy/search"

PROTOCOLS = (
    "vless",
    "vmess",
    "trojan",
    "ss",
)

PAGE_SIZE = 100
MAX_PAGES = 500


def fetch_json(url: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "VPN-Nodes-Catalog/1.0",
        },
    )

    with urllib.request.urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def build_url(protocol: str, page: int) -> str:
    params = {
        "country": "",
        "protocol": protocol,
        "anonymity": "",
        "speed": "0,60",
        "https": "0",
        "page_index": page,
        "page_size": PAGE_SIZE,
        "order_by": "id",
        "order_dir": "desc",
    }

    return BASE_URL + "?" + urllib.parse.urlencode(params)


def extract_uri(item) -> str:
    """
    Supports:
    1) Direct URI strings:
       vless://...
       vmess://...
       trojan://...
       ss://...

    2) JSON objects containing URI fields.
    """

    if isinstance(item, str):
        value = item.strip()

        if value.startswith(
            (
                "vless://",
                "vmess://",
                "trojan://",
                "ss://",
            )
        ):
            return value

        return ""

    if not isinstance(item, dict):
        return ""

    for key in (
        "uri",
        "config",
        "link",
        "url",
        "v2ray",
        "subscription",
    ):
        value = item.get(key)

        if isinstance(value, str) and "://" in value:
            return value.strip()

    return ""


def fetch_protocol(protocol: str) -> list[dict]:
    rows = []
    seen = set()

    for page in range(1, MAX_PAGES + 1):

        try:
            payload = fetch_json(
                build_url(protocol, page)
            )

        except Exception as exc:
            print(
                f"WARN FreeProxyDB-{protocol} page {page}: {exc}"
            )
            break


        data = payload.get("data", [])

        if not data:
            break


        for item in data:

            uri = extract_uri(item)

            if not uri:
                continue

            if uri in seen:
                continue

            seen.add(uri)

            rows.append(
                {
                    "name": f"FreeProxyDB-{protocol}",
                    "source": "FreeProxyDB-api",
                    "url": uri,
                    "protocol": protocol,
                    "metadata": item,
                }
            )


        if len(data) < PAGE_SIZE:
            break


    print(
        f"OK source FreeProxyDB-{protocol}: {len(rows)}"
    )

    return rows


def collect_freeproxydb() -> list[dict]:

    rows = []

    for protocol in PROTOCOLS:
        rows.extend(
            fetch_protocol(protocol)
        )

    print(
        f"OK source FreeProxyDB-api: {len(rows)}"
    )

    return rows
