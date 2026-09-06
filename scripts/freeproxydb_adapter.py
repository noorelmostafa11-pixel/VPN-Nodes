#!/usr/bin/env python3
"""FreeProxyDB API adapter.

Collects V2Ray nodes from FreeProxyDB search API using pagination.
Handles API rate limiting.
"""

from __future__ import annotations

import json
import time
import urllib.error
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
MAX_PAGES = 5000

PAGE_DELAY = 2
PROTOCOL_DELAY = 30
MAX_RETRIES = 4


def fetch_json(url: str) -> dict:

    for attempt in range(1, MAX_RETRIES + 1):

        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "VPN-Nodes-Catalog/1.0",
            },
        )

        try:

            with urllib.request.urlopen(
                req,
                timeout=20
            ) as response:

                return json.loads(
                    response.read().decode("utf-8")
                )


        except urllib.error.HTTPError as exc:

            if exc.code == 429:

                wait = attempt * 10

                print(
                    f"WARN FreeProxyDB rate limit "
                    f"retry {attempt}/{MAX_RETRIES} "
                    f"after {wait}s"
                )

                time.sleep(wait)
                continue

            raise


    raise RuntimeError(
        "FreeProxyDB rate limit exceeded"
    )


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
        "connect_string",
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


def extract_data(payload: dict) -> list:

    container = payload.get(
        "data",
        []
    )

    if isinstance(container, dict):

        return container.get(
            "data",
            []
        )


    if isinstance(container, list):
        return container


    return []


def fetch_protocol(protocol: str) -> list[dict]:

    rows = []
    seen = set()


    for page in range(
        1,
        MAX_PAGES + 1
    ):

        try:

            payload = fetch_json(
                build_url(
                    protocol,
                    page
                )
            )


        except Exception as exc:

            print(
                f"WARN FreeProxyDB-{protocol} "
                f"page {page}: {exc}"
            )

            break


        data = extract_data(
            payload
        )


        if not data:
            break


        for item in data:

            uri = extract_uri(
                item
            )


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


        print(
            f"FreeProxyDB-{protocol} "
            f"page {page}: {len(data)}"
        )


        if len(data) < PAGE_SIZE:
            break


        time.sleep(
            PAGE_DELAY
        )


    print(
        f"OK source FreeProxyDB-{protocol}: "
        f"{len(rows)}"
    )


    return rows


def collect_freeproxydb() -> list[dict]:

    rows = []


    for index, protocol in enumerate(PROTOCOLS):

        rows.extend(
            fetch_protocol(
                protocol
            )
        )

        if index < len(PROTOCOLS) - 1:
            time.sleep(
                PROTOCOL_DELAY
            )


    print(
        f"OK source FreeProxyDB-api: "
        f"{len(rows)}"
    )


    return rows
