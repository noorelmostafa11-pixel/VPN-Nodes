#!/usr/bin/env python3
"""PublicVPNList API adapter.

Converts PublicVPNList API records into catalog candidates.
"""
from __future__ import annotations

import json
import urllib.request

PROTOCOLS = {
    "vless": "https://publicvpnlist.com/api/v1/servers?protocol=vless&status=online&sort=last_checked&order=desc&per_page=200",
    "vmess": "https://publicvpnlist.com/api/v1/servers?protocol=vmess&status=online&sort=last_checked&order=desc&per_page=200",
    "trojan": "https://publicvpnlist.com/api/v1/servers?protocol=trojan&status=online&sort=last_checked&order=desc&per_page=200",
    "shadowsocks": "https://publicvpnlist.com/api/v1/servers?protocol=shadowsocks&status=online&sort=last_checked&order=desc&per_page=200",
}


def fetch_protocol(protocol: str) -> list[dict]:
    url = PROTOCOLS[protocol]
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "VPN-Nodes-Catalog/1.0"})
    with urllib.request.urlopen(req, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))

    rows = []
    for item in payload.get("data", []):
        rows.append({
            "name": f"PublicVPNList-{protocol}",
            "url": item.get("config_download_url") or item.get("server_page_url") or "",
            "protocol": protocol,
            "metadata": item,
        })
    return rows


def collect_publicvpnlist() -> list[dict]:
    rows = []
    for protocol in PROTOCOLS:
        try:
            rows.extend(fetch_protocol(protocol))
        except Exception:
            continue
    return rows
