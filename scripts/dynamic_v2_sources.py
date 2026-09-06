#!/usr/bin/env python3
from __future__ import annotations

import requests

from clashxw_daily_adapter import collect_clashxw_daily

SOURCES = {
    "sshs8": "https://sshs8.com/free-vless-server-v2ray/",
    "racevpn": "https://www.racevpn.com/free-v2ray-server",
    "v2rayse": "https://v2.v2rayse.com/en/free-node/",
}


def collect_urls():
    return SOURCES


def fetch_pages():
    out = {}
    for name, url in SOURCES.items():
        try:
            r = requests.get(url, timeout=10)
            r.raise_for_status()
            out[name] = r.text
        except Exception:
            out[name] = ""

    out["clashxw_daily"] = collect_clashxw_daily()
    return out
