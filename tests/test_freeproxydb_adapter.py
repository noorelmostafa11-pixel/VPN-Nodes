#!/usr/bin/env python3
import json
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import freeproxydb_adapter as adapter


def node(number: int) -> dict:
    return {
        "connect_string": (
            f"vless://{number:08d}-1111-1111-1111-111111111111"
            f"@node{number}.example:443?security=tls"
        )
    }


originals = {
    "CACHE_FILE": adapter.CACHE_FILE,
    "PAGE_SIZE": adapter.PAGE_SIZE,
    "MAX_REQUESTS_PER_RUN": adapter.MAX_REQUESTS_PER_RUN,
    "PAGE_DELAY": adapter.PAGE_DELAY,
    "fetch_json": adapter.fetch_json,
}

try:
    with tempfile.TemporaryDirectory() as temporary:
        adapter.CACHE_FILE = Path(temporary) / "freeproxydb_cache.json"
        adapter.PAGE_SIZE = 2
        adapter.MAX_REQUESTS_PER_RUN = 2
        adapter.PAGE_DELAY = 0

        pages = {
            1: [node(1), node(2)],
            2: [node(3), node(4)],
            3: [node(5), node(6)],
        }

        def fetch_page(url: str) -> dict:
            page = int(url.split("page_index=", 1)[1].split("&", 1)[0])
            return {
                "data": {
                    "data": pages[page],
                    "total_count": 6,
                }
            }

        adapter.fetch_json = fetch_page

        first = adapter.collect_freeproxydb()
        assert len(first) == 4
        state = json.loads(adapter.CACHE_FILE.read_text(encoding="utf-8"))
        assert state["next_page"] == 3

        second = adapter.collect_freeproxydb()
        assert len(second) == 6
        state = json.loads(adapter.CACHE_FILE.read_text(encoding="utf-8"))
        assert state["next_page"] == 1

        def rate_limited(_url: str) -> dict:
            raise adapter.RateLimited("test quota")

        adapter.fetch_json = rate_limited
        third = adapter.collect_freeproxydb()
        assert len(third) == 6
        state = json.loads(adapter.CACHE_FILE.read_text(encoding="utf-8"))
        assert state["rate_limited"] is True
        assert state["next_page"] == 1
finally:
    for name, value in originals.items():
        setattr(adapter, name, value)


print("OK FreeProxyDB rolling pagination cache")

