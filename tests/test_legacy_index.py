#!/usr/bin/env python3
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

try:
    import requests  # noqa: F401
except ModuleNotFoundError:
    class Session:
        def __init__(self):
            self.headers = {}

    sys.modules["requests"] = SimpleNamespace(Session=Session)

import build_tcp_pool


class Countries:
    @staticmethod
    def get(alpha_2):
        return SimpleNamespace(name={"US": "United States", "DE": "Germany"}.get(alpha_2, alpha_2))


def resolve_rows(rows):
    for index, row in enumerate(rows):
        row["country"] = "US" if index == 0 else "DE"
        row["country_resolution"] = "test"
    return {"hostname": 0, "geoip_local": 2, "metadata_fallback": 0, "unknown": 0}


sys.modules["pycountry"] = SimpleNamespace(countries=Countries())
sys.modules["country_resolver"] = SimpleNamespace(resolve_rows=resolve_rows)

with TemporaryDirectory() as tmp:
    build_tcp_pool.OUT = Path(tmp) / "output"
    rows = [
        {"uri": "vless://a@one.example:443?security=tls", "host": "one.example", "port": 443, "protocol": "vless", "source": "a", "latency_ms": 10},
        {"uri": "trojan://b@two.example:443?security=tls", "host": "two.example", "port": 443, "protocol": "trojan", "source": "b", "latency_ms": 20},
    ]
    app = build_tcp_pool.publish_app_pool(rows, [], {"schema": 1, "sources": {}})
    meta = build_tcp_pool.OUT / "metadata"
    legacy = json.loads((meta / "index.json").read_text(encoding="utf-8"))
    assert legacy["schema"] == 9
    assert legacy["published_total"] == app["published_total"] == 2
    assert legacy["allowed_ports"] == [80, 443]
    assert legacy["generated_at"] == app["generated_at"]
    assert "health_policy" in legacy and "ranking_policy" in legacy
    assert (build_tcp_pool.OUT / "countries" / "US.txt").is_file()
    assert (build_tcp_pool.OUT / "country_shards" / "US" / "000.txt").is_file()
    assert (build_tcp_pool.OUT / "protocols" / "vless.txt").is_file()

print("OK Android-facing legacy and shard paths remain compatible")
