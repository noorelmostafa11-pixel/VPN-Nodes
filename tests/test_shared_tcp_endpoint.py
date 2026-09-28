import asyncio
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, path
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


merge = load_module(
    "merge_and_build_tcp_pool",
    ROOT / "scripts" / "merge_and_build_tcp_pool.py",
)

probed = []


async def fake_run_tcp_checks(rows):
    probed.extend(rows)
    result = []
    for row in rows:
        if str(row["host"]).lower() == "alive.example" and int(row["port"]) == 443:
            result.append({
                **row,
                "latency_ms": 12.3,
                "liveness": "ALIVE",
                "country": "UNKNOWN",
                "country_resolution": "pending",
            })
    return result


merge.common.run_tcp_checks = fake_run_tcp_checks

rows = [
    {
        "protocol": "vless",
        "uri": "vless://one",
        "host": "ALIVE.example",
        "port": 443,
    },
    {
        "protocol": "trojan",
        "uri": "trojan://two",
        "host": "alive.example",
        "port": "443",
    },
    {
        "protocol": "vmess",
        "uri": "vmess://three",
        "host": "dead.example",
        "port": 80,
    },
    {
        "protocol": "ss",
        "uri": "ss://four",
        "host": "",
        "port": 443,
    },
]

checked, unique_endpoints, reachable_endpoints = asyncio.run(
    merge.run_tcp_checks_by_endpoint(rows)
)

assert unique_endpoints == 2
assert reachable_endpoints == 1
assert len(probed) == 2
assert {
    (str(row["host"]).lower(), int(row["port"]))
    for row in probed
} == {
    ("alive.example", 443),
    ("dead.example", 80),
}

assert [row["uri"] for row in checked] == [
    "vless://one",
    "trojan://two",
]
assert all(row["latency_ms"] == 12.3 for row in checked)
assert all(row["liveness"] == "ALIVE" for row in checked)

print("shared TCP endpoint tests: PASS")
