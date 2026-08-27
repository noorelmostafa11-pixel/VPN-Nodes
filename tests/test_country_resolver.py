import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("collector", Path(__file__).parents[1]/"scripts/update_catalog.py")
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

cases = [
    ("#Germany-01", "DE"),
    ("#Singapore-02", "SG"),
    ("Canada.txt", "CA"),
    ("United States", "US"),
]
for value, expected in cases:
    got = mod.country_from_text(value)
    assert got == expected, (value, got, expected)

assert mod.protocol_from_uri("vless://x@y:443") == "vless"
assert mod.protocol_from_uri("ss://x@y:443") == "shadowsocks"
assert mod.endpoint_from_uri("vless://00000000-0000-0000-0000-000000000000@example.com:443?type=ws#Germany")[1] == 443
print("country/protocol tests: PASS")
