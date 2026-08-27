import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "collector",
    Path(__file__).parents[1] / "scripts/update_catalog.py",
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

cases = [
    ("#Germany-01", "DE"),
    ("#Singapore-02", "SG"),
    ("Canada.txt", "CA"),
    ("United States", "US"),
    ("node-DE-01", "DE"),
]

for value, expected in cases:
    got = mod.country_from_text(value)
    assert got == expected, (value, got, expected)

# Never infer a country from arbitrary two-letter text or transport tokens.
assert mod.country_from_text("ws tls tcp") is None
assert mod.country_from_text("some-host.us.example") is None
assert mod.country_from_text("ZZ") is None

# Explicit country metadata still works.
assert mod.country_from_text("DE") == "DE"
assert mod.country_from_text("Canada.txt", allow_iso=False) == "CA"

assert mod.protocol_from_uri("vless://x@y:443") == "vless"
assert mod.protocol_from_uri("ss://x@y:443") == "shadowsocks"
assert (
    mod.endpoint_from_uri(
        "vless://00000000-0000-0000-0000-000000000000@example.com:443?type=ws#Germany"
    )[1]
    == 443
)

assert mod.source_hint_from_url("https://example.invalid/CA.txt") == "CA"
# WS is a valid ISO-3166 code (Samoa) when it appears as an explicit filename.
assert mod.source_hint_from_url("https://example.invalid/ws.txt") == "WS"

print("country/protocol/source tests: PASS")
