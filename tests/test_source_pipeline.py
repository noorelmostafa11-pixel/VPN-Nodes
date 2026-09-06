#!/usr/bin/env python3
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

try:
    import requests  # noqa: F401
except ModuleNotFoundError:
    class Session:
        def __init__(self):
            self.headers = {}

        def get(self, *args, **kwargs):
            raise AssertionError("unexpected network request in unit test")

    sys.modules["requests"] = SimpleNamespace(Session=Session)

import build_sources_candidates as builder
import update_catalog as catalog


VLESS_A = "vless://11111111-1111-1111-1111-111111111111@a.example:443?security=tls&type=ws#a"
VLESS_B = "vless://22222222-2222-2222-2222-222222222222@b.example:443?security=tls&type=ws#b"

rows = catalog.parse_lines(VLESS_A + VLESS_B, "joined")
assert [row["host"] for row in rows] == ["a.example", "b.example"]

# A single malformed bracketed endpoint previously aborted the whole source.
malformed = "vless://33333333-3333-3333-3333-333333333333@[1.2.3.4]:443?security=tls"
rows = catalog.parse_lines(malformed + "\n" + VLESS_A, "mixed-quality")
assert len(rows) == 1 and rows[0]["host"] == "a.example"

invalid_ss = "ss://not-a-cipher-password@ss.example:443#bad"
valid_ss = "ss://aes-256-gcm:password@ss.example:443#good"
assert catalog.parse_lines(invalid_ss, "ss") == []
assert len(catalog.parse_lines(valid_ss, "ss")) == 1

special_rows: list[dict] = []
health: list[dict] = []
builder.collect_special(
    "adapter",
    lambda: [{"url": VLESS_A}, {"url": VLESS_B}],
    special_rows,
    health,
    normalize=True,
)
assert len(special_rows) == 2
assert all(row["source"] == "adapter" for row in special_rows)
assert health[0]["raw_nodes"] == 2 and health[0]["nodes"] == 2

nested_rows: list[dict] = []
nested_health: list[dict] = []
builder.collect_special(
    "nested-adapter",
    lambda: [{"url": "https://example.invalid/server/1", "metadata": {"links": [VLESS_A]}}],
    nested_rows,
    nested_health,
    normalize=True,
)
assert len(nested_rows) == 1 and nested_health[0]["ok"] is True

assert "Authorization" not in catalog.session.headers
seen: list[tuple[str, dict]] = []


class Response:
    def raise_for_status(self):
        return None

    def json(self):
        return []


original_get = catalog.session.get
original_token = catalog.GITHUB_TOKEN
try:
    catalog.GITHUB_TOKEN = "test-token"

    def fake_get(url, **kwargs):
        seen.append((url, kwargs.get("headers", {})))
        return Response()

    catalog.session.get = fake_get
    catalog.github_api_json("https://api.github.com/repos/example/repo/contents")
    catalog.github_api_json("https://example.com/api")
finally:
    catalog.session.get = original_get
    catalog.GITHUB_TOKEN = original_token

assert seen[0][1].get("Authorization") == "Bearer test-token"
assert "Authorization" not in seen[1][1]

print("OK source pipeline security and normalization")
