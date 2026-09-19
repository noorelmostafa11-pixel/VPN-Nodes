import importlib.util
from pathlib import Path

ROOT = Path(__file__).parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, path
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


identity = load_module("node_identity", ROOT / "scripts/node_identity.py")

# Real-world duplicate seen in SG.txt: same VLESS/REALITY account and backend,
# represented by three sources with cosmetic/default differences.
base = (
    "vless://e3f0c894-0f76-4683-a751-6a93da8fd14d@206.206.78.36:443?"
    "type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&fp=chrome&"
    "pbk=UOLfRKeEoVxkp-APTF2OlvFkKSoiR2mWzUuhSWxcVmQ&sid=133a3f10a1581047&"
    "sni=www.cloudflare.com#SG"
)
variant_fp = (
    "vless://e3f0c894-0f76-4683-a751-6a93da8fd14d@206.206.78.36:443?"
    "flow=xtls-rprx-vision&fp=random&pbk=UOLfRKeEoVxkp-APTF2OlvFkKSoiR2mWzUuhSWxcVmQ&"
    "security=reality&sid=133a3f10a1581047&sni=www.cloudflare.com&type=tcp#source-two"
)
variant_raw = (
    "vless://e3f0c894-0f76-4683-a751-6a93da8fd14d@206.206.78.36:443?"
    "flow=xtls-rprx-vision&fp=firefox&pbk=UOLfRKeEoVxkp-APTF2OlvFkKSoiR2mWzUuhSWxcVmQ&"
    "security=reality&sid=133a3f10a1581047&sni=www.cloudflare.com&type=raw#source-three"
)

assert identity.dedup_key(base) == identity.dedup_key(variant_fp)
assert identity.dedup_key(base) == identity.dedup_key(variant_raw)

# Different credentials must NOT be collapsed just because IP/port are equal.
different_uuid = base.replace(
    "e3f0c894-0f76-4683-a751-6a93da8fd14d",
    "11111111-1111-1111-1111-111111111111",
)
assert identity.dedup_key(base) != identity.dedup_key(different_uuid)

# Different REALITY/TLS routing must remain distinct.
different_sni = base.replace("www.cloudflare.com", "www.microsoft.com")
assert identity.dedup_key(base) != identity.dedup_key(different_sni)

# WS path selects a backend and must remain significant.
ws_a = "vless://00000000-0000-0000-0000-000000000000@example.com:443?type=ws&security=tls&host=edge.example&path=/a#one"
ws_b = "vless://00000000-0000-0000-0000-000000000000@example.com:443?security=tls&type=websocket&host=edge.example&path=/b#two"
assert identity.dedup_key(ws_a) != identity.dedup_key(ws_b)

# Parameter order and remarks are cosmetic.
ws_a_reordered = "vless://00000000-0000-0000-0000-000000000000@example.com:443?path=/a&host=edge.example&security=tls&type=websocket#another-source"
assert identity.dedup_key(ws_a) == identity.dedup_key(ws_a_reordered)

print("semantic node identity tests: PASS")
