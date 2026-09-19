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

base = (
    "vless://e3f0c894-0f76-4683-a751-6a93da8fd14d@206.206.78.36:443?"
    "type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&fp=chrome&"
    "pbk=UOLfRKeEoVxkp-APTF2OlvFkKSoiR2mWzUuhSWxcVmQ&sid=133a3f10a1581047&"
    "sni=www.cloudflare.com#SG"
)

# The remark is display-only and must not create a second node.
variant_remark = base.replace("#SG", "#source-two")
variant_empty_remark = base.replace("#SG", "#")
variant_no_remark = base.split("#", 1)[0]
for variant in (variant_remark, variant_empty_remark, variant_no_remark):
    assert identity.dedup_key(base) == identity.dedup_key(variant)

# Query order is spelling, not connection data.
variant_order = base.replace(
    "type=tcp&security=reality&encryption=none",
    "encryption=none&security=reality&type=tcp",
)
assert identity.dedup_key(base) == identity.dedup_key(variant_order)

# Query-key case and one layer of percent-encoding are also spelling only.
trojan_a = (
    "trojan://humanity@212.183.88.136:443?"
    "security=tls&sni=www.calmlunch.com&type=ws&Host=www.calmlunch.com&"
    "path=%2Fassignment#source-a"
)
trojan_b = (
    "trojan://humanity@212.183.88.136:443?"
    "path=/assignment&host=www.calmlunch.com&type=ws&SNI=www.calmlunch.com&"
    "SECURITY=tls#source-b"
)
assert identity.dedup_key(trojan_a) == identity.dedup_key(trojan_b)

# Any real connection-data difference must remain distinct.
variant_fp = base.replace("fp=chrome", "fp=firefox")
variant_raw = base.replace("type=tcp", "type=raw")
variant_sni = base.replace("www.cloudflare.com", "www.microsoft.com")
variant_port = base.replace("@206.206.78.36:443", "@206.206.78.36:8443")
variant_uuid = base.replace(
    "e3f0c894-0f76-4683-a751-6a93da8fd14d",
    "adc11f30-e4cb-4985-bf5e-f9ded69c019f",
)
variant_protocol = base.replace("vless://", "trojan://")
variant_added_parameter = base.replace("#SG", "&allowInsecure=0#SG")

for variant in (
    variant_fp,
    variant_raw,
    variant_sni,
    variant_port,
    variant_uuid,
    variant_protocol,
    variant_added_parameter,
):
    assert identity.dedup_key(base) != identity.dedup_key(variant)

print("Conservative connection identity tests: PASS")
