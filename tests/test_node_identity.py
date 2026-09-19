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

assert identity.dedup_key(base) == identity.dedup_key(base)

variant_fp = base.replace("fp=chrome", "fp=firefox")
variant_remark = base.replace("#SG", "#source-two")
variant_order = base.replace(
    "type=tcp&security=reality",
    "security=reality&type=tcp",
)
variant_raw = base.replace("type=tcp", "type=raw")

for variant in (variant_fp, variant_remark, variant_order, variant_raw):
    assert identity.dedup_key(base) != identity.dedup_key(variant)

print("exact URI node identity tests: PASS")
