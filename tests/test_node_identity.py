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


# Cosmetic-only differences: same connection data, therefore one identity.
ws_a = (
    "vless://00000000-0000-0000-0000-000000000000@example.com:443?"
    "type=ws&security=tls&host=edge.example&path=/a&fp=chrome#source-one"
)
ws_a_reordered = (
    "vless://00000000-0000-0000-0000-000000000000@example.com:443?"
    "path=/a&fp=chrome&host=edge.example&security=tls&type=websocket#source-two"
)
assert identity.dedup_key(ws_a) == identity.dedup_key(ws_a_reordered)
# RAW-only header options have no effect on a WebSocket transport.
assert identity.dedup_key(ws_a) == identity.dedup_key(
    ws_a.replace("type=ws&", "type=ws&headerType=none&")
)

# Explicit VLESS encryption=none and its omitted default generate the same
# production outbound settings.
ws_a_implicit_encryption = ws_a.replace(
    "type=ws&security=tls&",
    "type=ws&security=tls&encryption=none&",
)
assert identity.dedup_key(ws_a) == identity.dedup_key(ws_a_implicit_encryption)

# tcp/raw are parser aliases that generate the same Xray stream network.
tcp_a = (
    "vless://aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa@one.example:443?"
    "type=tcp&security=tls&sni=one.example#tcp"
)
raw_a = tcp_a.replace("type=tcp", "type=raw").replace("#tcp", "#raw")
assert identity.dedup_key(tcp_a) == identity.dedup_key(raw_a)


# Every connection-affecting difference must stay distinct.
different_uuid = ws_a.replace(
    "00000000-0000-0000-0000-000000000000",
    "11111111-1111-1111-1111-111111111111",
)
assert identity.dedup_key(ws_a) != identity.dedup_key(different_uuid)

different_host = ws_a.replace("@example.com:443", "@other.example:443")
assert identity.dedup_key(ws_a) != identity.dedup_key(different_host)

different_port = ws_a.replace(":443?", ":8443?")
assert identity.dedup_key(ws_a) != identity.dedup_key(different_port)

different_path = ws_a.replace("path=/a", "path=/b")
assert identity.dedup_key(ws_a) != identity.dedup_key(different_path)
assert identity.dedup_key(ws_a) != identity.dedup_key(ws_a.replace("path=/a", "path=/a%20"))

different_transport_host = ws_a.replace("host=edge.example", "host=other.example")
assert identity.dedup_key(ws_a) != identity.dedup_key(different_transport_host)

different_fp = ws_a.replace("fp=chrome", "fp=firefox")
assert identity.dedup_key(ws_a) != identity.dedup_key(different_fp)

different_alpn = ws_a.replace("fp=chrome", "fp=chrome&alpn=h2")
assert identity.dedup_key(ws_a) != identity.dedup_key(different_alpn)

# Xray 26.9.9 removed allowInsecure, and the production Xray config does not
# emit it, so this source-only flag must not create a distinct connection identity.
different_insecure = ws_a.replace("fp=chrome", "fp=chrome&allowInsecure=1")
assert identity.dedup_key(ws_a) == identity.dedup_key(different_insecure)

different_sni = ws_a.replace("fp=chrome", "fp=chrome&sni=tls.example")
assert identity.dedup_key(ws_a) != identity.dedup_key(different_sni)


# REALITY-specific fields all affect the generated connection.
reality = (
    "vless://e3f0c894-0f76-4683-a751-6a93da8fd14d@206.206.78.36:443?"
    "type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&fp=chrome&"
    "pbk=UOLfRKeEoVxkp-APTF2OlvFkKSoiR2mWzUuhSWxcVmQ&sid=133a3f10a1581047&"
    "sni=www.cloudflare.com#one"
)
reality_reordered = (
    "vless://e3f0c894-0f76-4683-a751-6a93da8fd14d@206.206.78.36:443?"
    "sni=www.cloudflare.com&sid=133a3f10a1581047&pbk=UOLfRKeEoVxkp-APTF2OlvFkKSoiR2mWzUuhSWxcVmQ&"
    "fp=chrome&flow=xtls-rprx-vision&security=reality&type=raw#two"
)
assert identity.dedup_key(reality) == identity.dedup_key(reality_reordered)
# Xray's explicit RAW header type `none` passes the connection through just
# like an omitted rawSettings field, even when the share-link name differs.
reality_noop = reality_reordered.replace("type=raw#two", "type=tcp&headerType=none#three")
assert identity.dedup_key(reality) == identity.dedup_key(reality_noop)
assert identity.dedup_key(reality) == identity.dedup_key(
    reality_noop.replace("headerType=none", "headerType=None")
)
assert identity.dedup_key(reality) != identity.dedup_key(
    reality_noop.replace("headerType=none", "headerType=http")
)
assert identity.dedup_key(reality) != identity.dedup_key(reality.replace("fp=chrome", "fp=firefox"))
assert identity.dedup_key(reality) != identity.dedup_key(reality.replace("fp=chrome", "fp=random"))
assert identity.dedup_key(reality) != identity.dedup_key(reality.replace("fp=chrome", "fp="))
assert identity.dedup_key(reality) != identity.dedup_key(reality.replace("sid=133a3f10a1581047", "sid=223a3f10a1581047"))
assert identity.dedup_key(reality) != identity.dedup_key(reality.replace("flow=xtls-rprx-vision", "flow="))
assert identity.dedup_key(reality) != identity.dedup_key(reality.replace(
    "UOLfRKeEoVxkp-APTF2OlvFkKSoiR2mWzUuhSWxcVmQ",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
))


# gRPC service/authority differences must not collapse.
grpc_a = (
    "vless://22222222-2222-2222-2222-222222222222@grpc.example:443?"
    "type=grpc&security=tls&serviceName=alpha&authority=edge.example#one"
)
assert identity.dedup_key(grpc_a) != identity.dedup_key(grpc_a.replace("serviceName=alpha", "serviceName=beta"))
assert identity.dedup_key(grpc_a) != identity.dedup_key(grpc_a.replace("authority=edge.example", "authority=other.example"))


# If production parsing cannot prove equivalence, use exact-raw fallback only.
malformed_a = "vless://broken@[1.2.3.4]:443?type=ws#one"
malformed_b = "vless://broken@[1.2.3.4]:443?type=ws#two"
key_a, proven_a = identity.dedup_key_with_status(malformed_a)
key_b, proven_b = identity.dedup_key_with_status(malformed_b)
assert proven_a is False and proven_b is False
assert key_a != key_b
assert identity.dedup_key(malformed_a) == identity.dedup_key(malformed_a)

print("connection-equivalent node identity tests: PASS")
