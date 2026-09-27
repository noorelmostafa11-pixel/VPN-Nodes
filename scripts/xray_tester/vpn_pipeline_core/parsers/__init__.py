from .shadowsocks import parse_ss
from .trojan import parse_trojan
from .vless import parse_vless
from .vmess import parse_vmess

PARSERS = {
    "vless": parse_vless,
    "vmess": parse_vmess,
    "trojan": parse_trojan,
    "ss": parse_ss,
}

__all__ = ["PARSERS", "parse_vless", "parse_vmess", "parse_trojan", "parse_ss"]
