from __future__ import annotations

import ipaddress

# Cloudflare's published proxied IPv4 ranges. Keep these static and refresh them
# only through an explicit code/database update so the catalog remains offline.
# Source: https://www.cloudflare.com/ips-v4
CLOUDFLARE_IPV4_RANGES = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
)

CLOUDFLARE_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in CLOUDFLARE_IPV4_RANGES)
CLOUDFLARE_HOST_SUFFIXES = (
    ".workers.dev",
    ".pages.dev",
    ".cloudflareworkers.com",
    ".cloudflarestorage.com",
    ".r2.dev",
)


def is_cloudflare_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return ip.version == 4 and any(ip in network for network in CLOUDFLARE_NETWORKS)


def is_cloudflare_host(value: str | None) -> bool:
    if not value:
        return False
    host = value.strip().lower().rstrip(".")
    return any(host.endswith(suffix) for suffix in CLOUDFLARE_HOST_SUFFIXES)


def is_confirmed_cloudflare(host: str | None, resolved_ip: str | None) -> bool:
    return is_cloudflare_host(host) or is_cloudflare_ip(resolved_ip)
