from __future__ import annotations

import base64
import csv
import io
import json
import os
import re
from pathlib import Path
from urllib.parse import unquote, urlparse, parse_qs

import requests

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
MAX_SOURCE_BYTES = 20_000_000
CONNECT_TIMEOUT = 1.5
READ_TIMEOUT = 8.0
ALLOWED_PORTS = {80, 443}
PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks"}

session = requests.Session()
session.headers.update({"User-Agent": "Ahmed-VPN-Nodes/2.0 (+public-aggregator)"})
if os.getenv("GITHUB_TOKEN"):
    session.headers.update({"Authorization": f"Bearer {os.getenv('GITHUB_TOKEN')}"})

VMESS_DIAGNOSTICS = {"seen": 0, "decode_ok": 0, "decode_failed": 0}


def fetch(url: str) -> bytes:
    response = session.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), stream=True)
    response.raise_for_status()
    data = bytearray()
    for chunk in response.iter_content(8192):
        data.extend(chunk)
        if len(data) > MAX_SOURCE_BYTES:
            break
    return bytes(data[:MAX_SOURCE_BYTES])


def maybe_decode(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    compact = re.sub(r"\s+", "", text)
    if len(compact) > 100 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        try:
            decoded = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=False)
            candidate = decoded.decode("utf-8", errors="replace")
            if any(x in candidate for x in ("vless://", "vmess://", "trojan://", "ss://")):
                return candidate
        except Exception:
            pass
    return text


def protocol_from_uri(uri: str) -> str | None:
    scheme = uri.split(":", 1)[0].lower()
    return "shadowsocks" if scheme == "ss" else scheme if scheme in PROTOCOLS else None


def _decode_vmess_payload(uri: str):
    payload = unquote(uri.split("://", 1)[1].split("#", 1)[0].strip())
    if not payload:
        return None
    padded = payload + "=" * (-len(payload) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=False)
        obj = json.loads(decoded.decode("utf-8-sig", errors="strict"))
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    host = str(obj.get("add") or obj.get("address") or "").strip()
    try:
        port = int(obj.get("port"))
    except (TypeError, ValueError):
        return None
    if not host or not port:
        return None
    remark = str(obj.get("ps") or obj.get("remark") or "").strip()
    query = {}
    for src, dst in (("id", "uuid"), ("aid", "alterId"), ("net", "type"), ("host", "host"), ("path", "path"), ("tls", "security"), ("sni", "sni"), ("scy", "encryption")):
        if obj.get(src) not in (None, ""):
            query[dst] = [str(obj[src])]
    return host, port, remark, query


def endpoint_from_uri(uri: str):
    scheme = uri.split(":", 1)[0].lower()
    try:
        if scheme == "vmess":
            VMESS_DIAGNOSTICS["seen"] += 1
            decoded = _decode_vmess_payload(uri)
            if decoded:
                VMESS_DIAGNOSTICS["decode_ok"] += 1
                return decoded
            VMESS_DIAGNOSTICS["decode_failed"] += 1
        parsed = urlparse(uri)
        return parsed.hostname, parsed.port, unquote(parsed.fragment or ""), parse_qs(parsed.query)
    except Exception:
        return None, None, "", {}


def dedup_key(uri: str) -> str:
    host, port, _, query = endpoint_from_uri(uri)
    scheme = protocol_from_uri(uri) or ""
    if not host or not port:
        return uri
    identity = [scheme, host.lower(), str(port)]
    for key in ("uuid", "sid", "sni", "serverName", "path", "type", "security", "encryption", "method"):
        value = query.get(key, [""])[0]
        if value:
            identity.append(f"{key}={value}")
    return "|".join(identity)


def parse_lines(text: str, source_name: str, source_hint_country: str | None = None):
    rows = []
    text = maybe_decode(text.encode("utf-8", errors="ignore"))
    for line in text.splitlines():
        line = line.strip().strip('"')
        if not line or line.startswith(("#", "//", "proxies:", "proxy-groups:")):
            continue
        match = re.search(r'''(?:^|['"\s])((?:vless|vmess|trojan|ss)://[^'"\s,]+)''', line, re.I)
        uri = match.group(1) if match else (line if re.match(r"^(?:vless|vmess|trojan|ss)://", line, re.I) else None)
        if not uri:
            continue
        protocol = protocol_from_uri(uri)
        if not protocol:
            continue
        host, port, remark, _ = endpoint_from_uri(uri)
        if not host or port not in ALLOWED_PORTS:
            continue
        rows.append({"uri": uri, "protocol": protocol, "host": host, "port": port, "remark": remark, "country": "UNKNOWN", "source": source_name})
    return rows


def parse_vpngate_csv(data: bytes, source_name: str) -> list[dict]:
    text = data.decode("utf-8-sig", errors="replace")
    lines = [line for line in text.splitlines() if line.strip()]
    header_index = next((i for i, line in enumerate(lines) if line.startswith("#HostName,")), None)
    if header_index is None:
        raise ValueError("VPN Gate CSV header not found")
    reader = csv.DictReader(io.StringIO("\n".join(lines[header_index:])))
    rows: list[dict] = []
    for row in reader:
        cfg_b64 = str(row.get("OpenVPN_ConfigData_Base64") or "").strip()
        if not cfg_b64:
            continue
        try:
            config = base64.b64decode(cfg_b64 + "=" * (-len(cfg_b64) % 4)).decode("utf-8", errors="replace")
        except Exception:
            continue
        remotes = re.findall(r"^\s*remote\s+(\S+)\s+(\d+)\b", config, flags=re.MULTILINE)
        allowed = [(host, int(port)) for host, port in remotes if int(port) in ALLOWED_PORTS]
        if not allowed:
            continue
        host, port = allowed[0]
        rows.append({
            "uri": f"openvpn://{host}:{port}#{source_name}",
            "protocol": "openvpn",
            "host": host,
            "port": port,
            "server": host,
            "country": str(row.get("CountryShort") or "UNKNOWN").strip().upper() or "UNKNOWN",
            "country_name": str(row.get("CountryLong") or "").strip(),
            "source": source_name,
            "score": row.get("Score"),
            "ping": row.get("Ping"),
            "speed": row.get("Speed"),
            "config_b64": cfg_b64,
        })
    meta = OUT / "metadata"
    meta.mkdir(parents=True, exist_ok=True)
    (meta / "openvpn_candidates.json").write_text(json.dumps({"generated_by": source_name, "nodes": rows}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"INFO {source_name}: OpenVPN candidates={len(rows)}")
    return rows


def github_api_json(url: str):
    response = session.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
    response.raise_for_status()
    return response.json()


def github_index(url: str):
    payload = github_api_json(url)
    return payload if isinstance(payload, list) else []


def github_tree_entries(url: str):
    payload = github_api_json(url)
    return [x for x in payload.get("tree", []) if x.get("type") == "blob"] if isinstance(payload, dict) else []


def collect_github_api_source(item):
    rows = []
    for entry in github_index(item["url"]):
        if entry.get("type") != "file" or not entry.get("download_url"):
            continue
        try:
            rows.extend(parse_lines(fetch(entry["download_url"]).decode("utf-8", errors="replace"), f"{item['name']}:{entry.get('name','')}"))
        except Exception as exc:
            print(f"WARN {item['name']}/{entry.get('name','')}: {exc}")
    return rows


def collect_github_tree_source(item):
    rows = []
    for entry in github_tree_entries(item["url"]):
        path = entry.get("path", "")
        if item.get("path_regex") and not re.search(item["path_regex"], path, re.I):
            continue
        raw = f"https://raw.githubusercontent.com/{item['owner']}/{item['repo']}/{item.get('ref','main')}/{path}"
        try:
            rows.extend(parse_lines(fetch(raw).decode("utf-8", errors="replace"), f"{item['name']}:{path}"))
        except Exception as exc:
            print(f"WARN {item['name']}/{path}: {exc}")
    return rows


def collect_source(item):
    fmt = item.get("format")
    if fmt == "github_api":
        return collect_github_api_source(item)
    if fmt == "github_tree":
        return collect_github_tree_source(item)
    if fmt == "vpngate_csv":
        return parse_vpngate_csv(fetch(item["url"]), item["name"])
    if item.get("kind") == "country_template":
        return []
    return parse_lines(fetch(item["url"]).decode("utf-8", errors="replace"), item["name"])


def load_previous_snapshot():
    return []
