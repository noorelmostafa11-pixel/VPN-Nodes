#!/usr/bin/env python3
"""Direct Telegram source collector layered in front of the existing catalog pipeline.

Source collection is extended here, while country selection gets one explicit
metadata pass before the normal GeoLite2 fallback. This keeps node labels such as
flags and bracketed ISO codes authoritative without trusting loose text or source
filename hints as if they were exit-country metadata.
"""
from __future__ import annotations

import html
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import build_tcp_pool as pool
import update_catalog as catalog

ROOT = Path(__file__).resolve().parents[1]
TELEGRAM_CATALOG = ROOT / "sources" / "telegram_channels.json"
TELEGRAM_TIMEOUT = (3.0, 12.0)
DEFAULT_MAX_PAGES = 4
DEFAULT_MAX_URIS = 2000
PAGE_DELAY = 0.10
CHANNEL_WORKERS = 16

URI_RE = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s\"'<>`]+", re.IGNORECASE)

# Explicit node metadata only. We deliberately do not use loose substring matching
# such as "us" inside arbitrary text because that caused false country assignments.
EXPLICIT_ALIASES = {
    "uk": "GB", "england": "GB", "greatbritain": "GB", "unitedkingdom": "GB",
    "uae": "AE", "emirates": "AE", "unitedarabemirates": "AE", "usa": "US",
    "america": "US", "unitedstates": "US", "southkorea": "KR", "korea": "KR",
    "northkorea": "KP", "russia": "RU", "iran": "IR", "taiwan": "TW",
    "japan": "JP", "singapore": "SG", "seychelles": "SC", "germany": "DE",
    "france": "FR", "canada": "CA", "australia": "AU", "austria": "AT",
    "netherlands": "NL", "poland": "PL", "slovenia": "SI", "turkey": "TR",
    "turkiye": "TR", "hongkong": "HK", "finland": "FI", "sweden": "SE",
    "denmark": "DK", "bulgaria": "BG", "azerbaijan": "AZ", "china": "CN",
    "estonia": "EE", "czechrepublic": "CZ", "czechia": "CZ", "southafrica": "ZA",
    "newzealand": "NZ", "saudiarabia": "SA",
}

FLAG_RE = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")
BRACKET_CODE_RE = re.compile(r"(?:^|[\s\[\(\{/_|:#\-])([A-Za-z]{2})(?=$|[\s\]\)\}/_|:#\-\d])")
WORD_RE = re.compile(r"[A-Za-z]+")
TECHNICAL_WORDS = {
    "ws", "tls", "tcp", "raw", "grpc", "reality", "http", "https", "udp", "auto",
    "none", "vless", "vmess", "trojan", "shadowsocks", "server", "node", "vpn",
    "config", "free", "proxy", "speed", "fast", "cdn", "cloudflare", "worker",
}

COUNTRY_WORDS = {
    "uk": "GB", "england": "GB", "greatbritain": "GB", "unitedkingdom": "GB",
    "uae": "AE", "emirates": "AE", "unitedarabemirates": "AE", "usa": "US",
    "america": "US", "unitedstates": "US", "southkorea": "KR", "korea": "KR",
    "northkorea": "KP", "russia": "RU", "iran": "IR", "taiwan": "TW", "japan": "JP",
    "singapore": "SG", "seychelles": "SC", "germany": "DE", "france": "FR",
    "canada": "CA", "australia": "AU", "austria": "AT", "netherlands": "NL",
    "poland": "PL", "slovenia": "SI", "turkey": "TR", "turkiye": "TR",
    "hongkong": "HK", "finland": "FI", "sweden": "SE", "denmark": "DK",
    "bulgaria": "BG", "azerbaijan": "AZ", "china": "CN", "estonia": "EE",
    "czechrepublic": "CZ", "czechia": "CZ", "southafrica": "ZA", "newzealand": "NZ",
    "saudiarabia": "SA",
}


def _flag_to_country(text: str) -> str | None:
    match = FLAG_RE.search(text or "")
    if not match:
        return None
    letters = match.group(0)
    return "".join(chr(ord(char) - 0x1F1E6 + ord("A")) for char in letters).upper()


def _explicit_country_from_remark(text: str) -> str | None:
    if not text:
        return None

    flag = _flag_to_country(text)
    if flag and flag in catalog.ISO_CODES:
        return flag

    raw = text.replace("%5B", "[").replace("%5D", "]")

    # Strong forms such as [DE], (DE), DE-01, DE_01, #DE.
    for match in BRACKET_CODE_RE.finditer(raw):
        code = match.group(1).upper()
        if code in catalog.ISO_CODES and code.lower() not in TECHNICAL_WORDS:
            return code

    # Full country names / unambiguous aliases as whole lexical components.
    words = re.findall(r"[A-Za-z]+", raw.lower())
    compact_words = {re.sub(r"[^a-z0-9]", "", word) for word in words}
    for token, code in COUNTRY_WORDS.items():
        if token in compact_words:
            return code

    # Joined forms such as Germany-01 or United_States_1.
    compact = re.sub(r"[^a-z0-9]+", "", raw.lower())
    for token, code in EXPLICIT_ALIASES.items():
        if re.search(rf"(?:^|[^a-z0-9]){re.escape(token)}(?:[^a-z0-9]|$)", raw.lower()):
            return code
        if compact.startswith(token) or compact.endswith(token):
            return code

    return None


def _apply_metadata_first(rows: list[dict]) -> list[dict]:
    """Make explicit node-label metadata authoritative, then leave all other rows UNKNOWN.

    The normal parser historically assigns country from loose remark/source text. That
    can accidentally turn a Cloudflare/Anycast endpoint into US before GeoLite2 runs.
    Here we preserve only explicit node metadata; everything else is deliberately reset
    to UNKNOWN so build_tcp_pool can use the local GeoLite2 fallback.
    """
    metadata_count = 0
    reset_count = 0
    for row in rows:
        text = " ".join(
            str(row.get(key) or "")
            for key in ("remark", "name", "ps", "remarks", "title")
        ).strip()
        explicit = _explicit_country_from_remark(text)
        if explicit:
            row["country"] = explicit
            row["country_resolution"] = "metadata_explicit"
            row["country_resolution_confidence"] = "high"
            metadata_count += 1
        else:
            if row.get("country") != "UNKNOWN":
                reset_count += 1
            row["country"] = "UNKNOWN"
            row["country_resolution"] = "pending_geoip"
            row["country_resolution_confidence"] = "none"
    if rows:
        print(f"INFO metadata_first explicit={metadata_count} reset_for_geoip={reset_count}")
    return rows


# Patch the shared parser used by every source, including snapshots. This runs before
# build_tcp_pool's TCP screening and before country_resolver's local GeoLite2 fallback.
_original_parse_lines = catalog.parse_lines


def parse_lines_metadata_first(text, source_name, source_hint_country=None, source_priority=0):
    rows = _original_parse_lines(text, source_name, source_hint_country, source_priority)
    return _apply_metadata_first(rows)


catalog.parse_lines = parse_lines_metadata_first


def _telegram_page(channel: str, before: int | None = None) -> str:
    url = f"https://t.me/s/{channel}"
    if before:
        url += f"?before={before}"
    response = catalog.session.get(url, timeout=TELEGRAM_TIMEOUT)
    response.raise_for_status()
    return response.text


def _extract_before(channel: str, page: str, current_before: int | None) -> int | None:
    candidates: set[int] = set()
    for match in re.finditer(r"[?&]before=(\d+)", page, re.IGNORECASE):
        value = int(match.group(1))
        if value > 0:
            candidates.add(value)
    pattern = re.compile(
        rf"(?:https?://t\.me/|/)(?:s/)?{re.escape(channel)}/(\d+)(?:[\"'/?#]|$)",
        re.IGNORECASE,
    )
    for match in pattern.finditer(page):
        value = int(match.group(1))
        if value > 0:
            candidates.add(value)
    if current_before is not None:
        candidates = {value for value in candidates if value < current_before}
    return min(candidates) if candidates else None


def collect_telegram(item: dict) -> list[dict]:
    channel = item["channel"].lstrip("@").strip()
    max_pages = max(1, min(int(item.get("max_pages", DEFAULT_MAX_PAGES)), 25))
    max_uris = max(100, min(int(item.get("max_uris", DEFAULT_MAX_URIS)), 20000))
    priority = int(item.get("priority", 0))
    rows: list[dict] = []
    seen_uris: set[str] = set()
    before: int | None = None
    pages_ok = 0

    for page_number in range(max_pages):
        try:
            page = _telegram_page(channel, before)
        except Exception as exc:
            if page_number == 0:
                raise
            print(f"WARN telegram @{channel} page={page_number + 1}: {exc}")
            break

        pages_ok += 1
        decoded = html.unescape(page)
        page_uris = URI_RE.findall(decoded)
        if page_uris:
            parsed = catalog.parse_lines(
                "\n".join(page_uris),
                f"telegram:@{channel}",
                None,
                priority,
            )
            for row in parsed:
                key = row["uri"]
                if key in seen_uris:
                    continue
                seen_uris.add(key)
                rows.append(row)
                if len(rows) >= max_uris:
                    break

        if len(rows) >= max_uris:
            break
        next_before = _extract_before(channel, page, before)
        if next_before is None:
            break
        before = next_before
        if page_number + 1 < max_pages:
            time.sleep(PAGE_DELAY)

    print(f"INFO telegram @{channel}: pages={pages_ok} accepted={len(rows)}")
    return rows


def collect_telegram_catalog(item: dict) -> list[dict]:
    catalog_data = json.loads(TELEGRAM_CATALOG.read_text(encoding="utf-8"))
    channels = []
    seen = set()
    for raw in catalog_data.get("channels", []):
        channel = str(raw).lstrip("@").strip()
        if channel and channel.lower() not in seen:
            seen.add(channel.lower())
            channels.append(channel)

    max_pages = max(1, min(int(item.get("max_pages", DEFAULT_MAX_PAGES)), 25))
    max_uris = max(100, min(int(item.get("max_uris", DEFAULT_MAX_URIS)), 20000))
    priority = int(item.get("priority", 270))
    print(f"INFO telegram_catalog channels={len(channels)} workers={CHANNEL_WORKERS} pages={max_pages}")

    def run(channel: str):
        return collect_telegram({
            "channel": channel,
            "max_pages": max_pages,
            "max_uris": max_uris,
            "priority": priority,
        })

    rows: list[dict] = []
    with ThreadPoolExecutor(max_workers=CHANNEL_WORKERS) as executor:
        futures = {executor.submit(run, channel): channel for channel in channels}
        for future in as_completed(futures):
            channel = futures[future]
            try:
                rows.extend(future.result())
            except Exception as exc:
                print(f"WARN telegram @{channel}: {exc}")
    print(f"INFO telegram_catalog accepted={len(rows)}")
    return rows


_original_collect_source = catalog.collect_source


def collect_source(item: dict) -> list[dict]:
    if item.get("format") == "telegram_html":
        return collect_telegram(item)
    if item.get("format") == "telegram_catalog":
        return collect_telegram_catalog(item)
    return _original_collect_source(item)


catalog.collect_source = collect_source


if __name__ == "__main__":
    pool.main()
