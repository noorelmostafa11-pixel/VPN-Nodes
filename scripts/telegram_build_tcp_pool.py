#!/usr/bin/env python3
"""Collect special web/Telegram sources, then hand every node to common stages."""
from __future__ import annotations

import html
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import build_tcp_pool as pool
import update_catalog as catalog
import v2nodes_adapter

ROOT = Path(__file__).resolve().parents[1]
TELEGRAM_CATALOG = ROOT / "sources" / "telegram_channels.json"
TELEGRAM_TIMEOUT = (3.0, 12.0)
DEFAULT_MAX_PAGES = 4
DEFAULT_MAX_URIS = 2000
PAGE_DELAY = 0.10
CHANNEL_WORKERS = 16
URI_RE = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s\"'<>`]+", re.IGNORECASE)


def fetch_full(url: str) -> bytes:
    response = catalog.session.get(url, timeout=(catalog.CONNECT_TIMEOUT, catalog.READ_TIMEOUT), stream=True)
    response.raise_for_status()
    data = bytearray()
    for chunk in response.iter_content(8192):
        if chunk:
            data.extend(chunk)
    return bytes(data)


catalog.fetch = fetch_full


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
    pattern = re.compile(rf"(?:https?://t\.me/|/)(?:s/)?{re.escape(channel)}/(\d+)(?:[\"'/?#]|$)", re.IGNORECASE)
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
            parsed = catalog.parse_lines("\n".join(page_uris), f"telegram:@{channel}")
            for row in parsed:
                uri = row["uri"]
                if uri in seen_uris:
                    continue
                seen_uris.add(uri)
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
    channels: list[str] = []
    seen: set[str] = set()
    for raw in catalog_data.get("channels", []):
        channel = str(raw).lstrip("@").strip()
        if channel and channel.lower() not in seen:
            seen.add(channel.lower())
            channels.append(channel)

    max_pages = max(1, min(int(item.get("max_pages", DEFAULT_MAX_PAGES)), 25))
    max_uris = max(100, min(int(item.get("max_uris", DEFAULT_MAX_URIS)), 20000))
    print(f"INFO telegram_catalog channels={len(channels)} workers={CHANNEL_WORKERS} pages={max_pages}")

    def run(channel: str):
        return collect_telegram({"channel": channel, "max_pages": max_pages, "max_uris": max_uris})

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


def collect_v2nodes(item: dict) -> list[dict]:
    """Collect v2nodes raw URIs, then normalize through the common parser."""
    start_url = str(item.get("url") or v2nodes_adapter.BASE)
    max_pages = max(1, min(int(item.get("max_pages", 5000)), 5000))
    uris = v2nodes_adapter.collect(start_url=start_url, max_pages=max_pages)
    if not uris:
        raise RuntimeError("v2nodes returned no proxy URIs")
    rows = catalog.parse_lines("\n".join(uris), str(item.get("name") or "v2nodes"))
    print(f"INFO v2nodes pages_limit={max_pages} raw_uris={len(uris)} parsed={len(rows)}")
    return rows


_original_collect_source = catalog.collect_source


def collect_source(item: dict) -> list[dict]:
    # sources.json is the public-source catalog; Telegram keeps its own catalog.
    if item.get("format") == "v2nodes":
        return collect_v2nodes(item)
    if item.get("format") == "telegram_html":
        return collect_telegram(item)
    if item.get("format") == "telegram_catalog":
        return collect_telegram_catalog(item)
    return _original_collect_source(item)


catalog.collect_source = collect_source


if __name__ == "__main__":
    pool.main()
