#!/usr/bin/env python3
"""Run the normal TCP catalog builder with direct Telegram public-channel sources.

This wrapper intentionally leaves update_catalog/build_tcp_pool filtering, TCP
screening, country classification, ranking, and publication logic unchanged.
It only teaches the source layer how to read Telegram's public preview pages
(t.me/s/<channel>) without requiring a Telegram API token.
"""
from __future__ import annotations

import html
import re
import time
from urllib.parse import unquote

import requests

import build_tcp_pool as pool
import update_catalog as catalog

TELEGRAM_TIMEOUT = (3.0, 12.0)
DEFAULT_MAX_PAGES = 8
DEFAULT_MAX_URIS = 5000
PAGE_DELAY = 0.10

URI_RE = re.compile(
    r"(?:vless|vmess|trojan|ss)://[^\s\"'<>`]+",
    re.IGNORECASE,
)


def _telegram_page(channel: str, before: int | None = None) -> str:
    url = f"https://t.me/s/{channel}"
    if before:
        url += f"?before={before}"
    response = catalog.session.get(url, timeout=TELEGRAM_TIMEOUT)
    response.raise_for_status()
    return response.text


def _extract_post_ids(channel: str, page: str) -> list[int]:
    # Telegram preview HTML has used several link forms over time. Accept both
    # absolute and relative post links and both /channel/id and /s/channel/id.
    pattern = re.compile(
        rf"(?:https?://t\.me/|/)(?:s/)?{re.escape(channel)}/(\d+)(?:[\"'/?#]|$)",
        re.IGNORECASE,
    )
    ids = {int(match.group(1)) for match in pattern.finditer(page)}
    return sorted(ids)


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
        decoded = unquote(decoded)
        page_uris = URI_RE.findall(decoded)

        # Feed each URI through the exact parser already used by the catalog.
        # That preserves the existing 80/443 + protocol filtering verbatim.
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

        post_ids = _extract_post_ids(channel, page)
        if not post_ids:
            break
        next_before = min(post_ids)
        if before is not None and next_before >= before:
            break
        before = next_before
        if page_number + 1 < max_pages:
            time.sleep(PAGE_DELAY)

    print(f"INFO telegram @{channel}: pages={pages_ok} accepted={len(rows)}")
    return rows


_original_collect_source = catalog.collect_source


def collect_source(item: dict) -> list[dict]:
    if item.get("format") == "telegram_html":
        return collect_telegram(item)
    return _original_collect_source(item)


# build_tcp_pool calls update_catalog.collect_source indirectly through the
# imported module object. Monkey-patching only this process keeps the stable
# catalog parser and TCP pipeline untouched while adding Telegram as a source.
catalog.collect_source = collect_source


if __name__ == "__main__":
    pool.main()
