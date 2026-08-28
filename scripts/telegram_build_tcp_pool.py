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

import build_tcp_pool as pool
import update_catalog as catalog

TELEGRAM_TIMEOUT = (3.0, 12.0)
DEFAULT_MAX_PAGES = 8
DEFAULT_MAX_URIS = 5000
PAGE_DELAY = 0.10

URI_RE = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s\"'<>`]+", re.IGNORECASE)


def _telegram_page(channel: str, before: int | None = None) -> str:
    url = f"https://t.me/s/{channel}"
    if before:
        url += f"?before={before}"
    response = catalog.session.get(url, timeout=TELEGRAM_TIMEOUT)
    response.raise_for_status()
    return response.text


def _extract_before(channel: str, page: str, current_before: int | None) -> int | None:
    """Find the next older message id from Telegram's preview pagination."""
    candidates: set[int] = set()

    # Pagination links normally contain ?before=<message_id>.
    for match in re.finditer(r"[?&]before=(\d+)", page, re.IGNORECASE):
        value = int(match.group(1))
        if value > 0:
            candidates.add(value)

    # Fallback: post links themselves are stable message ids.
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

        next_before = _extract_before(channel, page, before)
        if next_before is None:
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
