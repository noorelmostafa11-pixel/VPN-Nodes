#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import v2nodes_adapter as v2nodes

UTC = dt.timezone.utc


def card(server_id: int, age_text: str | None = None, timestamp: str | None = None) -> str:
    if timestamp is not None:
        age = f'<time datetime="{timestamp}">timestamp</time>'
    elif age_text is not None:
        age = f"<span>🕓 {age_text}</span>"
    else:
        age = "<span>no timestamp</span>"
    return f'<div class="server-card"><a href="/servers/{server_id}/">server {server_id}</a>{age}</div>'


def listing(page: int, total: int, *cards: str) -> str:
    return (
        "<html><body>"
        + "".join(cards)
        + f'<div>{page} of {total}</div>'
        + (f'<a href="?page={page + 1}">Next</a>' if page < total else "")
        + f'<a href="?page={total}">Last</a>'
        + "</body></html>"
    )


def test_relative_age_parser() -> None:
    assert v2nodes.parse_relative_age("🕓 23 hours ago") == dt.timedelta(hours=23)
    assert v2nodes.parse_relative_age("1 day ago") == dt.timedelta(days=1)
    assert v2nodes.parse_relative_age("a minute ago") == dt.timedelta(minutes=1)
    assert v2nodes.parse_relative_age("just now") == dt.timedelta(0)


def test_fixed_24h_cutoff_and_safe_boundary_stop() -> None:
    started_at = dt.datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
    page1 = listing(
        1,
        3,
        card(1, timestamp="2026-09-07T12:01:00Z"),  # 23h59m: keep
        card(2, timestamp="2026-09-07T11:59:00Z"),  # 24h01m: reject
    )
    page2 = listing(
        2,
        3,
        card(3, timestamp="2026-09-07T11:00:00Z"),
        card(4, timestamp="2026-09-07T10:00:00Z"),
    )

    fetched = []

    def fake_fetch(url: str, timeout: float = 25, attempts: int = 3) -> str:
        fetched.append(url)
        if url == "https://www.v2nodes.com/?page=2":
            return page2
        raise AssertionError(f"unexpected fetch: {url}")

    original_fetch = v2nodes.fetch
    original_now = v2nodes.utc_now
    try:
        v2nodes.fetch = fake_fetch
        v2nodes.utc_now = lambda: started_at
        pages, stats = v2nodes.discover_recent_server_urls(
            page1,
            limit=5000,
            start_url=v2nodes.BASE,
            started_at=started_at,
            start_fetched_at=started_at,
            timeout=25,
        )
    finally:
        v2nodes.fetch = original_fetch
        v2nodes.utc_now = original_now

    assert pages == ["https://www.v2nodes.com/servers/1/"]
    assert stats["listing_pages_total"] == 3
    assert stats["listing_pages_scanned"] == 2
    assert stats["older_skipped"] == 3
    assert stats["undated_skipped"] == 0
    assert stats["stopped_at_boundary"] is True
    assert fetched == ["https://www.v2nodes.com/?page=2"]


def test_relative_age_is_measured_against_collection_start() -> None:
    started_at = dt.datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
    # Listing fetched two minutes after collection start. "23 hours ago" still
    # estimates a publication time inside the fixed 24-hour window.
    fetched_at = started_at + dt.timedelta(minutes=2)
    html = listing(1, 1, card(10, age_text="23 hours ago"))
    records = v2nodes.extract_listing_server_records(html, fetched_at, v2nodes.BASE)
    assert records == [
        ("https://www.v2nodes.com/servers/10/", fetched_at - dt.timedelta(hours=23))
    ]
    cutoff = started_at - dt.timedelta(hours=24)
    assert records[0][1] is not None and records[0][1] >= cutoff


def test_collect_catches_late_arrivals() -> None:
    initial = listing(1, 1, card(1, age_text="1 minute ago"))
    rescanned = listing(
        1,
        1,
        card(2, age_text="5 seconds ago"),
        card(1, age_text="2 minutes ago"),
    )
    uri1 = "vless://11111111-1111-1111-1111-111111111111@one.example:443?security=tls#one"
    uri2 = "trojan://secret@two.example:443?security=tls#two"

    base_fetches = 0

    def fake_fetch(url: str, timeout: float = 25, attempts: int = 3) -> str:
        nonlocal base_fetches
        if url == v2nodes.BASE:
            base_fetches += 1
            return initial if base_fetches == 1 else rescanned
        if url == "https://www.v2nodes.com/servers/1/":
            return f"<html><body>{uri1}</body></html>"
        if url == "https://www.v2nodes.com/servers/2/":
            return f"<html><body>{uri2}</body></html>"
        raise AssertionError(f"unexpected fetch: {url}")

    original_fetch = v2nodes.fetch
    old_workers = os.environ.get("V2NODES_WORKERS")
    old_retry_workers = os.environ.get("V2NODES_RETRY_WORKERS")
    try:
        v2nodes.fetch = fake_fetch
        os.environ["V2NODES_WORKERS"] = "1"
        os.environ["V2NODES_RETRY_WORKERS"] = "1"
        nodes = v2nodes.collect(start_url=v2nodes.BASE, max_pages=5000)
    finally:
        v2nodes.fetch = original_fetch
        if old_workers is None:
            os.environ.pop("V2NODES_WORKERS", None)
        else:
            os.environ["V2NODES_WORKERS"] = old_workers
        if old_retry_workers is None:
            os.environ.pop("V2NODES_RETRY_WORKERS", None)
        else:
            os.environ["V2NODES_RETRY_WORKERS"] = old_retry_workers

    assert nodes == [uri1, uri2]
    assert base_fetches == 2


def test_undated_cards_are_not_mistaken_for_recent() -> None:
    now = dt.datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
    html = listing(1, 1, card(99))
    records = v2nodes.extract_listing_server_records(html, now, v2nodes.BASE)
    assert records == [("https://www.v2nodes.com/servers/99/", None)]


if __name__ == "__main__":
    test_relative_age_parser()
    test_fixed_24h_cutoff_and_safe_boundary_stop()
    test_relative_age_is_measured_against_collection_start()
    test_collect_catches_late_arrivals()
    test_undated_cards_are_not_mistaken_for_recent()
    print("OK v2nodes 24-hour window and late-arrival rescan")
