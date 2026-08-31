#!/usr/bin/env python3
"""Collect v2nodes.com server pages and hand raw proxy URIs to the common pool.

This adapter intentionally owns no pool policy: worker count, allowed ports,
deduplication, liveness and downstream Xray validation remain centralized in the
repository's shared pipeline.
"""
from __future__ import annotations

import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

BASE = "https://www.v2nodes.com/"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151 Safari/537.36"
URI_RE = re.compile(r'(?P<uri>(?:vless|vmess|trojan|ss|ssconf)://[^\s<>"\'`]+)', re.IGNORECASE)
thread_local = threading.local()


def get_session() -> requests.Session:
    session = getattr(thread_local, "session", None)
    if session is None:
        session = requests.Session()
        session.headers.update({"User-Agent": UA, "Accept": "text/html,application/xhtml+xml"})
        adapter = requests.adapters.HTTPAdapter(pool_connections=8, pool_maxsize=8, max_retries=1)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        thread_local.session = session
    return session


def fetch(url: str, timeout: int = 20, attempts: int = 3) -> str:
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            r = get_session().get(url, timeout=timeout, headers={"Referer": BASE})
            r.raise_for_status()
            return r.text
        except Exception as exc:
            last_error = exc
            if attempt < attempts:
                import time
                time.sleep(0.5 * attempt)
    raise last_error


def discover_server_urls(html: str, limit: int, start_url: str) -> list[str]:
    seen_servers: set[str] = set()
    servers: list[str] = []
    listings: list[str] = [start_url]
    seen_listings: set[str] = {start_url}

    def add_server(href: str) -> None:
        url = urljoin(BASE, href)
        if "/servers/" in url and url not in seen_servers:
            seen_servers.add(url)
            servers.append(url)

    def add_listing(href: str) -> None:
        url = urljoin(BASE, href)
        if url.startswith(BASE) and "/servers/" not in url and url not in seen_listings:
            seen_listings.add(url)
            listings.append(url)

    def scan(page_html: str, listing_url: str) -> None:
        soup = BeautifulSoup(page_html, "html.parser")
        for a in soup.select("a[href]"):
            href = a.get("href")
            if not href:
                continue
            if "/servers/" in href:
                add_server(href)
            else:
                url = urljoin(listing_url, href)
                if url.startswith(BASE):
                    add_listing(href)
            if len(servers) >= limit:
                break

    scan(html, start_url)
    index = 0
    while index < len(listings) and len(servers) < limit:
        listing_url = listings[index]
        index += 1
        if listing_url == start_url:
            continue
        try:
            page_html = fetch(listing_url)
        except Exception:
            continue
        scan(page_html, listing_url)
    return servers[:limit]


def extract_uris(html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    chunks = [html, soup.get_text(" ", strip=True)]
    chunks.extend(tag.get_text(" ", strip=False) for tag in soup.find_all("script"))
    seen: set[str] = set()
    result: list[str] = []
    for chunk in chunks:
        for match in URI_RE.finditer(chunk):
            uri = match.group("uri").rstrip("),.;]}>'\"")
            if uri not in seen:
                seen.add(uri)
                result.append(uri)
    return result


def collect(start_url: str, max_pages: int = 5000) -> list[str]:
    """Return raw URIs only; shared pipeline applies all global constraints."""
    start_html = fetch(start_url)
    pages = discover_server_urls(start_html, max_pages, start_url)
    nodes: list[str] = []
    seen: set[str] = set()
    # Discovery concurrency is local to crawling, not the repository's node-test pool.
    # No v2nodes worker or port policy is exposed here.
    with ThreadPoolExecutor(max_workers=min(32, max(1, len(pages)))) as pool:
        futures = {pool.submit(fetch, url): url for url in pages}
        for future in as_completed(futures):
            url = futures[future]
            try:
                found = extract_uris(future.result())
            except Exception as exc:
                print(f"WARN v2nodes {url}: {exc}")
                continue
            for uri in found:
                if uri not in seen:
                    seen.add(uri)
                    nodes.append(uri)
    return nodes
