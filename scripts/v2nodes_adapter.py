#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

BASE = "https://www.v2nodes.com/"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151 Safari/537.36"

URI_RE = re.compile(
    r'(?P<uri>(?:vless|vmess|trojan|ss|ssconf)://[^\s<>"\'`]+)',
    re.IGNORECASE,
)

thread_local = threading.local()


def get_session() -> requests.Session:
    session = getattr(thread_local, "session", None)
    if session is None:
        session = requests.Session()
        session.headers.update({
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml",
        })
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=8,
            pool_maxsize=8,
            max_retries=1,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        thread_local.session = session
    return session


def fetch(url: str, timeout: int = 20, attempts: int = 3) -> str:
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            r = get_session().get(
                url,
                timeout=timeout,
                headers={"Referer": BASE},
            )
            r.raise_for_status()
            return r.text
        except Exception as exc:
            last_error = exc
            if attempt < attempts:
                import time
                time.sleep(0.5 * attempt)
    raise last_error


def discover_server_urls(html: str, limit: int, start_url: str) -> list[str]:
    """Collect every /servers/ URL visible in the site's crawled listing pages."""
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

    # Start page: collect server links and same-site listing links.
    soup = BeautifulSoup(html, "html.parser")
    for a in soup.select("a[href]"):
        href = a.get("href")
        if not href:
            continue
        if "/servers/" in href:
            add_server(href)
        else:
            # Keep broad same-site discovery, but do not chase arbitrary external links.
            url = urljoin(start_url, href)
            if url.startswith(BASE):
                add_listing(href)
        if len(servers) >= limit:
            return servers[:limit]

    # Follow same-site listing pages until there are no new ones or we hit the safety limit.
    index = 0
    while index < len(listings) and len(servers) < limit:
        listing_url = listings[index]
        index += 1
        if listing_url == start_url:
            page_html = html
        else:
            try:
                page_html = fetch(listing_url)
            except Exception:
                continue

        page_soup = BeautifulSoup(page_html, "html.parser")
        for a in page_soup.select("a[href]"):
            href = a.get("href")
            if not href:
                continue
            if "/servers/" in href:
                add_server(href)
                if len(servers) >= limit:
                    break
            else:
                url = urljoin(listing_url, href)
                if url.startswith(BASE):
                    add_listing(href)

    return servers[:limit]


def extract_uris(html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    chunks = [html, soup.get_text(" ", strip=True)]
    chunks.extend(tag.get_text(" ", strip=False) for tag in soup.find_all("script"))

    seen: set[str] = set()
    result: list[str] = []

    for chunk in chunks:
        for m in URI_RE.finditer(chunk):
            uri = m.group("uri").rstrip("),.;]}>'\"")
            if uri not in seen:
                seen.add(uri)
                result.append(uri)

    return result


def process_page(url: str) -> tuple[str, list[str], str | None]:
    try:
        return url, extract_uris(fetch(url)), None
    except Exception as exc:
        return url, [], str(exc)


def collect(start_url: str = BASE, max_pages: int = 5000) -> list[str]:
    """Collect proxy URIs using the same discovery/fetch logic as the laptop scraper."""
    start_html = fetch(start_url)
    pages = discover_server_urls(start_html, max_pages, start_url)

    nodes: list[str] = []
    seen: set[str] = set()

    with ThreadPoolExecutor(max_workers=250) as pool:
        futures = [pool.submit(process_page, url) for url in pages]

        for completed, future in enumerate(as_completed(futures), 1):
            url, found, error = future.result()

            if error:
                print(f"[{completed}/{len(pages)}] ERROR {url}: {error}")
                continue

            new = 0
            for uri in found:
                if uri not in seen:
                    seen.add(uri)
                    nodes.append(uri)
                    new += 1

            print(f"[{completed}/{len(pages)}] {new} new node(s) <- {url}")

    return nodes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-pages", type=int, default=5000)
    parser.add_argument("--output", default="v2nodes_nodes.txt")
    args = parser.parse_args()

    print(f"[+] Fetching {BASE}")
    try:
        nodes = collect(start_url=BASE, max_pages=args.max_pages)
    except Exception as exc:
        print(f"[!] Start page failed: {exc}", file=sys.stderr)
        return 1

    output = Path(args.output)
    output.write_text(
        "\n".join(nodes) + ("\n" if nodes else ""),
        encoding="utf-8",
    )

    print(f"\n[+] Unique nodes: {len(nodes)}")
    print(f"[+] Saved to: {output.resolve()}")

    if not nodes:
        print("[!] No proxy URI found in the pages.")
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
