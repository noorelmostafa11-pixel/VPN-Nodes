#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

BASE = "https://www.v2nodes.com/"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151 Safari/537.36"
RECENT_WINDOW_HOURS = 24

URI_RE = re.compile(
    r'(?P<uri>(?:vless|vmess|trojan|ss|ssconf)://[^\s<>"\'`]+)',
    re.IGNORECASE,
)
RELATIVE_AGE_RE = re.compile(
    r"\b(?P<count>\d+|a|an|one)\s+(?P<unit>second|minute|hour|day|week|month|year)s?\s+ago\b",
    re.IGNORECASE,
)
PAGE_OF_RE = re.compile(r"\b\d+\s+of\s+(?P<total>\d+)\b", re.IGNORECASE)

thread_local = threading.local()


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_utc(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


def env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.environ.get(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


def get_session() -> requests.Session:
    session = getattr(thread_local, "session", None)
    if session is None:
        session = requests.Session()
        session.headers.update({
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml",
        })
        # Explicit retry/backoff below owns retry behavior. Keep urllib3 from
        # silently multiplying requests when v2nodes is under load.
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=4,
            pool_maxsize=4,
            max_retries=0,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        thread_local.session = session
    return session


def is_retryable_error(exc: Exception) -> bool:
    if isinstance(exc, (requests.Timeout, requests.ConnectionError)):
        return True
    if isinstance(exc, requests.HTTPError):
        response = exc.response
        status = response.status_code if response is not None else 0
        return status == 429 or 500 <= status < 600
    return False


def fetch(url: str, timeout: float = 25, attempts: int = 3) -> str:
    last_error: Exception | None = None
    backoff = (1.0, 3.0, 6.0)
    for attempt in range(1, max(1, attempts) + 1):
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
            if attempt >= attempts or not is_retryable_error(exc):
                break
            time.sleep(backoff[min(attempt - 1, len(backoff) - 1)])
    assert last_error is not None
    raise last_error


def parse_relative_age(text: str) -> dt.timedelta | None:
    lowered = " ".join(text.lower().split())
    if "just now" in lowered:
        return dt.timedelta(0)

    match = RELATIVE_AGE_RE.search(lowered)
    if not match:
        return None

    raw_count = match.group("count").lower()
    count = 1 if raw_count in {"a", "an", "one"} else int(raw_count)
    unit = match.group("unit").lower()
    seconds_per_unit = {
        "second": 1,
        "minute": 60,
        "hour": 3600,
        "day": 86400,
        "week": 7 * 86400,
        "month": 30 * 86400,
        "year": 365 * 86400,
    }
    return dt.timedelta(seconds=count * seconds_per_unit[unit])


def parse_absolute_timestamp(raw: str) -> dt.datetime | None:
    value = (raw or "").strip()
    if not value:
        return None

    if re.fullmatch(r"\d{10,13}", value):
        number = int(value)
        if len(value) == 13:
            number /= 1000
        try:
            return dt.datetime.fromtimestamp(number, tz=dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def server_published_at(anchor, fetched_at: dt.datetime) -> dt.datetime | None:
    """Read one server card's timestamp without leaking into neighboring cards."""
    node = anchor
    for _ in range(6):
        node = getattr(node, "parent", None)
        if node is None:
            break

        server_links = node.select('a[href*="/servers/"]')
        if len(server_links) > 1:
            break

        time_tag = node.find("time")
        if time_tag is not None:
            for attr in ("datetime", "data-time", "data-timestamp"):
                parsed = parse_absolute_timestamp(time_tag.get(attr, ""))
                if parsed is not None:
                    return parsed

        age = parse_relative_age(node.get_text(" ", strip=True))
        if age is not None:
            return fetched_at - age

    return None


def extract_listing_server_records(
    html: str,
    fetched_at: dt.datetime,
    start_url: str,
) -> list[tuple[str, dt.datetime | None]]:
    soup = BeautifulSoup(html, "html.parser")
    seen: set[str] = set()
    records: list[tuple[str, dt.datetime | None]] = []

    for anchor in soup.select('a[href*="/servers/"]'):
        href = anchor.get("href")
        if not href:
            continue
        url = urljoin(start_url, href)
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or parsed.netloc != urlparse(BASE).netloc:
            continue
        if "/servers/" not in parsed.path or url in seen:
            continue
        seen.add(url)
        records.append((url, server_published_at(anchor, fetched_at)))

    return records


def discover_total_listing_pages(html: str, start_url: str) -> int:
    soup = BeautifulSoup(html, "html.parser")
    total = 1
    expected_host = urlparse(start_url).netloc or urlparse(BASE).netloc

    for anchor in soup.select("a[href]"):
        href = anchor.get("href")
        if not href:
            continue
        url = urljoin(start_url, href)
        parsed = urlparse(url)
        if parsed.netloc != expected_host or "/servers/" in parsed.path:
            continue
        values = parse_qs(parsed.query).get("page", [])
        for value in values:
            if value.isdigit():
                total = max(total, int(value))

    for match in PAGE_OF_RE.finditer(soup.get_text(" ", strip=True)):
        total = max(total, int(match.group("total")))

    return total


def listing_page_url(start_url: str, page: int) -> str:
    if page <= 1:
        return start_url

    parsed = urlparse(start_url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["page"] = str(page)
    return urlunparse(parsed._replace(query=urlencode(query)))


def discover_recent_server_urls(
    start_html: str,
    limit: int,
    start_url: str,
    started_at: dt.datetime,
    start_fetched_at: dt.datetime,
    timeout: float,
) -> tuple[list[str], dict[str, int | bool]]:
    """Collect only server pages that were fresh at v2nodes collection start."""
    cutoff = started_at - dt.timedelta(hours=RECENT_WINDOW_HOURS)
    total_listing_pages = discover_total_listing_pages(start_html, start_url)

    seen_servers: set[str] = set()
    recent_servers: list[str] = []
    listing_pages_scanned = 0
    older_skipped = 0
    undated_skipped = 0
    stopped_at_boundary = False

    for page_number in range(1, total_listing_pages + 1):
        if len(recent_servers) >= limit:
            break

        if page_number == 1:
            page_html = start_html
            fetched_at = start_fetched_at
        else:
            page_url = listing_page_url(start_url, page_number)
            try:
                page_html = fetch(page_url, timeout=timeout, attempts=3)
                fetched_at = utc_now()
            except Exception as exc:
                print(f"WARN v2nodes listing page {page_number} failed: {exc}")
                continue

        listing_pages_scanned += 1
        records = extract_listing_server_records(page_html, fetched_at, start_url)
        page_recent = 0
        page_older = 0
        page_undated = 0

        for url, published_at in records:
            if url in seen_servers:
                continue
            seen_servers.add(url)

            if published_at is None:
                page_undated += 1
                undated_skipped += 1
                continue
            if published_at < cutoff:
                page_older += 1
                older_skipped += 1
                continue

            recent_servers.append(url)
            page_recent += 1
            if len(recent_servers) >= limit:
                break

        # Stop only after a whole dated page is beyond the cutoff. This avoids
        # losing nodes on the mixed boundary page and tolerates minor card-order
        # changes within one listing page.
        if records and page_recent == 0 and page_older > 0 and page_undated == 0:
            stopped_at_boundary = True
            break

    return recent_servers[:limit], {
        "listing_pages_total": total_listing_pages,
        "listing_pages_scanned": listing_pages_scanned,
        "older_skipped": older_skipped,
        "undated_skipped": undated_skipped,
        "stopped_at_boundary": stopped_at_boundary,
    }


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


def process_page(url: str, timeout: float, attempts: int) -> tuple[str, list[str], Exception | None]:
    try:
        return url, extract_uris(fetch(url, timeout=timeout, attempts=attempts)), None
    except Exception as exc:
        return url, [], exc


def collect(start_url: str = BASE, max_pages: int = 5000) -> list[str]:
    """Collect only v2nodes proxy URIs fresh within 24h of this function start."""
    started_at = utc_now()
    cutoff = started_at - dt.timedelta(hours=RECENT_WINDOW_HOURS)

    primary_workers = env_int("V2NODES_WORKERS", 80, 1, 150)
    retry_workers = env_int("V2NODES_RETRY_WORKERS", 20, 1, 50)
    primary_timeout = env_float("V2NODES_TIMEOUT", 25.0, 5.0, 60.0)
    retry_timeout = env_float("V2NODES_RETRY_TIMEOUT", 30.0, 5.0, 90.0)

    start_html = fetch(start_url, timeout=primary_timeout, attempts=3)
    start_fetched_at = utc_now()
    pages, discovery = discover_recent_server_urls(
        start_html,
        max_pages,
        start_url,
        started_at,
        start_fetched_at,
        primary_timeout,
    )

    nodes: list[str] = []
    seen: set[str] = set()
    retry_urls: list[str] = []

    def add_found(found: list[str]) -> int:
        new = 0
        for uri in found:
            if uri not in seen:
                seen.add(uri)
                nodes.append(uri)
                new += 1
        return new

    print(f"INFO v2nodes started_at={iso_utc(started_at)} cutoff_24h={iso_utc(cutoff)}")
    print(
        f"INFO v2nodes listing_pages_total={discovery['listing_pages_total']} "
        f"listing_pages_scanned={discovery['listing_pages_scanned']} "
        f"recent_24h_server_pages={len(pages)} older_skipped={discovery['older_skipped']} "
        f"undated_skipped={discovery['undated_skipped']} "
        f"stopped_at_24h_boundary={str(discovery['stopped_at_boundary']).lower()}"
    )
    print(
        f"INFO v2nodes pages={len(pages)} primary_workers={primary_workers} "
        f"retry_workers={retry_workers} primary_timeout_s={primary_timeout} retry_timeout_s={retry_timeout}"
    )

    # First pass: one request per recent server page. Failed transient pages are
    # deferred instead of retrying immediately while the site is already saturated.
    with ThreadPoolExecutor(max_workers=primary_workers) as pool:
        futures = [pool.submit(process_page, url, primary_timeout, 1) for url in pages]

        for completed, future in enumerate(as_completed(futures), 1):
            url, found, error = future.result()

            if error is not None:
                if is_retryable_error(error):
                    retry_urls.append(url)
                    print(f"[{completed}/{len(pages)}] RETRY-LATER {url}: {error}")
                else:
                    print(f"[{completed}/{len(pages)}] ERROR {url}: {error}")
                continue

            new = add_found(found)
            print(f"[{completed}/{len(pages)}] {new} new node(s) <- {url}")

    recovered_pages = 0
    if retry_urls:
        print(f"INFO v2nodes second_pass={len(retry_urls)} workers={retry_workers} attempts=3")
        with ThreadPoolExecutor(max_workers=retry_workers) as pool:
            futures = [pool.submit(process_page, url, retry_timeout, 3) for url in retry_urls]

            for completed, future in enumerate(as_completed(futures), 1):
                url, found, error = future.result()
                if error is not None:
                    print(f"[retry {completed}/{len(retry_urls)}] ERROR {url}: {error}")
                    continue
                recovered_pages += 1
                new = add_found(found)
                print(f"[retry {completed}/{len(retry_urls)}] {new} new node(s) <- {url}")

    print(
        f"INFO v2nodes retry_summary queued={len(retry_urls)} "
        f"recovered_pages={recovered_pages} remaining_failed={len(retry_urls) - recovered_pages}"
    )

    # One final first-page read catches nodes published while this adapter was
    # processing the initial snapshot. The original cutoff remains fixed.
    late_arrivals: list[str] = []
    known_server_pages = set(pages)
    try:
        late_html = fetch(start_url, timeout=primary_timeout, attempts=3)
        late_fetched_at = utc_now()
        for url, published_at in extract_listing_server_records(late_html, late_fetched_at, start_url):
            if url in known_server_pages or published_at is None or published_at < cutoff:
                continue
            known_server_pages.add(url)
            late_arrivals.append(url)
    except Exception as exc:
        print(f"WARN v2nodes late-arrival rescan failed: {exc}")

    if late_arrivals:
        with ThreadPoolExecutor(max_workers=min(primary_workers, len(late_arrivals))) as pool:
            futures = [pool.submit(process_page, url, retry_timeout, 3) for url in late_arrivals]
            for completed, future in enumerate(as_completed(futures), 1):
                url, found, error = future.result()
                if error is not None:
                    print(f"[late {completed}/{len(late_arrivals)}] ERROR {url}: {error}")
                    continue
                new = add_found(found)
                print(f"[late {completed}/{len(late_arrivals)}] {new} new node(s) <- {url}")

    print(f"INFO v2nodes late_arrivals={len(late_arrivals)}")
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
