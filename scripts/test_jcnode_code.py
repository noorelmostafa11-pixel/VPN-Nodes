#!/usr/bin/env python3
"""Recognition-only JCNode transcript test.

Fetches the configured public YouTube transcript by video ID instead of
having yt-dlp download the media. It prints four-digit candidates and does
not submit codes or fetch any protected subscription.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
CFG = ROOT / "sources" / "jcnode_test.json"

TRANSCRIPT_ENDPOINT = "https://youtube-transcript.ai/transcript/{video_id}.txt"

DIGIT_WORDS = {
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9",
    "oh": "0",
    "صفر": "0", "واحد": "1", "اثنان": "2", "اثنين": "2", "ثلاثة": "3",
    "ثلاث": "3", "اربعة": "4", "أربعة": "4", "خمسة": "5", "ستة": "6",
    "سبعة": "7", "ثمانية": "8", "تسعة": "9",
}


def video_id_from_url(value: str) -> str:
    value = value.strip()
    if re.fullmatch(r"[A-Za-z0-9_-]{11}", value):
        return value
    parsed = urlparse(value)
    if parsed.hostname in {"youtu.be", "www.youtu.be"}:
        candidate = parsed.path.strip("/").split("/")[0]
    else:
        candidate = parse_qs(parsed.query).get("v", [""])[0]
    if not re.fullmatch(r"[A-Za-z0-9_-]{11}", candidate):
        raise ValueError(f"Could not extract an 11-character YouTube video ID from: {value}")
    return candidate


def fetch_transcript(video_id: str, language: str | None = None) -> str:
    endpoint = TRANSCRIPT_ENDPOINT.format(video_id=video_id)
    if language and language != "auto":
        endpoint += f"?lang={language}"
    request = urllib.request.Request(
        endpoint,
        headers={"User-Agent": "VPN-Nodes-JCNode-Test/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Transcript service returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Transcript service request failed: {exc.reason}") from exc


def normalize_digits(text: str) -> str:
    normalized = text.lower()
    # Longest words first avoids partial replacements in Arabic/English text.
    for word, digit in sorted(DIGIT_WORDS.items(), key=lambda item: len(item[0]), reverse=True):
        normalized = re.sub(rf"(?<!\w){re.escape(word)}(?!\w)", digit, normalized)
    return normalized


def extract_candidates(text: str, max_candidates: int) -> list[str]:
    normalized = normalize_digits(text)
    candidates = re.findall(r"(?<!\d)\d{4}(?!\d)", normalized)
    seen: set[str] = set()
    result: list[str] = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            result.append(candidate)
        if len(result) >= max_candidates:
            break
    return result


def main() -> None:
    cfg = json.loads(CFG.read_text(encoding="utf-8"))
    if not cfg.get("enabled", False):
        print("JCNode test is configured but disabled in the committed settings.")
        print("Set enabled=true in sources/jcnode_test.json for a manual test run.")
        return

    video_id = video_id_from_url(cfg["youtube_url"])
    asr = cfg.get("asr", {})
    transcript = fetch_transcript(video_id, asr.get("language"))

    print(f"Video ID: {video_id}")
    print("Transcript source: YouTube transcript service")
    print("Transcript:")
    print(transcript.strip())

    detection = cfg.get("code_detection", {})
    max_candidates = int(detection.get("max_candidates", 10))
    candidates = extract_candidates(transcript, max_candidates)
    print("Four-digit candidates:")
    for candidate in candidates:
        print(candidate)


if __name__ == "__main__":
    main()
