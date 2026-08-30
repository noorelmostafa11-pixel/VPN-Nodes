#!/usr/bin/env python3
"""Recognition-only JCNode test using an external YouTube-to-MP3 service."""
from __future__ import annotations

import json
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
CFG = ROOT / "sources" / "jcnode_test.json"
WORK = ROOT / ".jcnode-test"
CONVERTER_ENDPOINT = "https://ytmp3.ge/api/convert"

DIGIT_WORDS = {
    "zero":"0", "one":"1", "two":"2", "three":"3", "four":"4", "five":"5",
    "six":"6", "seven":"7", "eight":"8", "nine":"9", "oh":"0",
    "صفر":"0", "واحد":"1", "اثنان":"2", "اثنين":"2", "ثلاثة":"3", "ثلاث":"3",
    "اربعة":"4", "أربعة":"4", "خمسة":"5", "ستة":"6", "سبعة":"7", "ثمانية":"8", "تسعة":"9",
}


def video_id_from_url(value: str) -> str:
    value = value.strip()
    if re.fullmatch(r"[A-Za-z0-9_-]{11}", value):
        return value
    parsed = urlparse(value)
    candidate = parsed.path.strip("/").split("/")[0] if parsed.hostname in {"youtu.be", "www.youtu.be"} else parse_qs(parsed.query).get("v", [""])[0]
    if not re.fullmatch(r"[A-Za-z0-9_-]{11}", candidate):
        raise ValueError(f"Could not extract an 11-character YouTube video ID from: {value}")
    return candidate


def convert_to_mp3(video_url: str, quality: str = "192") -> Path:
    WORK.mkdir(exist_ok=True)
    audio = WORK / "jcnode.mp3"
    form = urllib.parse.urlencode({"youtube_url": video_url, "quality": quality}).encode()
    request = urllib.request.Request(
        CONVERTER_ENDPOINT,
        data=form,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "VPN-Nodes-JCNode-Test/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Audio conversion request failed: {exc}") from exc
    if not payload.get("success") or not payload.get("downloadUrl"):
        raise RuntimeError(f"Audio conversion failed: {payload}")
    download = urllib.request.Request(payload["downloadUrl"], headers={"User-Agent": "VPN-Nodes-JCNode-Test/1.0"})
    with urllib.request.urlopen(download, timeout=300) as response, audio.open("wb") as out:
        while chunk := response.read(1024 * 1024):
            out.write(chunk)
    if audio.stat().st_size == 0:
        raise RuntimeError("Converter returned an empty audio file")
    print(f"Audio downloaded: {audio.stat().st_size} bytes")
    return audio


def transcribe_audio(audio: Path, asr: dict) -> str:
    from faster_whisper import WhisperModel
    model = WhisperModel(asr.get("model", "small"), device="cpu", compute_type="int8")
    segments, info = model.transcribe(
        str(audio),
        language=None if asr.get("language", "auto") == "auto" else asr.get("language"),
        beam_size=int(asr.get("beam_size", 5)),
        vad_filter=bool(asr.get("vad_filter", True)),
    )
    print(f"ASR detected language: {info.language}")
    return " ".join(seg.text.strip() for seg in segments).strip()


def normalize_digits(text: str) -> str:
    normalized = text.lower()
    for word, digit in sorted(DIGIT_WORDS.items(), key=lambda item: len(item[0]), reverse=True):
        normalized = re.sub(rf"(?<!\w){re.escape(word)}(?!\w)", digit, normalized)
    return normalized


def extract_candidates(text: str, max_candidates: int) -> list[str]:
    normalized = normalize_digits(text)
    result: list[str] = []
    seen: set[str] = set()
    for candidate in re.findall(r"(?<!\d)\d{4}(?!\d)", normalized):
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
        return
    video_url = cfg["youtube_url"]
    video_id = video_id_from_url(video_url)
    asr = cfg.get("asr", {})
    quality = str(cfg.get("external_audio", {}).get("quality", "192"))
    print(f"Video ID: {video_id}")
    print("Audio source: external YouTube-to-MP3 converter")
    audio = convert_to_mp3(video_url, quality)
    text = transcribe_audio(audio, asr)
    print("ASR text:")
    print(text)
    candidates = extract_candidates(text, int(cfg.get("code_detection", {}).get("max_candidates", 10)))
    print("Four-digit candidates:")
    if candidates:
        print("\n".join(candidates))
    else:
        print("NONE")


if __name__ == "__main__":
    main()
