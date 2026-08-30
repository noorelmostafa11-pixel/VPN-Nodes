#!/usr/bin/env python3
"""Recognition-only JCNode test with transcript -> audio/ASR fallback.

Uses a public transcript when available. If no captions are available, it
falls back to downloading audio with yt-dlp and transcribing it with
faster-whisper. It never submits codes or fetches a protected subscription.
"""
from __future__ import annotations

import json
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
CFG = ROOT / "sources" / "jcnode_test.json"
WORK = ROOT / ".jcnode-test"
TRANSCRIPT_ENDPOINT = "https://youtube-transcript.ai/transcript/{video_id}.txt"

DIGIT_WORDS = {
    "zero":"0", "one":"1", "two":"2", "three":"3", "four":"4",
    "five":"5", "six":"6", "seven":"7", "eight":"8", "nine":"9", "oh":"0",
    "صفر":"0", "واحد":"1", "اثنان":"2", "اثنين":"2", "ثلاثة":"3", "ثلاث":"3",
    "اربعة":"4", "أربعة":"4", "خمسة":"5", "ستة":"6", "سبعة":"7", "ثمانية":"8", "تسعة":"9",
    "零":"0", "一":"1", "二":"2", "两":"2", "三":"3", "四":"4", "五":"5", "六":"6", "七":"7", "八":"8", "九":"9",
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


def fetch_transcript(video_id: str, language: str | None = None) -> str | None:
    endpoint = TRANSCRIPT_ENDPOINT.format(video_id=video_id)
    if language and language != "auto":
        endpoint += f"?lang={language}"
    request = urllib.request.Request(endpoint, headers={"User-Agent": "VPN-Nodes-JCNode-Test/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            text = response.read().decode("utf-8").strip()
            if not text or "No captions available" in text:
                return None
            return text
    except (urllib.error.HTTPError, urllib.error.URLError):
        return None


def transcribe_audio(url: str, asr: dict) -> str:
    WORK.mkdir(exist_ok=True)
    for old in WORK.glob("source.*"):
        old.unlink()
    audio = WORK / "audio.wav"
    subprocess.run([
        "yt-dlp", "--no-playlist", "-x", "--audio-format", "wav",
        "-o", str(WORK / "source.%(ext)s"), url,
    ], check=True)
    candidates = list(WORK.glob("source.*"))
    if not candidates:
        raise RuntimeError("YouTube download produced no media file")
    source = candidates[0]
    subprocess.run(["ffmpeg", "-y", "-i", str(source), "-ar", "16000", "-ac", "1", str(audio)], check=True)
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
    seen: set[str] = set()
    result: list[str] = []
    # Only inspect transcript/ASR text. Never inspect title, URL, metadata, or video ID.
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
    transcript = fetch_transcript(video_id, asr.get("language"))
    source = "transcript"
    if transcript is None:
        print("No captions available; falling back to audio ASR with faster-whisper.")
        transcript = transcribe_audio(video_url, asr)
        source = "faster-whisper ASR"
    print(f"Video ID: {video_id}")
    print(f"Recognition source: {source}")
    print("Transcript/ASR text:")
    print(transcript)
    candidates = extract_candidates(transcript, int(cfg.get("code_detection", {}).get("max_candidates", 10)))
    print("Four-digit candidates:")
    if not candidates:
        print("NONE")
    else:
        for candidate in candidates:
            print(candidate)


if __name__ == "__main__":
    main()
