#!/usr/bin/env python3
"""Recognition-only JCNode test.

Downloads the configured public YouTube video, transcribes its audio, and
prints four-digit candidates. It deliberately does not submit codes or fetch
any protected subscription.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CFG = ROOT / "sources" / "jcnode_test.json"
WORK = ROOT / ".jcnode-test"


def main() -> None:
    cfg = json.loads(CFG.read_text(encoding="utf-8"))
    if not cfg.get("enabled", False):
        print("JCNode test is configured but disabled in the committed settings.")
        print("Set enabled=true in sources/jcnode_test.json for a manual test run.")
        return

    url = cfg["youtube_url"]
    WORK.mkdir(exist_ok=True)
    audio = WORK / "audio.wav"

    subprocess.run([
        "yt-dlp", "--no-playlist", "-x", "--audio-format", "wav",
        "-o", str(WORK / "source.%(ext)s"), url
    ], check=True)

    candidates = sorted(WORK.glob("source.*"))
    if not candidates:
        raise SystemExit("YouTube download produced no media file")
    source = candidates[0]
    if source != audio:
        subprocess.run(["ffmpeg", "-y", "-i", str(source), "-ar", "16000", "-ac", "1", str(audio)], check=True)

    from faster_whisper import WhisperModel

    asr = cfg["asr"]
    model = WhisperModel(asr["model"], device="cpu", compute_type="int8")
    segments, info = model.transcribe(
        str(audio),
        language=None if asr.get("language") == "auto" else asr.get("language"),
        beam_size=asr.get("beam_size", 5),
        vad_filter=asr.get("vad_filter", True),
    )
    text = " ".join(seg.text.strip() for seg in segments)
    print(f"Detected language: {info.language}")
    print("Transcript:")
    print(text)

    digit_words = {
        "zero":"0", "one":"1", "two":"2", "three":"3", "four":"4",
        "five":"5", "six":"6", "seven":"7", "eight":"8", "nine":"9",
    }
    normalized = text.lower()
    for word, digit in digit_words.items():
        normalized = re.sub(rf"\b{word}\b", digit, normalized)

    candidates = []
    candidates.extend(re.findall(r"(?<!\d)\d{4}(?!\d)", normalized))
    seen = set()
    print("Four-digit candidates:")
    for c in candidates:
        if c not in seen:
            seen.add(c)
            print(c)


if __name__ == "__main__":
    main()
