#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import threading
import time
from pathlib import Path

import benchmark_engines_v3 as bench

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
SAMPLE = OUT / "metadata" / "benchmark_sample.txt"


def load_or_freeze_sample(limit: int) -> list[str]:
    """Reuse the committed benchmark snapshot; create it only if absent/invalid."""
    if SAMPLE.exists():
        rows = [x.strip() for x in SAMPLE.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()]
        if len(rows) == limit:
            return rows
    rows = bench.freeze_sample(limit)
    if len(rows) != limit:
        raise SystemExit(f"benchmark sample contains {len(rows)} nodes; requested {limit}")
    return rows


def descendants(pid: int) -> set[int]:
    """Return pid and all descendants using /proc, with no third-party dependency."""
    children: dict[int, list[int]] = {}
    proc = Path("/proc")
    for p in proc.iterdir():
        if not p.name.isdigit():
            continue
        try:
            stat = (p / "stat").read_text(encoding="utf-8", errors="ignore")
            rparen = stat.rfind(")")
            fields = stat[rparen + 2 :].split()
            ppid = int(fields[1])
            children.setdefault(ppid, []).append(int(p.name))
        except Exception:
            continue
    seen = {pid}; stack = [pid]
    while stack:
        cur = stack.pop()
        for child in children.get(cur, []):
            if child not in seen:
                seen.add(child); stack.append(child)
    return seen


def process_metrics(name: str, fn, interval: float = 0.10):
    stop = threading.Event()
    samples: list[dict] = []

    def sample() -> None:
        while not stop.is_set():
            rss = 0
            cpu = 0.0
            matched: list[int] = []
            try:
                for p in Path("/proc").iterdir():
                    if not p.name.isdigit():
                        continue
                    pid = int(p.name)
                    try:
                        comm = (p / "comm").read_text(encoding="utf-8", errors="ignore").strip().lower()
                        if comm != name.lower():
                            continue
                        matched.append(pid)
                        status = (p / "status").read_text(encoding="utf-8", errors="ignore")
                        for line in status.splitlines():
                            if line.startswith("VmRSS:"):
                                rss += int(line.split()[1]) * 1024
                                break
                        stat = (p / "stat").read_text(encoding="utf-8", errors="ignore")
                        rparen = stat.rfind(")")
                        fields = stat[rparen + 2 :].split()
                        utime = int(fields[11]); stime = int(fields[12])
                        cpu += (utime + stime)
                    except Exception:
                        continue
            except Exception:
                pass
            if matched:
                samples.append({"rss_bytes": rss, "cpu_ticks": cpu})
            stop.wait(interval)

    t = threading.Thread(target=sample, name=f"metrics-{name}", daemon=True)
    t.start()
    started = time.perf_counter()
    try:
        result = fn()
    finally:
        stop.set(); t.join(timeout=2)
    elapsed = time.perf_counter() - started

    ticks_per_second = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    cpus = os.cpu_count() or 1
    peak_rss_mb = max((x["rss_bytes"] for x in samples), default=0) / (1024 * 1024)
    cpu_pct_samples = []
    for prev, cur in zip(samples, samples[1:]):
        dt = interval * max(1, len(cur) * 0 + 1)
        delta_ticks = max(0.0, cur["cpu_ticks"] - prev["cpu_ticks"])
        cpu_pct_samples.append((delta_ticks / ticks_per_second / max(dt, 0.001)) * 100.0 / cpus)
    result["resource_metrics"] = {
        "peak_rss_mb": round(peak_rss_mb, 2),
        "avg_cpu_percent_of_runner": round(sum(cpu_pct_samples) / len(cpu_pct_samples), 2) if cpu_pct_samples else 0.0,
        "sample_count": len(samples),
        "metric_note": "sampled engine processes by /proc; CPU percentage is normalized to total runner CPUs",
    }
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=500)
    ap.add_argument("--workers", type=int, default=80)
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--out", default=str(OUT / "metadata" / "engine_benchmark_xray_mihomo.json"))
    args = ap.parse_args()

    rows = load_or_freeze_sample(args.limit)
    sample_hash = hashlib.sha256(("\n".join(rows) + "\n").encode()).hexdigest()
    print(json.dumps({"sample_sha256": sample_hash, "sample_loaded": len(rows), "sample_file": str(SAMPLE)}, ensure_ascii=False))

    xray = process_metrics(
        "xray",
        lambda: bench.run_xray(rows, args.workers, args.timeout),
    )
    mihomo = process_metrics(
        "mihomo",
        lambda: bench.base.run_mihomo(rows, args.workers, args.timeout),
    )

    report = {
        "schema": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sample_requested": args.limit,
        "sample_loaded": len(rows),
        "sample_sha256": sample_hash,
        "same_sample_for_engines": True,
        "workers": args.workers,
        "timeout_s": args.timeout,
        "probes": {
            "primary": "http://www.msftconnecttest.com/connecttest.txt",
            "secondary": "http://www.gstatic.com/generate_204",
        },
        "engines": [xray, mihomo],
    }
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for e in report["engines"]:
        print(json.dumps({
            "engine": e.get("engine"), "status": e.get("status"),
            "candidates": e.get("candidates"), "compatible": e.get("compatible"),
            "tested": e.get("tested"), "healthy": e.get("healthy"),
            "nodes_per_sec": e.get("nodes_per_sec"), "probe_elapsed_s": e.get("probe_elapsed_s"),
            "elapsed_s": e.get("elapsed_s"), "resources": e.get("resource_metrics"),
        }, ensure_ascii=False))


if __name__ == "__main__":
    main()
