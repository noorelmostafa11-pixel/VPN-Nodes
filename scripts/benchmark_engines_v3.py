#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

import benchmark_engines_v2 as base

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
SAMPLE = OUT / "metadata" / "benchmark_sample.txt"


def freeze_sample(limit: int) -> list[str]:
    rows = base.load_same_sample(limit)
    if len(rows) < limit:
        raise SystemExit(f"sample contains only {len(rows)} nodes; requested {limit}")
    SAMPLE.parent.mkdir(parents=True, exist_ok=True)
    SAMPLE.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return rows


def xray_test_config(cfg: Path) -> tuple[bool, str]:
    # Xray does not accept `run -test`; `-test` is a top-level flag.
    r = subprocess.run([str(base.XRAY), "-test", "-config", str(cfg)], text=True, capture_output=True, timeout=30)
    return r.returncode == 0, (r.stderr or r.stdout or "")[-1800:]


def valid_xray_indices(uris: list[str]) -> tuple[list[int], list[dict]]:
    # Validate each URI independently. This keeps one bad config from invalidating
    # an otherwise usable multi-outbound Xray benchmark configuration.
    valid: list[int] = []
    failed: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="xray-preflight-") as td:
        for idx, uri in enumerate(uris):
            try:
                tag = f"p{idx+1}"
                inbound = f"in{idx+1}"
                out = base.xray_outbound(uri, tag)
                cfg = Path(td) / f"xray-{idx}.json"
                cfg.write_text(
                    json.dumps({
                        "log": {"loglevel": "error"},
                        "inbounds": [{
                            "listen": "127.0.0.1",
                            "port": base.BASE_PORT,
                            "protocol": "socks",
                            "settings": {"udp": False},
                            "tag": inbound,
                        }],
                        "outbounds": [out],
                        "routing": {
                            "domainStrategy": "AsIs",
                            "rules": [{"type": "field", "inboundTag": [inbound], "outboundTag": tag}],
                        },
                    }),
                    encoding="utf-8",
                )
                ok, err = xray_test_config(cfg)
                if ok:
                    valid.append(idx)
                else:
                    failed.append({"index": idx, "reason": err or "xray config rejected"})
            except Exception as exc:
                failed.append({"index": idx, "reason": str(exc)[:800]})
    return valid, failed


def run_xray(uris: list[str], workers: int, timeout: float) -> dict:
    start = time.perf_counter()
    compatible, failed = valid_xray_indices(uris)
    if not compatible:
        return {
            "engine": "xray", "status": "no_compatible_nodes", "candidates": len(uris),
            "compatible": 0, "tested": 0, "healthy": 0, "parse_or_config_failed": failed,
            "elapsed_s": round(time.perf_counter() - start, 2),
        }
    with tempfile.TemporaryDirectory(prefix="bench-xray-") as td:
        ins, outs, rules = [], [], []
        for pos, idx in enumerate(compatible):
            tag = f"p{idx+1}"; it = f"in{idx+1}"
            outs.append(base.xray_outbound(uris[idx], tag))
            ins.append({"listen": "127.0.0.1", "port": base.BASE_PORT + pos, "protocol": "socks", "settings": {"udp": False}, "tag": it})
            rules.append({"type": "field", "inboundTag": [it], "outboundTag": tag})
        cfg = Path(td) / "c.json"
        cfg.write_text(json.dumps({"log": {"loglevel": "error"}, "inbounds": ins, "outbounds": outs, "routing": {"domainStrategy": "AsIs", "rules": rules}}), encoding="utf-8")
        ok, err = xray_test_config(cfg)
        if not ok:
            return {"engine": "xray", "status": "failed_to_start", "candidates": len(uris), "compatible": len(compatible), "tested": 0, "healthy": 0, "parse_or_config_failed": failed, "stderr": err, "elapsed_s": round(time.perf_counter() - start, 2)}
        p = subprocess.Popen([str(base.XRAY), "run", "-config", str(cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if compatible and not base.wait_port(base.BASE_PORT, 10):
            p.kill(); p.wait()
            return {"engine": "xray", "status": "failed_to_start", "candidates": len(uris), "compatible": len(compatible), "tested": 0, "healthy": 0, "parse_or_config_failed": failed, "stderr": "base inbound did not listen", "elapsed_s": round(time.perf_counter() - start, 2)}
        r = base.probe_many(compatible, workers, timeout)
        p.terminate()
        try: p.wait(3)
        except subprocess.TimeoutExpired: p.kill()
    return {"engine": "xray", "status": "ok", "candidates": len(uris), "compatible": len(compatible), **r, "elapsed_s": round(time.perf_counter() - start, 2), "parse_or_config_failed": failed}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=500)
    ap.add_argument("--workers", type=int, default=80)
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--out", default=str(OUT / "metadata" / "engine_benchmark.json"))
    a = ap.parse_args()
    rows = freeze_sample(a.limit)
    frozen_hash = hashlib.sha256(("\n".join(rows) + "\n").encode()).hexdigest()
    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sample_requested": a.limit, "sample_loaded": len(rows),
        "sample_file": str(SAMPLE.relative_to(ROOT)), "sample_sha256": frozen_hash,
        "same_sample_for_all_engines": True, "workers": a.workers, "timeout_s": a.timeout,
        "probes": {"primary": "http://www.msftconnecttest.com/connecttest.txt", "secondary": "http://www.gstatic.com/generate_204"},
        "engines": [run_xray(rows, a.workers, a.timeout), base.run_sing(rows, a.workers, a.timeout), base.run_mihomo(rows, a.workers, a.timeout)],
    }
    out = Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"sample_sha256": frozen_hash, "sample_file": str(SAMPLE)}, ensure_ascii=False))
    for e in report["engines"]:
        print(json.dumps({k: e.get(k) for k in ("engine", "status", "candidates", "compatible", "tested", "healthy", "msft_ok", "google_204_ok", "nodes_per_sec", "probe_elapsed_s", "elapsed_s")}, ensure_ascii=False))

if __name__ == "__main__":
    main()
