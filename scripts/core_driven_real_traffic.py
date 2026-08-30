#!/usr/bin/env python3
"""Run the exact node_debug_batch_v2 connection path used in the successful laptop test."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import tempfile
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POOL_FILE = ROOT / "output" / "metadata" / "tcp_reachable.json"
SOURCE_DIR = ROOT / "scripts" / "_exact_core_source"
EXPECTED_SHA256 = "69d0fc121e3ba583b81a1cc1c4e7d6b05ce4ad1609dfbce3828c14fd95e13e41"
WORKERS = max(1, min(int(os.environ.get("REAL_DELAY_WORKERS", "250")), 250))
SOCKS_BASE = int(os.environ.get("REAL_DELAY_SOCKS_BASE", "21080"))
TCP_TIMEOUT = float(os.environ.get("REAL_DELAY_TCP_TIMEOUT", "8"))
TRAFFIC_TIMEOUT = float(os.environ.get("REAL_DELAY_NODE_TIMEOUT", "10"))


def load_exact_tester():
    chunks = [SOURCE_DIR / f"{i:02d}" for i in range(1, 6)]
    encoded = "".join(path.read_text(encoding="utf-8").strip() for path in chunks)
    source = zlib.decompress(base64.b64decode(encoded)).decode("utf-8")
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(f"Exact tester integrity check failed: {digest}")
    path = Path(tempfile.gettempdir()) / "node_debug_batch_v2_exact.py"
    path.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("node_debug_batch_v2_exact", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load exact validated tester")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.SOCKS_BASE_PORT = SOCKS_BASE
    module.TCP_TIMEOUT = TCP_TIMEOUT
    module.TRAFFIC_TIMEOUT = TRAFFIC_TIMEOUT
    return module


def resolve_country(items):
    import country_resolver
    rows = []
    for item in items:
        try:
            node = item["tester"].parse_node(item["uri"])
        except Exception:
            node = {}
        rows.append({
            "uri": item["uri"],
            "server": node.get("server") or item["result"].get("address") or "",
            "address": node.get("server") or item["result"].get("address") or "",
            "port": node.get("port") or item["result"].get("port"),
            "remark": urllib.parse.unquote(urllib.parse.urlsplit(item["uri"]).fragment or ""),
            "country": "UNKNOWN",
        })
    resolution = country_resolver.resolve_rows(rows) if rows else {"hostname": 0, "geoip_local": 0, "unknown": 0, "database_loaded": False}
    for item, row in zip(items, rows):
        item["country"] = row.get("country") or "UNKNOWN"
        item["country_resolution"] = row.get("country_resolution") or "unknown"
    return resolution


def publish(items):
    out = ROOT / "output"
    dirs = {k: out / k for k in ("countries", "active", "backup", "protocols", "metadata")}
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    for k in ("countries", "active", "backup", "protocols"):
        for p in dirs[k].glob("*.txt"):
            p.unlink()

    groups = {"active": {}, "backup": {}}
    for item in items:
        kind = "active" if item["result"].get("status") == "PASS" else "backup"
        country = str(item.get("country") or "UNKNOWN").upper()
        groups[kind].setdefault(country, []).append(item)

    for kind in groups:
        for country, rows in groups[kind].items():
            rows.sort(key=lambda x: (x["result"].get("diagnostic_latency_ms", 10**9), x["result"].get("tcp_ms", 10**9), x["result"].get("index", 10**9)))
            (dirs[kind] / f"{country}.txt").write_text("\n".join(x["uri"] for x in rows) + "\n", encoding="utf-8")

    for country in sorted(set(groups["active"]) | set(groups["backup"])):
        rows = groups["active"].get(country, []) + groups["backup"].get(country, [])
        (dirs["countries"] / f"{country}.txt").write_text("\n".join(x["uri"] for x in rows) + "\n", encoding="utf-8")

    protocols = {}
    for item in items:
        try:
            proto = item["tester"].parse_node(item["uri"])["protocol"]
            protocols.setdefault(proto, []).append(item["uri"])
        except Exception:
            pass
    for proto, lines in protocols.items():
        (dirs["protocols"] / f"{proto}.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    if not POOL_FILE.is_file():
        raise SystemExit(f"TCP pool not found: {POOL_FILE}")
    tester = load_exact_tester()
    xray = str(Path(os.environ.get("XRAY_BIN", "/opt/hostedtoolcache/xray/xray")).resolve())
    if not Path(xray).is_file():
        raise SystemExit(f"Xray not found: {xray}")

    payload = json.loads(POOL_FILE.read_text(encoding="utf-8"))
    uris, seen = [], set()
    for row in payload.get("nodes", []):
        uri = str(row.get("uri") or "").strip()
        if not uri or uri in seen:
            continue
        try:
            node = tester.parse_node(uri)
        except Exception:
            continue
        if int(node.get("port", 0)) not in (80, 443):
            continue
        seen.add(uri)
        uris.append(uri)

    print(f"INFO tcp_candidates={len(uris)} workers={WORKERS}")
    print("INFO health_path=parse->dns->tcp->xray_config_validation->xray_start->local_socks5->real_xray_tunnel->strict_https->diagnostic_https")

    results = []
    counters = {"PASS": 0, "WORKS_BUT_CERT_INVALID": 0, "REAL_TRAFFIC_FAILED": 0, "OTHER_FAILED": 0}
    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = {executor.submit(tester.test_one, i, uri, xray, SOCKS_BASE + i - 1): (i, uri) for i, uri in enumerate(uris, 1)}
        finished = 0
        for future in as_completed(futures):
            idx, uri = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {"index": idx, "protocol": "", "address": "", "port": None, "tcp_ms": -1.0, "status": "OTHER_FAILED", "reason": f"worker exception: {exc}", "strict_ok": False, "diagnostic_ok": False, "diagnostic_latency_ms": -1.0}
            results.append({"uri": uri, "result": result, "tester": tester})
            status = result.get("status", "OTHER_FAILED")
            counters[status] = counters.get(status, 0) + 1
            finished += 1
            if finished % 100 == 0 or finished == len(uris):
                print(f"INFO real_progress={finished}/{len(uris)} PASS={counters['PASS']} CERT={counters['WORKS_BUT_CERT_INVALID']} FAIL={counters['REAL_TRAFFIC_FAILED']} OTHER={counters['OTHER_FAILED']}")

    resolution = resolve_country(results)
    publish(results)
    metadata = {
        "schema": 16,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": "exact_local_node_debug_batch_v2",
        "tcp_candidates": len(uris),
        "deep_checked": len(results),
        "pass": counters["PASS"],
        "works_but_cert_invalid": counters["WORKS_BUT_CERT_INVALID"],
        "real_traffic_failed": counters["REAL_TRAFFIC_FAILED"],
        "other_failed": counters["OTHER_FAILED"],
        "published_total": counters["PASS"] + counters["WORKS_BUT_CERT_INVALID"],
        "workers": WORKERS,
        "allowed_ports": [80, 443],
        "health_path": "parse->dns->tcp->xray_config_validation->xray_start->local_socks5->real_xray_tunnel->strict_https->diagnostic_https",
        "country_policy": "Automatic country resolution from successful nodes only; no fixed country allowlist.",
        "country_resolution": resolution,
    }
    (ROOT / "output" / "metadata" / "core_driven_health.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"INFO FINAL PASS={counters['PASS']} CERT={counters['WORKS_BUT_CERT_INVALID']} FAILED={counters['REAL_TRAFFIC_FAILED']} OTHER={counters['OTHER_FAILED']} TOTAL={len(results)} PUBLISHED={metadata['published_total']}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
