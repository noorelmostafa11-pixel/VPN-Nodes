#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "output"
META = OUT / "metadata"


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"invalid JSON object: {path}")
    return value


def lines(path: Path) -> list[str]:
    return [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def main() -> int:
    app = read_json(META / "app_pool.json")
    countries = read_json(META / "countries.json")
    index = read_json(META / "index.json")

    if app.get("mode") != "xray_26_9_9_real_https_verified":
        raise SystemExit(f"unexpected mode: {app.get('mode')}")
    if int(app.get("xray_matrix_shards") or 0) != 15:
        raise SystemExit("matrix must contain exactly 15 shards")
    if int(app.get("xray_workers_per_runner") or 0) != 40:
        raise SystemExit("each runner must use exactly 40 workers")
    if int(app.get("xray_total_concurrency") or 0) != 600:
        raise SystemExit("total Xray concurrency must be 600")
    if app.get("country_policy") != "endpoint_first; exit_ip GeoLite2 only for successful XX":
        raise SystemExit("unexpected country policy")

    tested = int(app.get("xray_tested_total") or 0)
    tcp = int(app.get("tcp_reachable_total") or 0)
    published = int(app.get("published_total") or 0)
    if tested <= 0 or tested != tcp:
        raise SystemExit(f"coverage mismatch tcp={tcp} tested={tested}")
    if published <= 0 or published > tested:
        raise SystemExit(f"invalid published count: {published}/{tested}")
    if int(index.get("published_total") or -1) != published:
        raise SystemExit("legacy index published_total mismatch")
    if index.get("generated_at") != app.get("generated_at"):
        raise SystemExit("legacy index generated_at mismatch")

    endpoint_counts = app.get("xray_success_endpoints") or {}
    if not isinstance(endpoint_counts, dict):
        raise SystemExit("invalid xray_success_endpoints")
    unexpected_endpoints = set(endpoint_counts) - {"google", "microsoft"}
    if unexpected_endpoints:
        raise SystemExit(f"unexpected success endpoints: {sorted(unexpected_endpoints)}")
    google_success = int(endpoint_counts.get("google") or 0)
    microsoft_success = int(endpoint_counts.get("microsoft") or 0)
    xray_working = int(app.get("xray_working_total") or 0)
    if google_success + microsoft_success != xray_working:
        raise SystemExit("success endpoint totals do not match xray_working_total")
    if (index.get("xray_success_endpoints") or {}) != endpoint_counts:
        raise SystemExit("legacy index success endpoint totals mismatch")

    for protocol, row in (app.get("test_summary") or {}).items():
        if not isinstance(row, dict):
            raise SystemExit(f"invalid test summary for {protocol}")
        protocol_endpoints = row.get("success_endpoints") or {}
        if sum(int(v) for v in protocol_endpoints.values()) != int(row.get("working") or 0):
            raise SystemExit(f"protocol success endpoint accounting mismatch: {protocol}")

    country_meta = {str(x.get("code") or "").upper(): x for x in countries.get("countries", [])}
    country_files = sorted((OUT / "countries").glob("*.txt"))
    if not country_files:
        raise SystemExit("no country files")

    country_total = 0
    country_raw: list[str] = []
    shard_total = 0
    for path in country_files:
        code = path.stem.upper()
        values = lines(path)
        if not values:
            raise SystemExit(f"empty country file: {path}")
        country_total += len(values)
        country_raw.extend(values)
        meta = country_meta.get(code)
        if not isinstance(meta, dict):
            raise SystemExit(f"missing country metadata: {code}")
        if int(meta.get("nodes") or -1) != len(values):
            raise SystemExit(f"country count mismatch: {code}")
        shards = sorted((OUT / "country_shards" / code).glob("*.txt"))
        rebuilt: list[str] = []
        for shard in shards:
            part = lines(shard)
            if not part or len(part) > 1000:
                raise SystemExit(f"invalid shard: {shard}")
            rebuilt.extend(part)
        if rebuilt != values:
            raise SystemExit(f"shard reassembly mismatch: {code}")
        if int(meta.get("shards") or -1) != len(shards):
            raise SystemExit(f"shard count mismatch: {code}")
        shard_total += len(shards)

    if country_total != published:
        raise SystemExit(f"country total mismatch: {country_total}/{published}")
    if len(country_raw) != len(set(country_raw)):
        raise SystemExit("exact duplicate raw node found in country publication")

    protocol_files = {
        "vless": OUT / "protocols" / "vless.txt",
        "vmess": OUT / "protocols" / "vmess.txt",
        "trojan": OUT / "protocols" / "trojan.txt",
        "ss": OUT / "protocols" / "shadowsocks.txt",
    }
    protocol_raw: list[str] = []
    for protocol, path in protocol_files.items():
        if not path.is_file():
            raise SystemExit(f"missing protocol file: {path}")
        vals = lines(path)
        protocol_raw.extend(vals)
        expected = int((app.get("protocols") or {}).get(protocol, -1))
        if len(vals) != expected:
            raise SystemExit(f"protocol count mismatch: {protocol}")
    if len(protocol_raw) != published:
        raise SystemExit("protocol total mismatch")
    if set(protocol_raw) != set(country_raw):
        raise SystemExit("country/protocol publication sets differ")

    geo = app.get("geoip_xx_fallback") or {}
    if geo.get("scope") != "working_xx_only":
        raise SystemExit("GeoIP scope must be working_xx_only")
    attempted = int(geo.get("attempted") or 0)
    classified = int(geo.get("classified") or 0)
    unresolved = int(geo.get("unresolved") or 0)
    if attempted != classified + unresolved:
        raise SystemExit("GeoIP fallback accounting mismatch")
    if attempted != int(geo.get("exit_ip_available") or 0) + int(geo.get("exit_ip_missing") or 0):
        raise SystemExit("exit IP fallback accounting mismatch")

    print(
        f"OK FINAL_CATALOG tested={tested} published={published} "
        f"countries={len(country_files)} shards={shard_total} "
        f"google={google_success} microsoft={microsoft_success} "
        f"geoip_xx_attempted={attempted} geoip_xx_unresolved={unresolved}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
