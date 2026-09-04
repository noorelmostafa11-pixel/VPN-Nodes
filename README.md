# VPN-Nodes

Public node catalog builder for the Android VPN client.

## Pipeline

```text
sources.json + Telegram + v2nodes
        -> parse / normalize / semantic deduplicate
        -> TCP reachability on ports 53/80/443/853/8008 (512 workers)
        -> country resolution and latency ordering
        -> output/countries/<CC>.txt (backwards-compatible full feed)
        -> output/country_shards/<CC>/<NNN>.txt (1,000 nodes per signed shard)
        -> Android Xray + real-traffic validation
```

The repository deliberately stops at TCP reachability. It does not run transport
handshakes or Xray compatibility checks; the Android app owns the final runtime
test and learns real transfer speed over successful connections.

## Repository layout

- `sources/` — maintained source lists.
- `scripts/` — current catalog pipeline plus Oracle automation support.
- `data/` — GeoLite2 Country database and catalog signing public key.
- `output/countries/` — canonical full country feeds kept for backwards compatibility.
- `output/country_shards/` — small ordered country chunks fetched on demand by current Android clients.
- `output/protocols/` — protocol-specific feeds.
- `output/metadata/` — compact catalog/index/signing metadata.
- `.github/workflows/update.yml` — catalog workflow; intentionally `workflow_dispatch` only.
- `.github/workflows/update_geolite2.yml` — GeoLite2 refresh on the 1st and 15th of each month, plus manual dispatch.

## Scheduling

The catalog workflow intentionally has no GitHub cron. An external Oracle server
schedules the hourly refresh and sends `workflow_dispatch` using its own GitHub
credential. No scheduler token or private credential is stored in this repository.

## On-demand country downloads

Country order remains exactly the same as the latency-ranked full feed. Current
Android clients download one signed 1,000-node shard at a time and continue to
the next shard only when needed. Older clients can continue to use the full
`output/countries/<CC>.txt` files.

## Generated intermediates

Collector and TCP intermediate JSON files exist only during a workflow run and
are ignored by Git. They are not part of the published repository.

## Catalog semantics

`TCP alive` only means the advertised endpoint accepted a TCP connection when
the catalog was generated. VLESS/VMess/Trojan/Shadowsocks correctness and Internet
access are verified later by Xray inside the Android application.
