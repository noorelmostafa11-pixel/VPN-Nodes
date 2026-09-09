# VPN-Nodes

Public node catalog builder for the Android VPN client.

## Pipeline

```text
sources.json + Telegram + v2nodes
        -> parse / normalize / semantic deduplicate
        -> source freshness competition (72 hours; always rechecked)
        -> TCP reachability on port 443 (512 workers)
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
Android clients download one signed 1,000-node shard at a time and continue
to the next shard only when needed. Older clients can continue to use the full
`output/countries/<CC>.txt` files.

## Source freshness

Every configured source is downloaded and checked on every run. A source whose
semantic node set has not changed for more than 72 hours is temporarily excluded
from the competition, but it is not forgotten or disabled. As soon as its node
set changes, it automatically re-enters in that same run. When two sources are
exact mirrors, only the first copy competes while both continue to be monitored.

This policy changes only which candidates reach the existing catalog. Android
URLs, country feeds, signed shard paths, protocol feeds, manifest schema,
signature algorithm and catalog public key remain unchanged.

## Generated intermediates

Collector and TCP intermediate JSON files exist only during a workflow run and
are ignored by Git. They are not part of the published repository.

## Catalog semantics

`TCP alive` only means the advertised endpoint accepted a TCP connection on port
443 when the catalog was generated. VLESS/VMess/Trojan/Shadowsocks correctness
and Internet access are verified later by Xray inside the Android application.
