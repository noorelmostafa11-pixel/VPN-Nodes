# VPN-Nodes

Collects proxy-node links, verifies connectivity through the pinned VPN-Core source, and publishes signed country and protocol catalogs.

## Run

Run **Actions → Update node catalog → Run workflow** on `main`.

- `core_ref`: core branch or revision to resolve once for the complete run; defaults to `main`.
- `publish_run_id`: leave empty for a fresh catalog, or provide a completed run ID for publication recovery.

The current catalog workflow is manually dispatched. It has no native schedule or external-server dependency.

## Collection and connectivity

Collectors retain complete source links, including encoded and structured connection fields. The existing collection port policy remains 443. Shared TCP host/port checks run once per endpoint; explicit UDP transports bypass the TCP gate. TCP success alone does not qualify a node for publication.

The workflow builds the selected core once and shares its exact revision, binary hashes and candidate snapshot across eight checker shards. Each shard uses 64 workers, a six-second node deadline and two-second target deadlines. The four shared HTTPS destinations are Google `generate_204`, Microsoft `robots.txt`, Cloudflare `cdn-cgi/trace` and `example.com`.

The canonical core repository is `noorelmostafa11-pixel/VPN-Core`. Stored core
provenance also accepts its former name, `noorelmostafa11-pixel/VPN-Core-Test`,
with the same pinned-source, binary and snapshot checks. Publication recovery
still requires an unchanged finalizer/signing contract and a valid source run.

A verified final HTTPS response with status 200–599 establishes connectivity. The original URI must pass through the core's own parser and outbound handler. Collection and publication do not silently rewrite rejected connection settings.

Country enrichment runs after connectivity success through the same handler, with its own bounded budget. Metadata lookup failures do not remove proven connections. Country assignment can fall back through the existing exit-IP, GeoLite2 and entry-host lookup paths, then `XX`.

## Deduplication and publication

Successful nodes are deduplicated using the core-built connection identity when available. The identity includes endpoint, credentials, transport, TLS and all effective connection settings; display names do not create distinct connections. The first successful original link is retained in source order. Reports without a connection key keep the existing exact-link checks.

Country feeds, 1000-node country shards, protocol feeds and metadata remain compatible with the signed Android catalog format. Publication requires the configured signing key. The last valid catalog remains available if a refresh fails.

Required repository secrets include `CATALOG_SIGNING_PRIVATE_KEY_B64` and `VPN_COUNTRY_URL`. Configure their values through repository secrets; their contents are not published in reports.

## Download ranking

Ranking runs after connectivity and connection deduplication. The Go helper in `scripts/xray_matrix/node_speed.go` links the same pinned core library; it does not add a core or Android SDK API.

There are eight speed shards with four concurrent nodes each, at most 32 measurements in parallel. Each node has one eight-second total budget:

1. Request a complete 1 MiB sample from `https://speed.cloudflare.com/__down?bytes=1048576`, with the primary attempt capped at five seconds.
2. If that attempt fails and time remains, request bytes `0–1048575` from `https://proof.ovh.net/files/10Mb.dat` through the same core outbound.

Both paths require verified HTTPS and uncompressed data. The primary requires HTTP 200 and the complete fixed-size response. The fallback requires HTTP 206, the exact 1 MiB content length and a valid matching `Content-Range`. It uses only the time remaining from the original eight-second budget. Redirects are not followed.

The score is sample bits divided by the interval from the first response byte to sample completion. Startup latency is recorded separately. The selected target and fallback use remain identifiable in measurement metadata. These are observations from the runner's network and measurement time, not a guarantee of performance on another connection.

Country files and their matching shards put measured rates first, descending. Ties retain verified HTTPS-delay ordering. Unmeasured nodes, including nodes assigned to missing speed jobs, remain published after measured nodes. Protocol feeds retain source order. A speed-measurement failure does not change connectivity eligibility.

`output/metadata/node_speeds.json` contains credential-free per-node observations and is included in the signed catalog manifest. Summaries record measured and unmeasured counts, policy and missing shards.

## Recover publication

If scanning completed but publication failed, rerun **Update node catalog** with `publish_run_id` set to the source run. Recovery reuses saved candidates, checker shards and speed observations. It does not rebuild the core or rescan nodes.

Recovery validates source-run provenance, complete checker coverage and the catalog/finalizer/signing contract. Missing or expired required artifacts stop recovery instead of silently dropping nodes.

Catalog and GeoLite2 publishers fetch the latest `main`, overlay only their intended generated payload and use an explicit Git lease. They retry branch movement at most three times, preserve unrelated changes and refuse stale replacement of a newer payload of the same kind.

## Reports and development

Checker artifacts include per-node results, failures and summaries. Source URIs remain in the intended node feeds and input artifacts; diagnostic metadata omits credentials and private service bodies. Checker artifacts are retained for seven days.

The `Validate speed fallback` workflow covers changes to speed-related source and tests on pull requests. It does not dispatch the catalog workflow. Historical validation records under `docs/` describe their recorded source revisions and environments.
