
# VPN-Nodes: catalog verified by the owner's core

`Update node catalog` runs daily at **04:00 and 16:00 UAE time** (00:00 and
12:00 UTC), and can also be started manually. Each run collects current sources
and builds the selected ref of `noorelmostafa11-pixel/VPN-Core-Test` once. The default
`core_ref` is `main`; it is resolved to one commit and a SHA256-identified Linux
binary shared by all eight check shards. No official Xray binary is downloaded.

Scheduled runs perform the full collection, core connectivity check, download measurement,
and signed publication pipeline using the latest core `main`. The schedule does
not depend on an external server or push. GitHub may delay scheduled starts under
load; the configured times are not a guaranteed exact start time.

The existing fast TCP precheck is retained: each shared host/port is tested once,
and unavailable TCP endpoints are removed before the expensive core check.
Explicit UDP transports (KCP, QUIC, Hysteria transport and QUIC plugins), including
HTTP/3 hints, bypass that TCP gate and go directly to the core. The source
collectors' existing port policy (currently 443) is preserved. TCP success alone
never qualifies a node for publication.

Each shard uses the core's original URI parser and `nodecheck` engine with
64 workers, a six-second node deadline and two-second target deadlines. Targets
are the same Google, Microsoft, Cloudflare and example.com defaults as the core
test repository. Any authenticated final HTTPS response with status 200–599
proves reachability, including 403/429/500. Failures retain phase/error details.
The original candidate link is published only after that link passed; Python
does not convert connection settings or repair rejected links.

Country enrichment runs only after PASS through that same core handler. The
existing `VPN_COUNTRY_URL` secret supplies the country service; a missing country
may fall back to an exit-IP request, local GeoLite2, then the existing entry-host
lookup, finally XX. A separate four-second enrichment budget cannot change a
proven node to failed. Private metadata URLs and bodies are omitted from reports.

Country feeds, 1000-node country shards, protocol feeds, metadata file paths,
ECDSA manifest schema and signing key are preserved for the Android app. The
existing `CATALOG_SIGNING_PRIVATE_KEY_B64` secret is still required to publish.
`VPN_TEST_URL` is no longer used. Legacy `xray_*` metadata names remain for
compatibility; the new `core` object identifies the actual owned source/binary.
Counters distinguish TCP-passed candidates from UDP bypasses.

Shard artifacts retain `nodecheck/results.jsonl`, `failures.jsonl`, `summary.json`
and `summary.md` for seven days. The publisher refuses incomplete, mismatched,
foreign-core or empty results. It preserves source links, country ordering,
deduplication after verification and the existing signed publication process.
The current committed catalog stays intact until a successful manual refresh.

After merging successful shards, publication additionally uses the core's optional
`connection_key` (`xray-outbound-v1:<SHA256>`). The core fingerprints the complete
built outbound, excluding its display/runtime tag, and canonicalizes nested
protobuf settings. Publication keeps the first successful original link in
candidate order; endpoint, credentials, transport, TLS and every built setting
remain part of the identity. It does not use the legacy Python parser to guess
equivalence, and it does not change prechecks, connectivity verdicts, country
sorting or the application's Saved keys.

Reports without a connection key retain the previous exact/before-fragment
checks. `app_pool.json` separately records semantic duplicates removed and
successful identity coverage, including missing keys. Duplicate successes remain
counted as successful tests. The new behavior is automatic with the next manual
run using the updated core and publisher; existing published feeds are not rewritten.

Retired official-downloader, Python engine, execution and repair modules were
removed. Pure legacy identity/parser helpers remain for their existing offline
regressions and standalone identity tooling, outside the production decision path.

Local validation: owned-core integration/coverage/provenance checks, country
publication and ordering checks, source/freshness/identity regressions, workflow
syntax checks, Windows/Linux core compilation and a synthetic loopback core
check. No public node scan or workflow dispatch was performed. Run the workflow
manually to produce a new verified catalog and real-run diagnostics.

### Country ordering by a fixed download sample

The workflow prepares the exact successful, connection-deduplicated
set, then runs eight speed jobs with four simultaneous nodes each (32 maximum).
The separate `scripts/xray_matrix/node_speed.go` tool belongs to this repository.
It is compiled once from the selected core's module directory and uses that
unchanged core library's URI resolver, outbound handlers and dispatcher. The
helper binary, helper source revision and linked core revision are recorded in
the same build artifact. No command or API is added to VPN-Core-Test or its AAR.

Each connection receives one verified HTTPS download request to
`https://speed.cloudflare.com/__down?bytes=1048576`, with an eight-second total
deadline. Only a complete, uncompressed 1 MiB response with verified target TLS
and HTTP 200 receives a score. The estimate uses bits divided by the interval
from the first response byte through sample completion, excluding tunnel/TLS
startup; startup latency is recorded separately. No redirects or retries occur.
Worker processes recycle after bounded batches to release core transport caches.

Country files and their matching country shards put measured download rates
first, descending; ties retain verified HTTPS-delay ordering. Unmeasured nodes
remain published after measured nodes, with the previous HTTPS-delay order.
Missing speed jobs also retain their assigned nodes. Protocol feeds keep their
original source order. Connectivity PASS, deduplication, country assignment,
original URI text, credentials and the app's Saved behavior do not change.

`output/metadata/node_speeds.json` contains credential-free per-node scores and
failure codes and is included in the existing signed catalog manifest. The
catalog summary reports measured/unmeasured counts and missing speed shards.
This is one sample from GitHub runners at that time, not a guarantee of a
phone's download speed. It adds sample traffic and elapsed time; the owner
continues to dispatch the workflow manually.

# Resume catalog publication

If scanning completed but publication failed, run **Update node catalog** on `main`
with `publish_run_id` set to the completed source run ID. Leave this input empty
for the normal collection, connectivity check, and download measurement pipeline.

Recovery downloads that run's saved candidates, all eight checker shards, and
its speed pool/observations; it does not build the core or contact proxy nodes.
The source run and unchanged catalog/finalizer/signing contract are checked before
the existing catalog validation and signature steps. Expired/missing required
artifacts fail publication rather than silently losing results.

Both catalog and GeoLite2 publication preserve the latest unrelated changes on
`main`, use a fresh explicit Git lease, and retry a moved branch up to three times.
A newer payload of the same kind is retained instead of being replaced by stale
results. The existing rolling-output history policy remains in effect.
