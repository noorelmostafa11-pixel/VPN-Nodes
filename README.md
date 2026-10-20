
# VPN-Nodes: catalog verified by the owner's core

`Update node catalog` remains manual. Each run collects current sources and
builds the selected ref of `noorelmostafa11-pixel/VPN-Core-Test` once. The default
`core_ref` is `main`; it is resolved to one commit and a SHA256-identified Linux
binary shared by all eight check shards. No official Xray binary is downloaded.

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

### Country ordering by Real Delay

The manual workflow prepares this run's exact successful, connection-deduplicated
set, then runs eight Real Delay jobs with four simultaneous nodes each (32 max).
The separate `scripts/xray_matrix/node_delay.go` tool belongs to VPN-Nodes and
links the same selected core library. Core source, commands, SDK and AAR stay
unchanged. Both tool/core revisions and binary hashes are recorded.

Like v2rayN 7.25.6 Real Ping, each node gets two lightweight HTTPS GETs using one
HTTP client, with 100 ms between requests. The minimum complete-request time is
reported in milliseconds, outside node import/build/startup. Keep-alive is enabled
so the second request can reuse its connection when the target permits it. Target:
`https://www.google.com/generate_204`, matching the owner's v2rayN configuration.
The two requests share a five-second node budget. There is no 1 MiB download,
transfer-rate calculation, download endpoint, redirect following or retry phase.

For trustworthy ranking we additionally require verified target TLS, complete
2xx responses and at most 64 KiB per response (normally an empty 204). A failure
makes only the delay unavailable: it never removes a previously successful node.
This is the same Real Ping timing principle, not a byte-for-byte v2rayN clone;
v2rayN does not apply these same response-status/body bounds.

Country files and matching country shards put measured delays first, ascending.
Ties and unavailable measurements retain the previous verified HTTPS-delay order.
Missing delay jobs also retain all their nodes. Connectivity PASS, complete
connection deduplication, original URI text, country assignment, protocol-feed
source order, credentials, catalog signing and the application's Saved behavior
are unchanged. The input is always from this run, not a previous catalog.

`output/metadata/node_delays.json` stores credential-free delay values, both
request receipts and failure codes, and is included in the existing signed
manifest. Previous download-score metadata remains verifiable for old catalogs;
the next publication removes that old score file. Real Delay estimates response
latency from GitHub's network. It does not guarantee download throughput or the
same ordering/numbers on a phone or another network. The owner runs the workflow.

Reference: [v2rayN 7.25.6 GetRealPingTime](https://github.com/2dust/v2rayN/blob/1883178b5f1e222b6c6db2782e7a3d989b7cc18f/v2rayN/ServiceLib/Handler/ConnectionHandler.cs#L63).
# Resume catalog publication

If scanning completed but publication failed, run **Update node catalog** on `main`
with `publish_run_id` set to the completed source run ID. Leave this input empty
for the normal collection, connectivity check, and Real Delay pipeline.

Recovery downloads that run's saved candidates, all eight checker shards, and
its delay pool/observations; it does not build the core or contact proxy nodes.
The source run and unchanged catalog/finalizer/signing contract are checked before
the existing catalog validation and signature steps. Expired/missing required
artifacts fail publication rather than silently losing results.

Both catalog and GeoLite2 publication preserve the latest unrelated changes on
`main`, use a fresh explicit Git lease, and retry a moved branch up to three times.
A newer payload of the same kind is retained instead of being replaced by stale
results. The existing rolling-output history policy remains in effect.
