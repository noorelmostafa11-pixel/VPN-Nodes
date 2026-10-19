
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

Retired official-downloader, Python engine, execution and repair modules were
removed. Pure legacy identity/parser helpers remain for their existing offline
regressions and standalone identity tooling, outside the production decision path.

Local validation: owned-core integration/coverage/provenance checks, country
publication and ordering checks, source/freshness/identity regressions, workflow
syntax checks, Windows/Linux core compilation and a synthetic loopback core
check. No public node scan or workflow dispatch was performed. Run the workflow
manually to produce a new verified catalog and real-run diagnostics.
