# Replace download ranking with Real Delay

Date: 2026-10-20. VPN-Nodes starting revision:
`7dca5ac050ffe2235c87ba9602b748f81471f9c0`.
Unchanged core used locally: `d0c467ec209652a977874cd3a078f88d9ab78044`.

The owner requested the latency ordering shown in v2rayN instead of the optional
1 MiB download stage. v2rayN 7.25.6 source was checked at its exact tag commit
`1883178b5f1e222b6c6db2782e7a3d989b7cc18f`, ConnectionHandler.GetRealPingTime:
two GETs using one HTTP client, 100 ms between requests, and the minimum positive
elapsed request time. The owner's configured test URL was read without changing
the application: `https://www.google.com/generate_204`.

The same timing principle is now implemented entirely in VPN-Nodes. Each node
uses a unique tagged outbound through the pinned core and a dedicated HTTP
transport with keep-alive. Import/build/startup is outside request timers; both
requests share a five-second deadline. Eight jobs, each with four node workers,
remain the concurrency limit. There is no active bandwidth download/score path.

Differences from v2rayN are deliberate evidence bounds: require verified target
TLS, complete 2xx responses and no more than 64 KiB per response, with no redirects
or retries. The normal target returns an empty 204. A failed measurement retains
the original successful node, after measured nodes. This ranks response latency
from GitHub; it does not measure download throughput or promise the same values
or ordering on another network.

## Preservation

The original latest-source, TCP/UDP precheck, 8x64 connectivity, success/dedup,
country resolution, original URI text, protocol feed order and app/security paths
remain intact. Only country feeds and their corresponding shards change order:
measured Real Delay ascending; ties and unmeasured nodes use previous HTTPS delay.
No VPN-Core-Test source/command/API/AAR or private application file is changed.

The new signed score file is `metadata/node_delays.json`. New schemas and helper
hash/revision fields prevent mixing old download scores with current delay scores.
The next publication removes the stale node_speeds.json. A read-only legacy score
verifier and optional signing coverage retain validation of prior catalogs.
Existing published data is not rewritten by this source change.

## Local verification

- 37 focused Python tests passed: 11 ranking/handoff/signing invariants, nine
  country/publication integration, 14 existing owned-core and three dedup tests.
  All original successful links survive missing/failed observations. Synthetic
  country and shard order follows the lower delay; protocol order is unchanged.
- Real Go loopback fixtures passed through an independent VLESS wire peer and a
  trusted HTTPS origin. Two empty 204 requests reused one tunnel/HTTP connection;
  the result equals the exact minimum complete-request duration.
- HTTP errors, redirects, oversized declared/chunked bodies, truncated bodies,
  content encoding, a failed second request, unknown CA, wrong node credentials
  and timeout remained unmeasured. Invalid TLS/node credentials did not reach
  the origin handler, so there was no direct fallback or target-TLS bypass.
- The compiled CLI/worker path handled eight nodes, exactly 16 requests, at most
  four active requests, complete result coverage and credential-free logs.
- Targeted Go vet, formatting, Windows build and Linux/amd64 cross-build passed.
  actionlint v1.7.12 accepted the updated workflow. Existing catalog verification
  passed without rewriting published data. Core checkout remained unchanged.

These are bounded synthetic checks and compilation evidence. No public nodes,
real Internet measurements, workflow dispatch, application build or release was
performed; the owner dispatches the next catalog workflow personally.
