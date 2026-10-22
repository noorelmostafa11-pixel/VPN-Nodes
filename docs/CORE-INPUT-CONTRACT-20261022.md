# Core list-input compatibility

Run `39774835306` built clean core revision
`3f0f4e387eb28269cac609ae56f67e59f38468f3`. Its normal list reader can expand
one joined source record into multiple independent nodes. The catalog previously
assigned one identity per source row, so four shards returned 13,715 observations
for 13,714 assigned rows. The strict result validator correctly blocked publication.

## Catalog-side repair

`node_input.go` belongs to VPN-Nodes and is compiled as an explicit file from the
same pinned core module as the checker and speed helper. It calls the core's
`SplitNodeURIListLine` and `DescribeNodeURI` APIs. No core source, dependency,
SDK, Android artifact or core command is changed.

The candidate job downloads this run's adapter and verifies its binary hash,
core revision, tool revision and input hash. Expansion runs after source freshness
and literal/HTML wrapper normalization, before the existing literal deduplication,
allowed-port/TCP endpoint filter and eight-shard assignment. Each component uses
its own core-described protocol, host and port; it cannot inherit its parent's
TCP result. An ordinary record remains byte-for-byte unchanged, including invalid
input that nodecheck must reject. Unsupported children are kept for normal
validation rather than silently discarded.

Joined components retain the parent record in `joined_original_uri`, their
component index/count and existing collector provenance such as `original_uri`.
The immutable candidate snapshot counts the expanded, filtered nodes and records
the complete core build manifest. Checker and publication stages verify that
manifest when present. Older immutable snapshots retain their existing strict
validation path. Result count, source line, index, URI digest, authenticated HTTPS
evidence, deduplication and publication checks remain in force.

## Verification

The workflow runs Go adapter fixtures against the selected unchanged core and
Python integration fixtures with the built adapter. Fixtures cover literal and
encoded joined links, all four protocols, unsupported children, expansion bounds,
unchanged ordinary/NUL inputs, child endpoints, helper/snapshot identity, corrupt
coverage and all eight shards through speed-pool preparation. A bounded test with
closed loopback peers reproduces the old one-line/two-results mismatch, then runs
the unchanged production checker through the corrected handoff. These are local
fixtures, not a public-node scan or evidence of Internet acceptance.

The owner starts a new normal catalog run manually. Retrying the old run would
reuse its old workflow/source revision and does not validate this repair.
