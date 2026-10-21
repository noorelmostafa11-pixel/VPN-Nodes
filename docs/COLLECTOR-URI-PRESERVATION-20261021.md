# Complete share-link extraction

The former regular expressions stopped at quotes or commas. A complete query
such as `fm={"tcp":[]}` could therefore reach the core as `fm={`. Page-level
extractors could truncate the URI before the shared catalog reader saw it.

## Implemented path

- A shared standard-library scanner preserves nested JSON objects/arrays,
  escaped quotes, commas and subsequent query parameters. It separates adjacent
  links and does not supply missing source bytes or resolve conflicting options.
- HTML text and attributes are decoded at their container boundary. Script
  contents retain their literal entity text. Valid JSON string containers are
  decoded with the JSON parser, without evaluating JavaScript. JSON string
  control bytes are percent-encoded to preserve one record per checker line.
- `original_uri` retains the extracted source token before wrapper decoding.
  `uri_encoding: literal` prevents a later second HTML decode. Old cache rows
  without this marker retain the former single HTML normalization pass.
- Catalog imports, Telegram, V2Nodes, OutlineKeys, ClashXW and the HTML/base64
  helper use the shared reader. V2Nodes keeps its ordinary string-list API;
  the candidate builder explicitly requests records carrying provenance.
- Adapter normalization retains nested links but does not reimport provenance
  text as a second candidate. Different wrapper interpretations remain separate
  until their actual URI bytes have been normalized.
- Existing V2Nodes/HTML-helper punctuation cleanup remains on simple links;
  structured query values keep their closing braces and brackets.

Endpoint/port policy, source freshness, shared TCP precheck, owned-core
validation, successful-node identity, download ranking, publication recovery and
scheduling retain their existing behavior. The workflow diff only adds the new
offline regression suite to the existing validation step.

## Local evidence

Python 3.12: all 30 tests in `tests/test_share_link_extractor.py` passed. These
include old four-protocol inputs, base64 subscriptions, complete JSON/HTML/JSON
string wrappers, malformed inputs followed by valid nodes, Telegram's collector,
V2Nodes primary/retry paths, its serialized candidate file, adapter provenance,
and the owned-core candidate merge with network calls replaced by fixtures.

Related existing tests passed: source pipeline, OutlineKeys, kort0881,
share-daily, FreeProxyDB, node identity, source freshness, shared TCP endpoint and
connection deduplication. Workflow actionlint and whitespace checks passed.

No source fetch, public-node scan, workflow dispatch or application/package build
was performed for this collector change. These fixtures do not measure how many
of the historical rejected nodes will pass connectivity. Previously truncated
source bytes cannot be recovered from the damaged URI alone; a subsequent normal
collection can preserve the complete URI when the upstream still provides it.

The mobile app consumes the resulting URI through the same core node importer.
Collector repairs do not replace a mobile core update: the app must use an AAR
built from the core revision containing the separately published compatibility
additions. Source wrappers and collector provenance are not runtime settings.
