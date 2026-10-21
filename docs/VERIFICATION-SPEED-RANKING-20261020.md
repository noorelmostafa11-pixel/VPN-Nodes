# Optional country speed ranking

Starting VPN-Nodes revision: `ad3a1ae6d68c9058c418132627125ba84a6850b3`.
Core used for local validation: `aa1b40e50f74bcb41cbefa755800e34975dc09fa`.

The implementation lives entirely in VPN-Nodes. VPN-Core-Test source, commands,
SDK and Android artifacts are unchanged. The standalone Go measurement helper
links the selected existing core library; Python controls artifact handoff and
country publication. This follows the owner's clarified separation of duties.

## Run contract

1. Existing latest-source preparation and 8x64 connectivity checks are unchanged.
2. Validate this run's shard/candidate provenance and use the original successful
   deduplication rules to prepare its exact unique pool. No source is re-fetched
   for speed ranking; no old catalog or fixed node count supplies the pool.
3. Build the helper from this run's pinned core module and this workflow's exact
   VPN-Nodes commit. Record both binary hashes and source revisions.
4. Eight measurement jobs each run at most four nodes concurrently. Each starts
   with Cloudflare HTTPS, a fixed 1 MiB sample, and an eight-second complete
   deadline. Cloudflare gets at most five seconds; if its verified sample fails,
   the same outbound attempts an OVHcloud HTTPS byte range for exactly 1 MiB
   within the remainder of the *same* eight seconds. No concurrent duplicate
   requests, direct-network fallback, or extra per-node time. OVHcloud must
   return HTTP 206, a valid 0-1048575 Content-Range and 1048576-byte length.
5. Only a complete Cloudflare HTTP 200 or strictly validated OVHcloud HTTP 206
   response with verified target TLS and no compression earns a score. Rank by
   observed bits/second after the first response byte, keeping provider provenance.
   Recycle subprocesses after bounded batches; never fall back to direct access.
6. Retain unmeasured nodes and missing-job assignments using the old HTTPS-delay
   order, after measured nodes. Regenerate corresponding country shards, verify
   counts/order and sign score metadata using the existing catalog signature.

## Completed local checks

- 35 focused Python tests passed: 9 ranking, 9 country/publication integration,
  14 existing owned-core handoff and 3 existing connection-dedup cases.
- Full synthetic publication preserved the exact original URI/protocol sets,
  reversed country order when download score required it, regenerated matching
  country shards and passed the final catalog verifier.
- Missing observations, partial/invalid samples, mismatched connection keys,
  different input hashes and helper failures exercised retention/integrity paths.
- The archived run 39372974516 preparation produced exactly its existing 5,283
  unique original links from 13,246 successful observations. This was offline
  data validation only, not a scan or an input source for any future workflow.
- The existing published catalog passed the verifier without speed metadata.
- Windows helper build and Linux/amd64 cross-build passed using the unchanged
  pinned core module; targeted Go vet and Go formatting passed.
- The real Windows loopback fixture used VLESS and a local trusted HTTPS peer.
  Eight complete samples passed with observed peak concurrency exactly four.
  Short/truncated bodies, HTTP 429, timeout, untrusted target CA and wrong node
  credentials stayed unmeasured. Wrong credentials never reached the HTTPS peer,
  proving there was no direct fallback. Reports did not contain source URIs/UUIDs.
- GitHub workflow lint passed with actionlint v1.7.12; job graph checks verified
  eight speed shards, guarded publication and the optional-stage failure policy.
- Core checkout remained clean at the original revision.

No public-node speed checks, GitHub workflow dispatch, private app changes or
Android builds were performed. These checks do not prove real Internet scores,
Linux runtime performance or elapsed time of the next owner-dispatched run.
The sample is an estimate from GitHub's network, not a speed guarantee for a phone.
