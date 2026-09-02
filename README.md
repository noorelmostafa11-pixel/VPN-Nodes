# VPN-Nodes

Automated catalog builder for VPN/Xray node candidates.

## Validation model

The backend intentionally performs a lightweight **TCP reachability** check only. A node published by this repository has an endpoint that accepted a TCP connection at generation time; that does **not** prove that the full VLESS/VMess/Trojan/Shadowsocks configuration is valid.

The Android application owns the final runtime validation using Xray plus a local HTTP/Internet health check.

Pipeline:

```text
public sources + Telegram + v2nodes
        -> parse / normalize / deduplicate
        -> TCP reachability check
        -> country resolution
        -> output/countries/<CC>.txt
        -> Android Xray + real-traffic validation
```

## App-facing output

The country feeds consumed by the app live at:

```text
output/countries/<COUNTRY_CODE>.txt
```

`output/active/` is no longer generated because it duplicated the country feeds.

Protocol-level feeds remain under `output/protocols/`, and compact run metadata remains under `output/metadata/`.

## Temporary workflow files

The collectors still generate intermediate JSON files during a workflow run because later steps need them. They are intentionally ignored by Git and are discarded with the GitHub Actions runner after the job finishes:

- `output/metadata/sources_candidates.json`
- `output/metadata/telegram_candidates.json`
- `output/metadata/v2nodes_candidates.json`
- `output/metadata/tcp_reachable.json`
- `output/metadata/merged_pool.json`

This keeps the pipeline behavior unchanged while avoiding large, fast-changing intermediate blobs in repository history.

## Updating the catalog

Run the **Update node catalog** GitHub Actions workflow. It installs the pinned Python dependencies, prepares the local GeoLite2 database, runs the country resolver regression tests, builds/merges candidates, performs the common TCP checks, verifies the app metadata, and commits only publishable `output/` changes.

## Important semantics

- `TCP alive` means the advertised host/port accepted a TCP connection during the run.
- It is not equivalent to `Xray verified`.
- Country feeds are the canonical app-facing node lists.
- Final protocol/runtime verification belongs to the Android client.
