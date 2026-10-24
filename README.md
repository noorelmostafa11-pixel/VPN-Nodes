# VPN-Nodes

Public runner for the owner's private catalog pipeline.

Run **Actions → Update node catalog → Run workflow** on `main`. Leave `publish_run_id` empty for a fresh catalog, or provide a completed owned run ID for publication recovery. `core_ref` selects the private core revision to resolve once for that run.

The complete pipeline and newly generated signed catalogs are stored in the private `VPN-Nodes-Private` repository. This repository contains only the runner launchers and safe recovery metadata code. Intermediate artifacts and diagnostics are encrypted; forks do not receive the required credentials.

The existing public `output` snapshot and signing public key remain temporarily available while the owner's clients migrate to authenticated private reads. They are not updated by the new pipeline.

The catalog workflow remains manual. The existing GeoLite refresh schedule is preserved and writes to the private repository.
