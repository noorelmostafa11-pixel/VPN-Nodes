This directory retains pure parsing/identity helpers and historical offline
fixtures used by `scripts/node_identity.py` and its regression checks.

The production catalog no longer uses these parsers, Python repairs, SOCKS
probes or an official Xray downloader to decide whether a node works. The old
downloader, engine, repair and execution modules have been removed.

`scripts/xray_matrix/run_shard.py` passes the original link to the owned
VPN-Core-Test executable's `nodecheck` command. Connection compatibility and
normalization belong to that core. See the repository README for the run and
signed-catalog contract.
