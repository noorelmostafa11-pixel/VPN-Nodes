"""Synthetic regression for the actual core-linked input adapter; no public nodes."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock
from urllib.parse import quote_plus

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts" / "xray_matrix"))
import merge_and_build_tcp_pool as merge
import build_tcp_candidates
import run_shard
import finalize_catalog
from owned_core import digest, read_json, TARGET_LABELS, verify_prepared_input
from prepare_core_input import prepare_rows

ID = "00000000-0000-4000-8000-000000000001"


@unittest.skipUnless(os.environ.get("VPN_NODE_INPUT_TOOL") and os.environ.get("VPN_NODE_INPUT_MANIFEST"),
                     "Build node-input against the pinned core and supply its manifest")
class CoreInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tool = Path(os.environ["VPN_NODE_INPUT_TOOL"])
        self.manifest = read_json(Path(os.environ["VPN_NODE_INPUT_MANIFEST"]))
        self.child = "trojan://synthetic@127.0.0.2:443?type=ws&path=%2Fedge#child"
        self.raw = (f"vless://{ID}@127.0.0.1:443?type="
                    + quote_plus("tcp#☺️99@synthetic_channel" + self.child)
                    + "&security=tls&sni=outer.example.invalid#outer")
        self.row = {"protocol": "vless", "uri": self.raw, "host": "127.0.0.1", "port": 443,
                    "original_uri": "source-wrapper", "uri_encoding": "literal", "source": "fixture",
                    "latency_ms": 7, "country": "AE"}

    def prepare(self, rows):
        return prepare_rows(rows, self.tool, self.manifest)

    def test_joined_and_encoded_inputs_keep_children_and_parent_provenance(self):
        rows = self.prepare([self.row])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]["uri"], self.child)
        self.assertEqual(rows[1]["protocol"], "trojan")
        self.assertEqual(rows[1]["host"], "127.0.0.2")
        self.assertEqual(rows[1]["port"], 443)
        for i, row in enumerate(rows):
            self.assertEqual(row["joined_original_uri"], self.raw)
            self.assertEqual(row["original_uri"], "source-wrapper")
            self.assertEqual(row["joined_component"], i)
            self.assertEqual(row["joined_components"], 2)
            self.assertNotIn("latency_ms", row)
            self.assertNotIn("country", row)
        self.assertEqual(self.prepare(rows), rows)

    def test_ordinary_nul_and_unsupported_children_are_not_discarded(self):
        invalid = dict(self.row, protocol="trojan", uri="trojan://synthetic\0password@127.0.0.1:443")
        literal = dict(self.row, uri=f"vless://{ID}@127.0.0.1:443?type=ws&path=/vless://literal")
        self.assertEqual(self.prepare([invalid, literal]), [invalid, literal])
        unsupported = f"vless://{ID}@127.0.0.2:443?type=unknown"
        rows = self.prepare([dict(self.row, uri=self.raw.replace(quote_plus(self.child), quote_plus(unsupported)))])
        self.assertEqual(rows[1]["uri"], unsupported)

    def test_wrong_helper_core_or_snapshot_identity_blocks_handoff(self):
        for key, value in (("input_core_revision", "0" * 40), ("input_binary_sha256", "0" * 64),
                           ("input_tool_revision", "0" * 40)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                prepare_rows([self.row], self.tool, dict(self.manifest, **{key: value}))
        with self.assertRaises(ValueError):
            verify_prepared_input({"core_input": {"schema": "vpn-node-input-v1", "core": {}}}, self.manifest)
        for control in ("\r", "\n"):
            with self.assertRaises(ValueError):
                self.prepare([dict(self.row, uri=self.raw + control)])

    def test_expansion_precedes_tcp_filter_and_snapshot_counts(self):
        freshness = {"sources_checked": 0, "active_sources": 0, "failed_sources": 0,
                     "empty_sources": 0, "included_nodes": 1, "filtering_policy": "fixture"}

        async def tcp(rows):
            self.assertEqual([(r["host"], r["port"]) for r in rows],
                             [("127.0.0.1", 443), ("127.0.0.2", 443)])
            return [dict(r, latency_ms=10) for r in rows], 2, 2

        with mock.patch.object(merge, "META", self.root), mock.patch.object(merge, "INPUTS", [self.root]), \
             mock.patch.object(merge, "load_rows", return_value=([self.row], [])), \
             mock.patch.object(merge.source_freshness, "apply_source_freshness", return_value=([self.row], [], freshness)), \
             mock.patch.object(merge, "run_tcp_checks_by_endpoint", side_effect=tcp), \
             mock.patch.object(merge.common, "publish_app_pool", return_value={}), \
             mock.patch.object(build_tcp_candidates, "TCP_REACHABLE", self.root / "tcp_reachable.json"), \
             mock.patch.object(build_tcp_candidates, "XRAY_CANDIDATES", self.root / "candidates.json"), \
             mock.patch.object(sys, "argv", ["build_tcp_candidates.py", "--input-tool", str(self.tool),
                  "--core-manifest", os.environ["VPN_NODE_INPUT_MANIFEST"]]):
            self.assertEqual(build_tcp_candidates.main(), 0)
        snapshot = read_json(self.root / "tcp_reachable.json")
        self.assertEqual(snapshot["candidate_total"], 2)
        self.assertEqual(snapshot["tcp_reachable"], 2)
        self.assertEqual(snapshot["udp_precheck_bypassed"], 0)
        prepared = read_json(self.root / "candidates.json")
        self.assertEqual(prepared["candidate_total"], 2)
        self.assertEqual(prepared["protocol_counts"], {"vless": 1, "trojan": 1})
        verify_prepared_input(prepared, self.manifest)

    def test_missing_reordered_or_foreign_expansion_records_are_rejected(self):
        real_run = subprocess.run
        for fault in ("missing", "reordered", "foreign", "header"):
            def tamper(command, **kwargs):
                result = real_run(command, **kwargs)
                output = Path(command[command.index("-output") + 1])
                lines = output.read_text().splitlines()
                if fault == "missing":
                    lines.pop()
                elif fault == "foreign":
                    lines.append(lines[-1])
                elif fault == "reordered":
                    record = json.loads(lines[1])
                    record["index"] = 7
                    lines[1] = json.dumps(record)
                else:
                    record = json.loads(lines[0])
                    record["input_sha256"] = "0" * 64
                    lines[0] = json.dumps(record)
                output.write_text("\n".join(lines) + "\n")
                return result
            with self.subTest(fault=fault), mock.patch.object(subprocess, "run", side_effect=tamper), \
                 self.assertRaises(ValueError):
                self.prepare([self.row])

    def test_each_joined_endpoint_receives_the_existing_port_policy(self):
        row = dict(self.row, uri=self.raw.replace("127.0.0.1:443", "127.0.0.1:8443"), port=8443)
        freshness = {"sources_checked": 0, "active_sources": 0, "failed_sources": 0,
                     "empty_sources": 0, "included_nodes": 1, "filtering_policy": "fixture"}

        async def tcp(rows):
            self.assertEqual([(r["host"], r["port"]) for r in rows], [("127.0.0.2", 443)])
            return [dict(rows[0], latency_ms=10)], 1, 1

        with mock.patch.object(merge, "META", self.root), mock.patch.object(merge, "INPUTS", [self.root]), \
             mock.patch.object(merge, "load_rows", return_value=([row], [])), \
             mock.patch.object(merge.source_freshness, "apply_source_freshness", return_value=([row], [], freshness)), \
             mock.patch.object(merge, "run_tcp_checks_by_endpoint", side_effect=tcp), \
             mock.patch.object(merge.common, "publish_app_pool", return_value={}):
            self.assertEqual(merge.main(core_candidates=True, prepare_core_rows=self.prepare), 0)
        self.assertEqual(read_json(self.root / "tcp_reachable.json")["nodes"][0]["uri"], self.child)

    def test_expanded_shards_convert_and_finalize_without_weakening_identity(self):
        ordinary = [dict(self.row, uri=f"vless://{ID}@127.0.0.1:443?type=ws&path=%2Ffixture-{i}#ordinary")
                    for i in range(10)]
        rows = self.prepare([self.row, *ordinary])
        snapshot = self.root / "candidates.json"
        snapshot.write_text(json.dumps({"nodes": rows, "tcp_reachable": len(rows),
                             "core_input": {"schema": "vpn-node-input-v1", "core": self.manifest}}))
        results_root = self.root / "results"
        for shard in range(8):
            assigned = run_shard.assign(rows, shard, 8)
            directory = results_root / f"shard-{shard}"
            directory.mkdir(parents=True)
            source = directory / "nodes.txt"
            source.write_bytes("".join(row["uri"] + "\n" for _, _, row in assigned).encode())
            reports = directory / "nodecheck"
            reports.mkdir()
            observations = []
            for index, (protocol, _, row) in enumerate(assigned):
                observations.append({"index": index, "line": index + 1, "source": "nodes.txt",
                    "node_id": hashlib.sha256(row["uri"].encode()).hexdigest(), "status": "PASS",
                    "protocol": protocol, "network_tested": True, "exit_metadata": {"country": "AE"},
                    "attempts": [{"target": next(iter(TARGET_LABELS)), "http_status": 204,
                                  "verified_tls": True, "duration_ms": 12}]})
            summary = {"schema": "xray-node-connectivity-v1", "completed": True, "runner_errors": 0,
                       "inventory": len(assigned), "selected": len(assigned), "finished": len(assigned),
                       "shard": 0, "shards": 1, "revision": self.manifest["revision"],
                       "binary_sha256": self.manifest["binary_sha256"], "targets": list(TARGET_LABELS),
                       "workers": 64, "node_timeout_ms": 6000, "attempt_timeout_ms": 2000,
                       "exit_metadata_enabled": True, "metadata_timeout_ms": 4000,
                       "input_sha256": {"nodes.txt": digest(source)},
                       "statuses": dict(Counter(r["status"] for r in observations))}
            (reports / "summary.json").write_text(json.dumps(summary))
            (reports / "results.jsonl").write_text("".join(json.dumps(r) + "\n" for r in observations))
            working, counts = run_shard.convert_results(reports, assigned, self.manifest)
            if observations:
                corrupt = copy.deepcopy(observations)
                corrupt[0]["node_id"] = "0" * 64
                (reports / "results.jsonl").write_text("".join(json.dumps(r) + "\n" for r in corrupt))
                with self.assertRaises(ValueError):
                    run_shard.convert_results(reports, assigned, self.manifest)
            for row in working:
                row["shard"] = shard
            (directory / "working.jsonl").write_text("".join(json.dumps(r) + "\n" for r in working))
            (directory / "summary.json").write_text(json.dumps({"schema": 2, "shard": shard, "shards": 8,
                "workers": 64, "core": self.manifest, "candidates_sha256": digest(snapshot), "protocols": counts}))
        freshness = self.root / "freshness.json"
        freshness.write_text("{}")
        pool = self.root / "pool"
        argv = ["finalize_catalog.py", "--candidates", str(snapshot), "--results-root", str(results_root),
                "--source-freshness", str(freshness), "--prepare-speed", str(pool)]
        with mock.patch.object(sys, "argv", argv):
            self.assertEqual(finalize_catalog.main(), 0)
        nodes = read_json(pool / "pool.json")["nodes"]
        self.assertCountEqual([row["raw"] for row in nodes], [row["uri"] for row in rows])

    @unittest.skipUnless(os.environ.get("VPN_NODECHECK_BINARY"), "Supply the unchanged core for loopback-only checking")
    def test_real_core_reproduces_mismatch_then_accepts_prepared_identity(self):
        binary = Path(os.environ["VPN_NODECHECK_BINARY"])
        self.assertEqual(digest(binary), self.manifest["binary_sha256"])
        # Both synthetic peers use closed loopback ports; no public-node traffic.
        raw = self.raw.replace("127.0.0.1:443", "127.0.0.1:1").replace(
            quote_plus(self.child), quote_plus("trojan://synthetic@127.0.0.1:1?type=ws"))
        before = self.root / "before.txt"
        before.write_bytes((raw + "\n").encode())
        subprocess.run([str(binary), "nodecheck", "-input", str(before), "-output", str(self.root / "before"),
                        "-workers", "1", "-live=false"], check=True, capture_output=True)
        self.assertEqual(read_json(self.root / "before" / "summary.json")["inventory"], 2)
        rows = self.prepare([dict(self.row, uri=raw)])
        snapshot = self.root / "snapshot.json"
        snapshot.write_text(json.dumps({"nodes": rows,
            "core_input": {"schema": "vpn-node-input-v1", "core": self.manifest}}))
        for shard in range(8):
            output = self.root / f"checked-{shard}"
            argv = ["run_shard.py", "--input", str(snapshot), "--core", str(binary),
                    "--core-manifest", os.environ["VPN_NODE_INPUT_MANIFEST"], "--output", str(output),
                    "--shard", str(shard)]
            with mock.patch.object(sys, "argv", argv), mock.patch.dict(os.environ, {
                    "VPN_NODECHECK_COUNTRY_URL": "https://country.example.invalid/private"}):
                self.assertEqual(run_shard.main(), 0)
            summary = read_json(output / "summary.json")
            assigned = run_shard.assign(rows, shard, 8)
            self.assertEqual(sum(p["tested"] for p in summary["protocols"].values()), len(assigned))
            self.assertFalse((output / "nodes.txt").exists())


if __name__ == "__main__":
    unittest.main()
