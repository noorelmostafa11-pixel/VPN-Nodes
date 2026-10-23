"""Offline integration checks: exact links, authenticated evidence and provenance."""
from __future__ import annotations
import copy
import asyncio
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "xray_matrix"))
sys.path.insert(0, str(ROOT / "scripts"))
import run_shard
import merge_and_build_tcp_pool as merge
from owned_core import CORE_REPOSITORY, TARGET_LABELS, digest, verify_binary, verify_prepared_input
from core_tcp_filter import uses_udp_transport


class OwnedCoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.reports = self.root / "nodecheck"
        self.reports.mkdir()
        self.raw = "vless://11111111-2222-4333-8444-555555555555@node.example:443?type=quic&fm=source#name"
        self.assigned = [("vless", 0, {"uri": self.raw, "host": "node.example", "port": 443})]
        (self.root / "nodes.txt").write_bytes((self.raw + "\n").encode())
        self.manifest = {"repository": CORE_REPOSITORY, "revision": "a"*40,
                         "binary_sha256": "b"*64, "source_modified": False}
        self.summary = {"schema": "xray-node-connectivity-v1", "completed": True, "runner_errors": 0,
                        "inventory": 1, "selected": 1, "finished": 1, "shard": 0, "shards": 1,
                        "revision": "a"*40, "binary_sha256": "b"*64, "targets": list(TARGET_LABELS),
                        "workers": 64, "node_timeout_ms": 6000, "attempt_timeout_ms": 2000,
                        "exit_metadata_enabled": True, "metadata_timeout_ms": 4000,
                        "input_sha256": {"nodes.txt": digest(self.root / "nodes.txt")}, "statuses": {"PASS": 1}}
        self.result = {"index": 0, "line": 1, "source": "nodes.txt",
                       "node_id": hashlib.sha256(self.raw.encode()).hexdigest(), "status": "PASS",
                       "protocol": "vless", "network_tested": True,
                       "attempts": [{"target": "https://www.cloudflare.com/cdn-cgi/trace",
                                     "verified_tls": True, "http_status": 403, "duration_ms": 37}],
                       "exit_metadata": {"country": "XX", "failure_code": "EXIT_METADATA_UNAVAILABLE"}}

    def write(self):
        (self.reports / "summary.json").write_text(json.dumps(self.summary), encoding="utf-8")
        (self.reports / "results.jsonl").write_text(json.dumps(self.result) + "\n", encoding="utf-8")

    def test_authenticated_non_204_and_metadata_failure_preserve_success(self):
        for status in (200, 204, 302, 403, 429, 500, 599):
            with self.subTest(status=status):
                self.result["attempts"][0]["http_status"] = status
                self.write()
                rows, counts = run_shard.convert_results(self.reports, self.assigned, self.manifest)
                self.assertEqual(rows[0]["raw"], self.raw)
                self.assertEqual(rows[0]["country"], "XX")
                self.assertEqual(rows[0]["http204_ms"], 37)
                self.assertEqual(counts["vless"]["success_endpoints"], {"cloudflare": 1})

    def test_corrupt_or_unverified_observations_block_publication(self):
        original = copy.deepcopy(self.result)
        for field, value in (("node_id", "wrong"), ("line", 2), ("status", "RUNNER_ERROR"),
                             ("protocol", "ss"), ("network_tested", False)):
            with self.subTest(field=field):
                self.result = dict(original, **{field: value})
                self.write()
                with self.assertRaises(ValueError):
                    run_shard.convert_results(self.reports, self.assigned, self.manifest)
        self.result = original
        self.result["attempts"][0]["verified_tls"] = False
        self.write()
        with self.assertRaises(ValueError):
            run_shard.convert_results(self.reports, self.assigned, self.manifest)

    def test_core_identity_survives_handoff_without_changing_raw_or_legacy_ids(self):
        self.result["connection_key"] = "xray-outbound-v1:" + "c" * 64
        self.write()
        rows, counts = run_shard.convert_results(self.reports, self.assigned, self.manifest)
        self.assertEqual(rows[0]["connection_key"], self.result["connection_key"])
        self.assertEqual(rows[0]["raw"], self.raw)
        self.assertEqual(rows[0]["node_id"], self.result["node_id"])
        self.assertEqual(counts["vless"]["working"], 1)
        del self.result["connection_key"]
        self.write()
        rows, _ = run_shard.convert_results(self.reports, self.assigned, self.manifest)
        self.assertEqual(rows[0]["connection_key"], "")

    def test_invalid_identity_is_a_report_contract_error(self):
        self.result["connection_key"] = "not-a-core-digest"
        self.write()
        with self.assertRaises(ValueError):
            run_shard.convert_results(self.reports, self.assigned, self.manifest)

    def test_foreign_core_or_snapshot_block_publication(self):
        original = dict(self.summary)
        for field, value in (("revision", "c"*40), ("binary_sha256", "d"*64),
                             ("finished", 0), ("completed", False), ("runner_errors", 1),
                             ("input_sha256", {})):
            with self.subTest(field=field):
                self.summary = dict(original, **{field: value})
                self.write()
                with self.assertRaises(ValueError):
                    run_shard.convert_results(self.reports, self.assigned, self.manifest)

    def test_missing_or_duplicate_result_blocks_publication(self):
        self.write()
        results = self.reports / "results.jsonl"
        for content in ("", (json.dumps(self.result) + "\n")*2):
            results.write_text(content, encoding="utf-8")
            with self.assertRaises(ValueError):
                run_shard.convert_results(self.reports, self.assigned, self.manifest)

    def test_shards_cover_original_links_once(self):
        rows = [{"protocol": p, "uri": f"{p}://source-{i}?new=unchanged"}
                for p in ("vless", "vmess", "trojan", "shadowsocks") for i in range(19)]
        assigned = [item for shard in range(8) for item in run_shard.assign(rows, shard, 8)]
        self.assertCountEqual([item[2] for item in assigned], rows)
        self.assertEqual(len({(p, i) for p, i, _ in assigned}), len(rows))

    def test_nul_source_reaches_core_and_is_counted_as_an_individual_rejection(self):
        self.raw = "trojan://synthetic\x00password@127.0.0.1:1#invalid-source"
        row = {"protocol": "trojan", "uri": self.raw}
        assigned = run_shard.assign([row], 0, 8)
        self.assertEqual(assigned, [("trojan", 0, row)])
        (self.root / "nodes.txt").write_bytes((self.raw + "\n").encode())
        self.summary["input_sha256"] = {"nodes.txt": digest(self.root / "nodes.txt")}
        self.summary["statuses"] = {"REJECTED": 1}
        self.result = {"index": 0, "line": 1, "source": "nodes.txt",
                       "node_id": hashlib.sha256(self.raw.encode()).hexdigest(),
                       "status": "REJECTED", "protocol": "unknown", "network_tested": False,
                       "failure": {"code": "INVALID_NODE", "message": "invalid input"}}
        self.write()
        working, counts = run_shard.convert_results(self.reports, assigned, self.manifest)
        self.assertEqual(working, [])
        self.assertEqual(counts["trojan"]["tested"], 1)
        self.assertEqual(counts["trojan"]["failed"], 1)
        self.assertEqual(counts["trojan"]["failure_stages"], {"INVALID_NODE": 1})

    def test_embedded_line_separator_cannot_inject_additional_core_inputs(self):
        for control in ("\r", "\n"):
            with self.assertRaises(ValueError):
                run_shard.assign([{"protocol": "trojan", "uri": "trojan://one" + control + "trojan://two"}], 0, 8)

    def test_binary_must_match_owned_source_manifest(self):
        binary = self.root / "core"
        binary.write_bytes(b"fixture")
        manifest = dict(self.manifest, binary_sha256=digest(binary))
        verify_binary(binary, manifest)
        for changed in ({"repository": "XTLS/Xray-core"}, {"source_modified": True}, {"binary_sha256": "0"*64}):
            with self.assertRaises(ValueError):
                verify_binary(binary, dict(manifest, **changed))

    def test_repository_rename_preserves_pinned_legacy_recovery_artifacts(self):
        binary = self.root / "core"
        binary.write_bytes(b"same-owner-core-fixture")
        for repository in ("noorelmostafa11-pixel/VPN-Core", "noorelmostafa11-pixel/VPN-Core-Test"):
            with self.subTest(repository=repository):
                manifest = dict(self.manifest, repository=repository, binary_sha256=digest(binary))
                original = copy.deepcopy(manifest)
                verify_binary(binary, manifest)
                snapshot = {"core_input": {"schema": "vpn-node-input-v1", "core": copy.deepcopy(manifest)}}
                verify_prepared_input(snapshot, manifest)
                self.assertEqual(manifest, original)
                for changed in ({"revision": "not-pinned"}, {"source_modified": True},
                                {"binary_sha256": "0"*64}):
                    with self.assertRaises(ValueError):
                        verify_binary(binary, dict(manifest, **changed))
                other_name = "noorelmostafa11-pixel/VPN-Core-Test" if repository == CORE_REPOSITORY else CORE_REPOSITORY
                with self.assertRaises(ValueError):
                    verify_prepared_input(snapshot, dict(manifest, repository=other_name))

    def test_repository_rename_does_not_trust_other_owners_or_malformed_identities(self):
        binary = self.root / "core"
        binary.write_bytes(b"fixture")
        manifest = dict(self.manifest, binary_sha256=digest(binary))
        for repository in ("someone-else/VPN-Core", "someone-else/VPN-Core-Test",
                           "noorelmostafa11-pixel/other-core", None, {}, []):
            with self.subTest(repository=repository), self.assertRaises(ValueError):
                verify_binary(binary, dict(manifest, repository=repository))

    def test_workflow_checkout_and_build_manifest_use_the_canonical_repository(self):
        workflow = (ROOT / ".github/workflows/update.yml").read_text(encoding="utf-8")
        self.assertIn("repository: " + CORE_REPOSITORY + "\n", workflow)
        self.assertIn("manifest = {'repository': '" + CORE_REPOSITORY + "',", workflow)
        self.assertNotIn("noorelmostafa11-pixel/VPN-Core-Test", workflow)

    def test_tcp_gate_preserves_udp_labeled_configs_if_endpoint_has_tcp(self):
        tcp_raw = self.raw.replace("type=quic", "type=ws")
        rows = [{"protocol": "vless", "host": "node.example", "port": 443, "uri": raw}
                for raw in (self.raw, self.raw.replace("#name", "#alias"),
                            tcp_raw, tcp_raw.replace("#name", "#alias"),
                            tcp_raw.replace("fm=source", "fm=other"))]
        meta = self.root / "metadata"
        freshness = {"sources_checked": 0, "active_sources": 0, "failed_sources": 0,
                     "empty_sources": 0, "included_nodes": 5, "filtering_policy": "fixture"}

        async def tcp_check(candidates):
            self.assertEqual([r["uri"] for r in candidates],
                             [self.raw, tcp_raw, rows[4]["uri"]])
            return [{**r, "latency_ms": 10} for r in candidates], 1, 1

        with mock.patch.object(merge, "META", meta), mock.patch.object(merge, "INPUTS", [self.root]), \
             mock.patch.object(merge, "load_rows", return_value=(rows, [])), \
             mock.patch.object(merge.source_freshness, "apply_source_freshness", return_value=(rows, [], freshness)), \
             mock.patch.object(merge, "run_tcp_checks_by_endpoint", side_effect=tcp_check), \
             mock.patch.object(merge.common, "publish_app_pool", return_value={"published_total": 3}):
            self.assertEqual(merge.main(core_candidates=True), 0)
        payload = json.loads((meta / "tcp_reachable.json").read_text())
        self.assertTrue(payload["tcp_precheck_applied"])
        self.assertEqual(payload["udp_precheck_bypassed"], 0)
        self.assertEqual(payload["tcp_reachable"], 3)
        self.assertEqual([r["uri"] for r in payload["nodes"]],
                         [self.raw, tcp_raw, rows[4]["uri"]])

    def test_prefilter_uses_tcp_endpoint_only_regardless_of_uri_transport(self):
        rows = [
            {"uri": "vless://alive.example:443?type=ws", "host": "alive.example", "port": 443},
            {"uri": "vless://alive.example:443?type=quic", "host": "alive.example", "port": 443},
            {"uri": "vless://alive.example:443?type=xhttp&alpn=h2,h3",
             "host": "alive.example", "port": 443},
            {"uri": "vless://dead.example:443?type=tcp", "host": "dead.example", "port": 443},
            {"uri": "vless://dead.example:443?type=kcp", "host": "dead.example", "port": 443},
        ]

        async def tcp_only(candidates):
            self.assertEqual(candidates, rows)
            return [row | {"latency_ms": 10} for row in rows[:3]], 2, 1

        with mock.patch.object(merge, "run_tcp_checks_by_endpoint", side_effect=tcp_only):
            selected, endpoints, alive, bypass = asyncio.run(merge.run_core_prefilter(rows))
        self.assertEqual([row["uri"] for row in selected],
                         [row["uri"] for row in rows[:3]])
        self.assertEqual((endpoints, alive, bypass), (2, 1, 0))

        async def no_tcp(candidates):
            self.assertEqual(candidates, [rows[1]])
            return [], 1, 0

        with mock.patch.object(merge, "run_tcp_checks_by_endpoint", side_effect=no_tcp):
            self.assertEqual(asyncio.run(merge.run_core_prefilter([rows[1]])),
                             ([], 1, 0, 0))
        self.assertEqual(asyncio.run(merge.run_core_prefilter([])),
                         ([], 0, 0, 0))

    def test_udp_hints_cover_native_transports_and_vmess_without_rebuilding_settings(self):
        for transport in ("quic", "kcp", "mkcp", "hysteria2"):
            self.assertTrue(uses_udp_transport("vless://id@host:443?type=" + transport))
            payload = base64.b64encode(json.dumps({"net": transport, "type": "none"}).encode()).decode()
            self.assertTrue(uses_udp_transport("vmess://" + payload))
        self.assertTrue(uses_udp_transport("ss://auth@host:443?plugin=v2ray-plugin%3Bmode%3Dquic"))
        self.assertTrue(uses_udp_transport("vless://id@host:443?type=xhttp&alpn=h2,h3"))
        self.assertTrue(uses_udp_transport('vless://id@host:443?type=xhttp&extra={"downloadSettings":{"tlsSettings":{"alpn":["h3"]}}}'))
        for transport in ("tcp", "raw", "ws", "grpc", "httpupgrade", "xhttp"):
            self.assertFalse(uses_udp_transport("vless://id@host:443?type=" + transport))
        self.assertFalse(uses_udp_transport('vless://id@host:443?type=xhttp&extra={"path":"/h3"}'))

    def test_runner_hands_exact_links_to_owned_command_and_cleans_inputs(self):
        binary = self.root / "core"
        binary.write_bytes(b"fixture")
        manifest = dict(self.manifest, binary_sha256=digest(binary))
        manifest_path = self.root / "core-build.json"
        manifest_path.write_text(json.dumps(manifest))
        candidates = self.root / "candidates.json"
        candidates.write_text(json.dumps({"nodes": [self.assigned[0][2] | {"protocol": "vless"}]}))
        output = self.root / "shard"
        argv = ["run_shard.py", "--input", str(candidates), "--output", str(output),
                "--core", str(binary), "--core-manifest", str(manifest_path), "--shard", "0"]

        def fake_core(command, **kwargs):
            self.assertEqual(command[:2], [str(binary.resolve()), "nodecheck"])
            self.assertNotIn("-target", command)
            self.assertTrue(kwargs["check"])
            self.assertEqual((output / "nodes.txt").read_bytes(), (self.raw + "\n").encode())
            self.assertEqual(kwargs["env"]["VPN_NODECHECK_COUNTRY_URL"], "https://country.example/private")
            report_dir = output / "nodecheck"
            report_dir.mkdir()
            summary = dict(self.summary, binary_sha256=manifest["binary_sha256"],
                           input_sha256={"nodes.txt": digest(output / "nodes.txt")})
            (report_dir / "summary.json").write_text(json.dumps(summary))
            (report_dir / "results.jsonl").write_text(json.dumps(self.result) + "\n")

        with mock.patch.object(sys, "argv", argv), \
             mock.patch.dict(os.environ, {"VPN_NODECHECK_COUNTRY_URL": "https://country.example/private"}), \
             mock.patch.object(run_shard.subprocess, "run", side_effect=fake_core):
            self.assertEqual(run_shard.main(), 0)
        self.assertFalse((output / "nodes.txt").exists())
        published = json.loads((output / "working.jsonl").read_text())
        self.assertEqual(published["raw"], self.raw)
        failed_output = self.root / "failed"
        argv[argv.index(str(output))] = str(failed_output)
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.dict(os.environ, {"VPN_NODECHECK_COUNTRY_URL": "https://country.example/private"}), \
             mock.patch.object(run_shard.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "fixture")):
            with self.assertRaises(subprocess.CalledProcessError):
                run_shard.main()
        self.assertFalse((failed_output / "nodes.txt").exists())
        self.assertFalse((failed_output / "working.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
