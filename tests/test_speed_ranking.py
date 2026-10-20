"""Ranking cannot change eligibility, original links, or connection identity."""
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/xray_matrix"))
from finalize_catalog import country_sort_key, deduplicate_working
from speed_ranking import (POLICY, REPORT_SCHEMA, apply_ranking, assigned, digest,
                           load_pool, observation, verify_ranking, write_pool)

CORE = {"repository": "noorelmostafa11-pixel/VPN-Core-Test", "revision": "a"*40,
        "binary_sha256": "b"*64, "source_modified": False}


def row(index, latency):
    raw = f"vless://original-{index}?path=%2F#label"
    return {"protocol": "vless", "index": index, "raw": raw, "http204_ms": latency,
            "node_id": hashlib.sha256(raw.encode()).hexdigest(), "connection_key": "xray-outbound-v1:"+f"{index+1:064x}"}


def measured(node, local, duration):
    return {"index": local, "source": "nodes.txt", "line": local+1, "node_id": node["node_id"],
            "connection_key": node["connection_key"], "protocol": node["protocol"],
            "status": "MEASURED", "network_tested": True,
            "speed": {"target": POLICY["target"], "http_status": 200, "verified_tls": True,
                      "bytes": POLICY["sample_bytes"], "transfer_ns": duration,
                      "bits_per_second": POLICY["sample_bytes"]*8*1_000_000_000//duration,
                      "first_byte_ms": 20}}


class SpeedRankingTests(unittest.TestCase):
    def test_optional_speed_metadata_is_included_in_existing_signed_manifest(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        import sign_catalog
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); output = root/"output"; metadata = output/"metadata"
            metadata.mkdir(parents=True)
            for name in ("countries.json", "app_pool.json", "index.json", "source_freshness.json"):
                (metadata/name).write_text('{}')
            for relative in ("countries/US.txt", "country_shards/US/000.txt", "protocols/vless.txt"):
                path = output/relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('original\n')
            with mock.patch.object(sign_catalog, "ROOT", root), mock.patch.object(sign_catalog, "OUT", output), mock.patch.object(sign_catalog, "META", metadata):
                original = sign_catalog.included_files()
                speed = metadata/"node_speeds.json"; speed.write_text('{}')
                self.assertEqual(set(sign_catalog.included_files()), set(original)|{speed})

    def prepare(self, root, rows):
        write_pool(rows, CORE, "c"*64, root / "input")
        path = root / "input/pool.json"
        return path, load_pool(path)

    def shard(self, root, path, pool, shard, measurements):
        directory = root / "results" / str(shard)
        directory.mkdir(parents=True)
        entries, counts = [], Counter()
        for local, (index, node) in enumerate(assigned(pool, shard)):
            result = measurements.get(node["node_id"])
            counts[observation(result, node, local)["status"]] += 1
            entries.append({"index": index, "node_id": node["node_id"], "measurement": result})
        (directory / "observations.jsonl").write_text(''.join(json.dumps(e)+'\n' for e in entries))
        (directory / "summary.json").write_text(json.dumps({"schema": REPORT_SCHEMA, "policy": POLICY,
            "core": CORE, "pool_sha256": digest(path), "shard": shard, "assigned": len(entries), "statuses": dict(counts)}))

    def test_only_first_original_per_complete_connection_enters_pool(self):
        first, other = row(0, 100), row(1, 20)
        duplicate = row(8, 2)
        duplicate["connection_key"] = first["connection_key"]
        selected, *counts = deduplicate_working([duplicate, other, first])
        self.assertEqual([n["raw"] for n in selected], [first["raw"], other["raw"]])
        self.assertEqual(counts, [0, 0, 1])
        with tempfile.TemporaryDirectory() as d:
            _, pool = self.prepare(Path(d), selected)
            self.assertEqual([n["raw"] for n in pool["nodes"]], [first["raw"], other["raw"]])

    def test_eight_shards_assign_every_node_once(self):
        with tempfile.TemporaryDirectory() as d:
            _, pool = self.prepare(Path(d), [row(i, i+1) for i in range(19)])
            indexes = [i for shard in range(8) for i, _ in assigned(pool, shard)]
            self.assertEqual(sorted(indexes), list(range(19)))

    def test_all_measurements_missing_retains_every_node_and_previous_order(self):
        nodes = [row(0, 90), row(1, 20), row(2, 50)]
        original = [n["raw"] for n in nodes]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); path, _ = self.prepare(root, nodes)
            report = apply_ranking(nodes, path, root/"absent", CORE, "c"*64)
            self.assertEqual(report["summary"]["unmeasured"], 3)
            self.assertEqual(report["summary"]["missing_shards"], list(range(8)))
            self.assertEqual([n["raw"] for n in nodes], original)
            self.assertEqual([n["index"] for n in sorted(nodes, key=country_sort_key)], [1, 2, 0])

    def test_full_speed_samples_sort_before_unmeasured_without_losing_originals(self):
        nodes = [row(0, 10), row(1, 100), row(2, 5), row(3, 1)]
        original = {n["raw"] for n in nodes}
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); path, pool = self.prepare(root, nodes)
            measurements = {nodes[0]["node_id"]: measured(nodes[0], 0, 2_000_000_000),
                            nodes[1]["node_id"]: measured(nodes[1], 0, 100_000_000)}
            for shard in range(8): self.shard(root, path, pool, shard, measurements)
            report = apply_ranking(nodes, path, root/"results", CORE, "c"*64)
            ordered = sorted(nodes, key=country_sort_key)
            self.assertEqual([n["index"] for n in ordered], [1, 0, 3, 2])
            self.assertEqual({n["raw"] for n in ordered}, original)
            self.assertEqual((report["summary"]["measured"], report["summary"]["unmeasured"]), (2, 2))
            country = root / "US.txt"
            country.write_text(''.join(n["raw"]+'\n' for n in ordered))
            verify_ranking(report, report["summary"], CORE, list(original), [country])
            country.write_text(''.join(n["raw"]+'\n' for n in reversed(ordered)))
            with self.assertRaises(ValueError): verify_ranking(report, report["summary"], CORE, list(original), [country])

    def test_partial_wrong_identity_and_unverified_samples_cannot_receive_scores(self):
        node = row(0, 10)
        valid = measured(node, 0, 200_000_000)
        variants = [("bytes", 1024), ("http_status", 403), ("verified_tls", False),
                    ("transfer_ns", 0), ("bits_per_second", 999), ("target", "https://different.invalid/")]
        for name, value in variants:
            bad = copy.deepcopy(valid); bad["speed"][name] = value
            with self.subTest(name=name), self.assertRaises(ValueError): observation(bad, node, 0)
        bad = copy.deepcopy(valid); bad["connection_key"] = "xray-outbound-v1:"+"d"*64
        with self.assertRaises(ValueError): observation(bad, node, 0)
        bad = copy.deepcopy(valid); bad["node_id"] = "e"*64
        with self.assertRaises(ValueError): observation(bad, node, 0)

    def test_measurement_failure_is_retained_unmeasured(self):
        node = row(0, 10); result = measured(node, 0, 200_000_000)
        result["status"] = "UNMEASURED"; result["speed"]["bits_per_second"] = 0
        result["failure"] = {"code": "SPEED_HTTP_STATUS"}
        self.assertEqual(observation(result, node, 0)["status"], "UNMEASURED")

    def test_foreign_pool_and_shard_provenance_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); nodes = [row(0, 20)]; path, pool = self.prepare(root, nodes)
            with self.assertRaises(ValueError): apply_ranking(nodes, path, root/"results", CORE, "d"*64)
            self.shard(root, path, pool, 0, {})
            summary_path = root/"results/0/summary.json"
            summary = json.loads(summary_path.read_text()); summary["pool_sha256"] = "e"*64
            summary_path.write_text(json.dumps(summary))
            with self.assertRaises(ValueError): apply_ranking(nodes, path, root/"results", CORE, "c"*64)

    def test_helper_handoff_checks_hashes_and_keeps_failed_measurements(self):
        import run_speed_shard
        for successful in (True, False):
            with self.subTest(successful=successful), tempfile.TemporaryDirectory() as d:
                root = Path(d); core_file, tool_file = root/"core", root/"tool"
                core_file.write_bytes(b"synthetic-core"); tool_file.write_bytes(b"synthetic-helper")
                manifest = dict(CORE, binary_sha256=digest(core_file), speed_binary_sha256=digest(tool_file),
                                speed_core_revision=CORE["revision"], speed_tool_revision="d"*40)
                manifest_path = root/"core-build.json"; manifest_path.write_text(json.dumps(manifest))
                nodes = [row(0, 15)]; write_pool(nodes, manifest, "c"*64, root/"input")
                def invoke(arguments, **kwargs):
                    self.assertEqual(arguments[0], str(tool_file.resolve()))
                    if not successful: return SimpleNamespace(returncode=1)
                    report = Path(arguments[arguments.index("-output")+1]); report.mkdir()
                    input_path = Path(arguments[arguments.index("-input")+1])
                    self.assertEqual(input_path.read_text(), nodes[0]["raw"]+'\n')
                    result = measured(nodes[0], 0, 200_000_000)
                    (report/"results.jsonl").write_text(json.dumps(result)+'\n')
                    (report/"summary.json").write_text(json.dumps({"schema":"xray-node-speed-v1",
                        "revision":manifest["revision"], "tool_revision":manifest["speed_tool_revision"],
                        "binary_sha256":manifest["speed_binary_sha256"], "input_sha256":{"nodes.txt":digest(input_path)},
                        "inventory":1, "workers":4, "sample_bytes":POLICY["sample_bytes"], "target":POLICY["target"],
                        "node_timeout_ms":8000, "finished":1, "statuses":{"MEASURED":1}, "completed":True}))
                    return SimpleNamespace(returncode=0)
                output = root/"output"
                argv = ["run_speed_shard.py", "--pool", str(root/"input/pool.json"), "--core", str(core_file),
                        "--tool", str(tool_file), "--core-manifest", str(manifest_path), "--output", str(output), "--shard", "0"]
                with mock.patch.object(sys, "argv", argv), mock.patch.object(run_speed_shard.subprocess, "run", side_effect=invoke):
                    self.assertEqual(run_speed_shard.main(), 0)
                summary = json.loads((output/"summary.json").read_text())
                self.assertEqual(summary["statuses"], {"MEASURED" if successful else "UNMEASURED":1})
                self.assertFalse((output/"nodes.txt").exists())


if __name__ == "__main__":
    unittest.main()
