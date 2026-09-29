#!/usr/bin/env python3
"""Exercise country fallback and published ordering without network requests."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "xray_tester"))
sys.path.insert(0, str(ROOT / "scripts" / "xray_matrix"))

from vpn_pipeline_core import connectivity  # noqa: E402
from vpn_pipeline_core.models import Node  # noqa: E402
import finalize_catalog  # noqa: E402
import verify_final_catalog  # noqa: E402


class ExitCountryAndOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.node = Node("vless", 0, "original-node", "entry.example", 443, {}, {})

    def _test_node(self, country_response, exit_response):
        calls = []

        def read(port, url, limit, **kwargs):
            calls.append((port, url, limit, kwargs))
            if url == "https://country.example/cc":
                return country_response
            self.assertEqual(url, connectivity.config.COUNTRY_EXIT_URL)
            return exit_response

        with mock.patch.object(connectivity.config, "COUNTRY_URL", "https://country.example/cc"), \
             mock.patch.object(connectivity, "REAL_PING_TARGETS", (("google", "https://test.example/204", 9),)), \
             mock.patch.object(connectivity, "_real_ping_target", return_value=147), \
             mock.patch.object(connectivity, "_https_read_limited", side_effect=read):
            result = connectivity.v2rayn_real_ping(self.node, 10808)
        return result, calls

    def test_private_country_success_skips_backup(self):
        result, calls = self._test_node((200, b'{"country":"DE"}'), None)
        self.assertTrue(result.ok)
        self.assertEqual((result.country, result.exit_ip, result.http204_ms), ("DE", "", 147.0))
        self.assertEqual(len(calls), 1)

    def test_private_country_returns_exit_ip_without_country(self):
        result, calls = self._test_node((200, b'{"ip":"8.8.8.8","country":"XX"}'), None)
        self.assertTrue(result.ok)
        self.assertEqual((result.country, result.exit_ip), ("XX", "8.8.8.8"))
        self.assertEqual(len(calls), 1)

    def test_backup_uses_same_node_and_preserves_success(self):
        result, calls = self._test_node((503, b""), (200, b'{"ip":"1.1.1.1"}'))
        self.assertTrue(result.ok)
        self.assertEqual((result.country, result.exit_ip), ("XX", "1.1.1.1"))
        self.assertEqual([port for port, *_ in calls], [10808, 10808])
        self.assertEqual(calls[1][3]["request_timeout"], connectivity.config.COUNTRY_EXIT_TIMEOUT)

    def test_backup_failure_does_not_discard_working_node(self):
        result, calls = self._test_node((503, b""), (429, b""))
        self.assertTrue(result.ok)
        self.assertEqual((result.country, result.exit_ip), ("XX", ""))
        self.assertEqual(len(calls), 2)

    def test_json_without_country_never_infers_ip_as_country(self):
        result, calls = self._test_node((200, b'{"ip":"8.8.8.8"}'), None)
        self.assertEqual((result.country, result.exit_ip), ("XX", "8.8.8.8"))
        self.assertEqual(len(calls), 1)

    def test_publication_orders_real_delay_and_preserves_all_nodes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = root / "results"
            results.mkdir()
            candidates = root / "candidates.json"
            source_freshness = root / "source_freshness.json"
            candidates.write_text(json.dumps({"nodes": [
                {"protocol": "vless", "uri": "vless://slow", "latency_ms": 1, "source": "first"},
                {"protocol": "vless", "uri": "vless://fast", "latency_ms": 999, "source": "second"},
                {"protocol": "vless", "uri": "vless://unknown", "latency_ms": 5, "source": "third"},
            ], "sources": [], "source_freshness": {}}), encoding="utf-8")
            source_freshness.write_text("{}", encoding="utf-8")

            for shard in range(15):
                folder = results / f"shard-{shard:02d}"
                folder.mkdir()
                n = 1 if shard < 3 else 0
                summary = {"shard": shard, "shards": 15, "workers": 40, "protocols": {
                    protocol: {"assigned": n if protocol == "vless" else 0,
                               "tested": n if protocol == "vless" else 0,
                               "working": n if protocol == "vless" else 0,
                               "success_endpoints": {"google": n} if protocol == "vless" and n else {},
                               "failure_stages": {}}
                    for protocol in ("vless", "vmess", "trojan", "ss")
                }}
                (folder / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
                row = None
                if shard < 3:
                    row = {"protocol": "vless", "index": shard, "shard": shard,
                           "raw": ("vless://slow", "vless://fast", "vless://unknown")[shard],
                           "host": "1.1.1.1", "ok": True, "success_endpoint": "google",
                           "country": ("XX", "US", "XX")[shard],
                           "exit_ip": "8.8.8.8" if shard == 0 else "",
                           "http204_ms": (200.0, 50.0, 25.0)[shard]}
                (folder / "working.jsonl").write_text(
                    json.dumps(row) + "\n" if row else "", encoding="utf-8",
                )

            argv = ["finalize_catalog.py", "--candidates", str(candidates),
                    "--results-root", str(results), "--source-freshness", str(source_freshness)]
            with mock.patch.object(finalize_catalog, "ROOT", root), \
                 mock.patch.object(finalize_catalog, "COUNTRY_SHARD_SIZE", 1), \
                 mock.patch.object(finalize_catalog.country_resolver, "country_from_ip", return_value="US") as geo, \
                 mock.patch.object(finalize_catalog.country_resolver, "resolve_ip", side_effect=AssertionError("entry host used")), \
                 mock.patch.object(sys, "argv", argv):
                self.assertEqual(finalize_catalog.main(), 0)
            geo.assert_called_once_with("8.8.8.8")

            def contents(path):
                return path.read_text(encoding="utf-8").splitlines()

            out = root / "output"
            self.assertEqual(contents(out / "countries" / "US.txt"), ["vless://fast", "vless://slow"])
            self.assertEqual(contents(out / "country_shards" / "US" / "000.txt"), ["vless://fast"])
            self.assertEqual(contents(out / "country_shards" / "US" / "001.txt"), ["vless://slow"])
            self.assertEqual(contents(out / "countries" / "XX.txt"), ["vless://unknown"])
            self.assertEqual(contents(out / "protocols" / "vless.txt"),
                             ["vless://slow", "vless://fast", "vless://unknown"])
            app = json.loads((out / "metadata" / "app_pool.json").read_text(encoding="utf-8"))
            self.assertEqual(app["published_total"], 3)
            self.assertEqual(app["geoip_xx_fallback"], {
                "provider": "GeoLite2-Country", "scope": "working_xx_only",
                "attempted": 2, "exit_ip_available": 1, "exit_ip_missing": 1,
                "classified": 1, "unresolved": 1,
            })
            with mock.patch.object(verify_final_catalog, "OUT", out), \
                 mock.patch.object(verify_final_catalog, "META", out / "metadata"):
                self.assertEqual(verify_final_catalog.main(), 0)


if __name__ == "__main__":
    unittest.main()
