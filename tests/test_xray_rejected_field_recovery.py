"""Keep core-rejected share fields recoverable without changing source links."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "xray_tester"))
sys.path.insert(0, str(ROOT / "scripts"))

import node_identity  # noqa: E402
from vpn_pipeline_core.models import TestResult  # noqa: E402
from vpn_pipeline_core.parsers import PARSERS  # noqa: E402
from vpn_pipeline_core.repairs import repair_candidate_for_failure  # noqa: E402
from vpn_pipeline_core.testing import run_protocol_role  # noqa: E402
from vpn_pipeline_core.xray_engine import (  # noqa: E402
    classify_xray_config_failure,
    make_xray_config,
)


TLS_ERROR = (
    'Failed to build TLS config. The feature "allowInsecure" has been removed '
    'and migrated to "pinnedPeerCertSha256" and "verifyPeerCertByName".'
)
MASK_ERROR = (
    'json: cannot unmarshal string into Go struct field '
    'Config.outbounds.0.streamSettings.finalmask of type conf.FinalMask'
)
BOOL_ERROR = (
    'json: cannot unmarshal string into Go struct field '
    'Config.outbounds.0.streamSettings.tlsSettings.allowInsecure of type bool'
)
TROJAN = (
    "trojan://secret@example.com:443?security=tls&sni=example.com&"
    "type=ws&host=example.com&path=%2Fws&allowInsecure=1&insecure=1#original"
)
VLESS = (
    "vless://00000000-0000-0000-0000-000000000001@example.com:443?"
    "encryption=none&security=tls&type=ws&host=example.com&path=%2Fws&fm=%7B#original"
)


def failure(raw, reason, protocol=None):
    protocol = protocol or raw.split(":", 1)[0]
    node = PARSERS[protocol](raw, 3, "https://www.gstatic.com/generate_204")
    return TestResult(
        protocol, node.index, raw, node.host, node.port, False,
        classify_xray_config_failure(reason), reason,
    )


class RejectedFieldRecoveryTests(unittest.TestCase):
    def test_source_option_stays_distinct_until_xray_decides(self):
        without_override = TROJAN.replace("&allowInsecure=1&insecure=1", "")
        self.assertNotEqual(
            node_identity.dedup_key(TROJAN),
            node_identity.dedup_key(without_override),
        )
        self.assertIn(
            "allowInsecure",
            PARSERS["trojan"](TROJAN, 3, "").stream_settings["tlsSettings"],
        )
        self.assertNotIn(
            "allowInsecure",
            PARSERS["trojan"](without_override, 3, "").stream_settings["tlsSettings"],
        )

    def test_only_proven_core_rejections_get_one_derived_link(self):
        original = TROJAN
        repaired, strategy = repair_candidate_for_failure(failure(original, TLS_ERROR))
        self.assertEqual(strategy, "omit_removed_tls_override")
        self.assertNotIn("insecure=", repaired.lower())
        before = PARSERS["trojan"](original, 3, "")
        after = PARSERS["trojan"](repaired, 3, "")
        self.assertEqual(before.host, after.host)
        self.assertEqual(before.port, after.port)
        self.assertEqual(before.outbound_settings, after.outbound_settings)
        self.assertEqual(before.stream_settings["wsSettings"], after.stream_settings["wsSettings"])
        self.assertEqual(before.stream_settings["tlsSettings"]["serverName"], after.stream_settings["tlsSettings"]["serverName"])
        self.assertEqual(before.raw, original)
        self.assertEqual(after.raw, repaired)
        self.assertTrue(repaired.endswith("#original"))

        mask_repaired, strategy = repair_candidate_for_failure(failure(VLESS, MASK_ERROR))
        self.assertEqual(strategy, "omit_rejected_finalmask")
        self.assertNotIn("fm=", mask_repaired)
        self.assertEqual(PARSERS["vless"](mask_repaired, 3, "").stream_settings["wsSettings"],
                         PARSERS["vless"](VLESS, 3, "").stream_settings["wsSettings"])

        combined = TROJAN.replace("#original", "&fm=%7B#original")
        derived, strategy = repair_candidate_for_failure(failure(combined, MASK_ERROR))
        self.assertEqual(strategy, "omit_removed_tls_override+omit_rejected_finalmask")
        self.assertNotIn("insecure=", derived.lower())
        self.assertNotIn("fm=", derived)

        self.assertEqual(classify_xray_config_failure(BOOL_ERROR), "source_invalid")
        invalid_bool = TROJAN.replace("allowInsecure=1&insecure=1", "allowInsecure=maybe")
        self.assertIsNotNone(repair_candidate_for_failure(failure(invalid_bool, BOOL_ERROR)))
        self.assertIsNone(repair_candidate_for_failure(failure(VLESS, "unknown core failure")))
        disconnected = failure(TROJAN, TLS_ERROR)
        disconnected.stage = "connectivity"
        self.assertIsNone(repair_candidate_for_failure(disconnected))

    def test_only_a_successful_derived_connection_can_be_published(self):
        for derivative_works in (True, False):
            with self.subTest(derivative_works=derivative_works):
                calls = []

                def fake_batch(nodes, _xray, _log):
                    self.assertEqual(len(nodes), 1)
                    node = nodes[0]
                    calls.append(node.raw)
                    return [TestResult(
                        node.protocol, node.index, node.raw, node.host, node.port,
                        len(calls) == 2 and derivative_works,
                        "working" if len(calls) == 2 and derivative_works else "source_invalid" if len(calls) == 1 else "connectivity",
                        "" if len(calls) == 2 and derivative_works else TLS_ERROR if len(calls) == 1 else "connection failed",
                    )]

                with tempfile.TemporaryDirectory() as workdir:
                    with patch("vpn_pipeline_core.testing.run_v2rayn_real_ping_batch", side_effect=fake_batch):
                        row, = run_protocol_role("trojan", "server1", [(3, TROJAN)], Path("xray"), Path(workdir), "sha")
                self.assertEqual(len(calls), 2)
                self.assertEqual(calls[0], TROJAN)
                self.assertNotEqual(calls[1], TROJAN)
                self.assertEqual(row.ok, derivative_works)
                if derivative_works:
                    self.assertEqual(row.source_raw, TROJAN)
                    self.assertEqual(row.raw, calls[1])
                    self.assertEqual(row.repair_strategy, "omit_removed_tls_override")
                else:
                    self.assertEqual(row.raw, TROJAN)
                    self.assertFalse(row.source_raw)

    @unittest.skipUnless(os.environ.get("XRAY_TEST_BINARY"), "requires the selected Xray executable")
    def test_target_core_rejects_original_and_accepts_derived_config(self):
        xray = os.environ["XRAY_TEST_BINARY"]

        def check(raw):
            node = PARSERS[raw.split(":", 1)[0]](raw, 3, "")
            with tempfile.TemporaryDirectory() as workdir:
                config = Path(workdir) / "config.json"
                config.write_text(json.dumps(make_xray_config([(node, 23567)])), encoding="utf-8")
                process = subprocess.run(
                    [xray, "run", "-test", "-c", str(config)],
                    capture_output=True, text=True, timeout=10,
                )
            return process.returncode, process.stdout + process.stderr

        for original in (TROJAN, VLESS, TROJAN.replace("#original", "&fm=%7B#original"),
                         TROJAN.replace("allowInsecure=1&insecure=1", "allowInsecure=maybe")):
            with self.subTest(original=original):
                old_status, error = check(original)
                self.assertNotEqual(old_status, 0)
                derived = repair_candidate_for_failure(failure(original, error))
                self.assertIsNotNone(derived, error)
                new_status, new_error = check(derived[0])
                self.assertEqual(new_status, 0, new_error)


if __name__ == "__main__":
    unittest.main()
