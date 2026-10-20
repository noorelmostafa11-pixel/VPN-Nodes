"""Successful-result merge uses only the core's connection identity."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/xray_matrix"))
from finalize_catalog import deduplicate_working


class ConnectionDedupTests(unittest.TestCase):
    def test_shard_completion_order_does_not_choose_the_winning_link(self):
        key = "xray-outbound-v1:" + "a" * 64
        rows = [
            {"protocol": "vless", "index": 7, "raw": "vless://u@same?path=/&type=ws#later", "connection_key": key},
            {"protocol": "vless", "index": 0, "raw": "vless://u@same?type=ws&path=%2F#original", "connection_key": key},
            {"protocol": "vless", "index": 4, "raw": "vless://other@same?type=ws&path=%2F", "connection_key": "xray-outbound-v1:" + "b" * 64},
        ]
        selected, exact, fragment, semantic = deduplicate_working(rows)
        self.assertEqual([r["index"] for r in selected], [0, 4])
        self.assertEqual(selected[0]["raw"], rows[1]["raw"])
        self.assertEqual((exact, fragment, semantic), (0, 0, 1))

    def test_missing_identity_never_guesses_equivalence_or_drops_options(self):
        rows = [{"protocol": "vless", "index": i, "raw": raw} for i, raw in enumerate([
            "vless://u@same?path=%2F&type=ws", "vless://u@same?type=ws&path=/",
            "vless://u@same?path=%2F&type=ws&future-option=1",
        ])]
        selected, *removed = deduplicate_working(rows)
        self.assertEqual(selected, rows)
        self.assertEqual(removed, [0, 0, 0])

    def test_protocols_and_distinct_core_settings_remain_separate(self):
        rows = [{"protocol": p, "index": i, "raw": f"{p}://opaque-{i}",
                 "connection_key": "xray-outbound-v1:" + char * 64}
                for i, (p, char) in enumerate([("vless", "a"), ("vless", "b"), ("trojan", "a")])]
        selected, *removed = deduplicate_working(rows)
        self.assertEqual(selected, rows)
        self.assertEqual(removed, [0, 0, 0])


if __name__ == "__main__":
    unittest.main()
