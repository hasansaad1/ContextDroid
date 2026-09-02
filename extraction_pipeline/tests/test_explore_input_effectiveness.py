"""Explore input effectiveness and functional-tap counting (Step 4 defect fixes)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quality_rules import _explore_functional_tap, _explore_metrics


class ExploreInputEffectivenessTests(unittest.TestCase):
    def test_no_op_input_not_functional_tap(self):
        act = {
            "action_success": True,
            "pipeline_phase": "explore",
            "screen_hash": "aaa",
            "screen_hash_after": "aaa",
            "explore_input_effective": False,
            "parsed_action": {"action_type": "input", "text": "demo", "reason": "bfs_text_entry_probe"},
        }
        self.assertFalse(_explore_functional_tap(act))

    def test_effective_input_counts_as_functional_tap(self):
        act = {
            "action_success": True,
            "pipeline_phase": "explore",
            "screen_hash": "aaa",
            "screen_hash_after": "bbb",
            "explore_input_effective": True,
            "parsed_action": {"action_type": "input", "text": "demo", "reason": "bfs_text_entry_probe"},
        }
        self.assertTrue(_explore_functional_tap(act))

    def test_legacy_log_screen_hash_fallback(self):
        act = {
            "action_success": True,
            "pipeline_phase": "explore",
            "screen_hash": "aaa",
            "screen_hash_after": "bbb",
            "parsed_action": {"action_type": "input", "text": "demo"},
        }
        self.assertTrue(_explore_functional_tap(act))

    def test_repeated_no_op_probes_inflate_ft_before_stamp(self):
        """Seven identical no-op probes should count as 0 effective functional taps."""
        probes = [
            {
                "action_success": True,
                "pipeline_phase": "explore",
                "screen_hash": "ebf883f4",
                "screen_hash_after": "ebf883f4",
                "explore_input_effective": False,
                "parsed_action": {"action_type": "input", "text": "demo", "reason": "bfs_text_entry_probe"},
            }
            for _ in range(7)
        ]
        m = _explore_metrics(probes)
        self.assertEqual(m["explore_functional_tap_count"], 0)


if __name__ == "__main__":
    unittest.main()
