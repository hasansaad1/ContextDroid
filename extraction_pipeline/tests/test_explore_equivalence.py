"""Step 5 — deterministic old-vs-new explore equivalence on real input snapshots."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llm_agent.explore_equivalence import run_snapshot
from llm_agent.explore_snapshot_corpus import build_equivalence_snapshot_corpus


class ExploreEquivalenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = build_equivalence_snapshot_corpus()
        cls.reports = [run_snapshot(s) for s in cls.corpus]
        cls.by_id = {r.snapshot_id: r for r in cls.reports}

    def test_corpus_has_minimum_snapshot_count(self):
        self.assertGreaterEqual(len(self.corpus), 15)

    def test_legacy_equals_new_on_every_snapshot(self):
        failures = [r for r in self.reports if not r.passed]
        if failures:
            lines = [
                f"{r.snapshot_id} ({r.category}): {'; '.join(r.errors)}"
                for r in failures
            ]
            self.fail("Equivalence failures:\n" + "\n".join(lines))

    def test_mensa_anonymous_admission_fixture(self):
        r = self.by_id["mensa_anonymous_admission_empty_state"]
        self.assertTrue(r.passed, r.errors)
        self.assertEqual(r.legacy_action, r.new_action)
        self.assertEqual(r.new_action.get("reason"), "bfs_expand_frontier")

    def test_protonvpn_hub_scarcity_shut_fixture(self):
        r = self.by_id["protonvpn_hub_scarcity_shut"]
        self.assertTrue(r.passed, r.errors)
        self.assertTrue(r.new_action.get("target_resource_id"))

    def test_protonvpn_signin_scarcity_open_fixture(self):
        r = self.by_id["protonvpn_signin_scarcity_open"]
        self.assertTrue(r.passed, r.errors)
        self.assertFalse(r.new_action.get("target_resource_id"))

    def test_ied_text_entry_probe_fixture(self):
        r = self.by_id["ied_text_entry_probe"]
        self.assertTrue(r.passed, r.errors)
        self.assertEqual(r.new_action.get("action_type"), "input")
        self.assertEqual(r.new_action.get("reason"), "bfs_text_entry_probe")

    def test_ied_probe_repeat_guard_fixture(self):
        r = self.by_id["ied_text_entry_probe_repeat_guard"]
        self.assertTrue(r.passed, r.errors)
        self.assertNotEqual(r.new_action.get("reason"), "bfs_text_entry_probe")
        self.assertIn(r.new_action.get("action_type"), {"back", "wait"})

    def test_mensa_11tap_replay_snapshots_legacy_equals_new(self):
        replay = [r for r in self.reports if r.category == "mensa_replay_11tap"]
        self.assertGreaterEqual(len(replay), 11)
        for r in replay:
            self.assertEqual(r.legacy_action, r.new_action, r.snapshot_id)

    def test_mensa_9tap_launch_screen_snapshot_legacy_equals_new(self):
        first = self.by_id.get("mensa_step1_c721dd89")
        if first is None:
            first = next(r for r in self.reports if "step1_c721dd89" in r.snapshot_id)
        self.assertEqual(first.legacy_action, first.new_action)
        self.assertEqual(first.new_action.get("reason"), "bfs_expand_frontier")
        self.assertEqual(first.new_action.get("x"), 1007)
        self.assertEqual(first.new_action.get("y"), 148)


if __name__ == "__main__":
    unittest.main()
