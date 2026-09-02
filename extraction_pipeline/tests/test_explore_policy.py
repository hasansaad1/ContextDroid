"""Step 5 explore_policy unit tests — candidate builder, tier walk, invariants (no device)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llm_agent.explore_instrumentation import build_explore_candidate_instrumentation
from llm_agent.explore_policy import (
    ActionChooser,
    CandidateBuilder,
    ExploreState,
    ExploreTurnInput,
    InteractiveElement,
    NavGraphBfsExploreStrategy,
    RecoveryPolicy,
    choose_explore_action,
)
from llm_agent.navigation import _build_text_entry_input_action, _pick_text_entry_explore_action, _text_entry_probe_field_key
from llm_agent.screen import _normalized_elements

MENSA_XML = """<?xml version="1.0" encoding="UTF-8"?>
<hierarchy rotation="0">
  <node class="android.view.View" bounds="[21,348][1059,474]" clickable="true"
        enabled="true" package="ch.famoser.mensa"/>
  <node class="android.view.View" bounds="[21,475][1059,601]" clickable="true"
        enabled="true" package="ch.famoser.mensa"/>
  <node class="android.widget.EditText" bounds="[100,200][900,280]" clickable="false"
        focusable="true" enabled="true" package="ch.famoser.mensa"/>
</hierarchy>"""


class ExplorePolicyPurityTests(unittest.TestCase):
    def test_choose_explore_action_no_device(self):
        elements = _normalized_elements(MENSA_XML)
        state = ExploreState()
        turn = ExploreTurnInput(
            elements=elements,
            pkg="ch.famoser.mensa",
            screen_hash="abc123",
            fg_now="ch.famoser.mensa",
        )
        result = choose_explore_action(turn, state)
        self.assertIn(result.action.get("action_type"), {"tap", "back", "wait", "input"})
        self.assertGreaterEqual(result.nav_cands.__len__() + result.expand_cands.__len__(), 0)


class MensaAnonymousAdmissionTests(unittest.TestCase):
    def test_zero_labeled_anonymous_admitted_when_scarcity_open(self):
        elements = _normalized_elements(MENSA_XML)
        builder = CandidateBuilder()
        buckets = builder.build(
            elements,
            pkg="ch.famoser.mensa",
            screen_hash="sh1",
            permission_risk_keys=set(),
        )
        self.assertEqual(len(buckets.nav_cands), 0)
        self.assertEqual(len(buckets.other_cands), 2)
        expand = buckets.expand_cands
        self.assertEqual(len(expand), 2)
        inst = build_explore_candidate_instrumentation(
            elements,
            buckets.nav_cands,
            buckets.other_cands,
            expand,
            buckets.tab_cands,
            screen_hash="sh1",
            recovery_step=False,
        )
        self.assertEqual(inst["explore_candidate_counts"]["other_cands"], 2)


class ProtonVpnScarcityTests(unittest.TestCase):
    def test_hub_labeled_nav_shuts_anonymous_admission(self):
        elements = [
            {
                "package": "ch.protonvpn.android",
                "resource_id": "ch.protonvpn.android:id/connectButton",
                "content_desc": "Connect",
                "text": "",
                "class_name": "android.widget.Button",
                "bounds": "[100,50][900,150]",
                "clickable": "true",
            },
            {
                "package": "ch.protonvpn.android",
                "resource_id": "",
                "content_desc": "",
                "text": "",
                "class_name": "android.view.View",
                "bounds": "[21,348][1059,474]",
                "clickable": "true",
            },
        ]
        buckets = CandidateBuilder().build(
            elements,
            pkg="ch.protonvpn.android",
            screen_hash="hub",
            permission_risk_keys=set(),
        )
        self.assertEqual(len(buckets.other_cands), 1)
        self.assertTrue(buckets.other_cands[0].get("target_resource_id"))

    def test_sign_in_zero_label_opens_scarcity(self):
        sparse = [
            {
                "package": "ch.protonvpn.android",
                "resource_id": "",
                "content_desc": "",
                "text": "",
                "class_name": "android.view.View",
                "bounds": "[21,348][1059,474]",
                "clickable": "true",
            }
        ]
        buckets = CandidateBuilder().build(
            sparse,
            pkg="ch.protonvpn.android",
            screen_hash="signin",
            permission_risk_keys=set(),
        )
        self.assertEqual(len(buckets.other_cands), 1)
        self.assertFalse(buckets.other_cands[0].get("target_resource_id"))


class TextEntryTierTests(unittest.TestCase):
    def test_edittext_only_routes_to_input_not_tap(self):
        elements = [
            {
                "class_name": "android.widget.EditText",
                "resource_id": "",
                "content_desc": "",
                "text": "",
                "bounds": "[500,50][580,76]",
                "clickable": "true",
                "package": "at.krixec.ied",
            }
        ]
        state = ExploreState()
        turn = ExploreTurnInput(
            elements=elements,
            pkg="at.krixec.ied",
            screen_hash="ebf883f4",
            fg_now="at.krixec.ied",
        )
        result = choose_explore_action(turn, state)
        self.assertEqual(result.action.get("action_type"), "input")
        self.assertEqual(result.action.get("reason"), "bfs_text_entry_probe")

    def test_probe_repeat_guard_blocks_second_pick(self):
        elements = [
            {
                "class_name": "android.widget.EditText",
                "resource_id": "",
                "content_desc": "",
                "text": "",
                "bounds": "[500,50][580,76]",
                "clickable": "true",
                "package": "at.krixec.ied",
            }
        ]
        state = ExploreState()
        turn = ExploreTurnInput(
            elements=elements,
            pkg="at.krixec.ied",
            screen_hash="ebf883f4",
            fg_now="at.krixec.ied",
        )
        first = choose_explore_action(turn, state)
        act = first.action
        state.bfs_text_entry_probed_keys.add(_text_entry_probe_field_key("ebf883f4", act))
        state.bfs_back_streak = 0
        second = choose_explore_action(turn, state)
        self.assertNotEqual(second.action.get("reason"), "bfs_text_entry_probe")
        self.assertIn(second.action.get("action_type"), {"back", "wait"})


class InteractiveElementModelTests(unittest.TestCase):
    def test_identity_key_anonymous_uses_bounds(self):
        ie = InteractiveElement.from_dict(
            {
                "package": "at.krixec.ied",
                "resource_id": "",
                "content_desc": "",
                "text": "",
                "class_name": "android.widget.EditText",
                "bounds": "[500,50][580,76]",
                "clickable": "true",
            },
            screen_hash="ebf883f4",
        )
        self.assertFalse(ie.labeled)
        self.assertTrue(ie.is_text_entry)
        self.assertIn("xy:540:63", ie.identity_key)


class ExploreStrategySeamTests(unittest.TestCase):
    def test_resolve_noop_strategy_without_session_edit(self):
        import os

        from llm_agent.explore_policy import NoOpExploreStrategy, resolve_explore_strategy

        prev = os.environ.get("CONTEXTDROID_EXPLORE_STRATEGY")
        os.environ["CONTEXTDROID_EXPLORE_STRATEGY"] = "noop"
        try:
            strat = resolve_explore_strategy()
            self.assertIsInstance(strat, NoOpExploreStrategy)
        finally:
            if prev is None:
                os.environ.pop("CONTEXTDROID_EXPLORE_STRATEGY", None)
            else:
                os.environ["CONTEXTDROID_EXPLORE_STRATEGY"] = prev

    def test_default_strategy_delegates_to_choose(self):
        elements = _normalized_elements(MENSA_XML)
        state = ExploreState()
        turn = ExploreTurnInput(
            elements=elements,
            pkg="ch.famoser.mensa",
            screen_hash="x",
            fg_now="ch.famoser.mensa",
        )
        r1 = choose_explore_action(turn, state)
        state2 = ExploreState()
        r2 = NavGraphBfsExploreStrategy().pick_action(turn, state2)
        self.assertEqual(
            r1.action.get("action_type"),
            r2.action.get("action_type"),
        )
        self.assertEqual(
            r1.action.get("reason"),
            r2.action.get("reason"),
        )


if __name__ == "__main__":
    unittest.main()
