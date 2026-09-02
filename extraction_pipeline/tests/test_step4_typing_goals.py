"""Step 4 — typing goal classifier and EditText routing."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llm_agent.goals import (
    _derive_app_screen_state,
    _goal_execute_status,
    _goal_needs_text_entry_field,
    _is_degenerate_transitions_goal,
    _sanitize_ux_goal_strings,
    _typing_goal_recently_satisfied,
)
from llm_agent.navigation import (
    _build_text_entry_input_action,
    _pick_text_entry_explore_action,
    _text_entry_probe_field_key,
)


class Step4TypingGoalsTests(unittest.TestCase):
    def test_input_text_in_field_is_text_entry_goal(self):
        self.assertTrue(_goal_needs_text_entry_field("Input text in field"))
        self.assertTrue(_goal_needs_text_entry_field("Input text in username"))
        self.assertFalse(_goal_needs_text_entry_field("Tap Settings"))

    def test_search_query_still_text_entry(self):
        self.assertTrue(_goal_needs_text_entry_field("Input search query"))
        self.assertTrue(_goal_needs_text_entry_field("Type query in search box"))

    def test_degenerate_transitions_rejected(self):
        self.assertTrue(_is_degenerate_transitions_goal("Tap TRANSITIONS: foo"))
        cleaned = _sanitize_ux_goal_strings(["Tap Categories", "Tap TRANSITIONS: sparse"])
        self.assertEqual(cleaned, ["Tap Categories"])

    def test_lone_edittext_is_text_entry_not_search(self):
        elements = [
            {
                "class_name": "android.widget.EditText",
                "resource_id": "com.app:id/editor",
                "content_desc": "",
                "text": "",
                "bounds": "[0,100][100,200]",
                "clickable": "true",
            }
        ]
        state = _derive_app_screen_state(elements, "com.app")
        self.assertEqual(state["screen_role"], "text_entry")
        self.assertFalse(state["search_open"])

    def test_unchanged_taps_do_not_satisfy_typing_goal(self):
        elements = [
            {
                "class_name": "android.widget.EditText",
                "resource_id": "com.app:id/editor",
                "content_desc": "",
                "text": "",
                "bounds": "[0,100][100,200]",
                "clickable": "true",
            }
        ]
        recent = [
            {
                "parsed_action": {"action_type": "tap"},
                "action_success": True,
                "screen_hash": "aaa",
                "screen_hash_after": "aaa",
            },
            {
                "parsed_action": {"action_type": "tap"},
                "action_success": True,
                "screen_hash": "aaa",
                "screen_hash_after": "aaa",
            },
        ]
        status = _goal_execute_status(
            "Input text in field",
            elements,
            recent,
            target_pkg="com.app",
        )
        self.assertEqual(status, "feasible")

    def test_input_event_satisfies_typing_goal(self):
        elements = [
            {
                "class_name": "android.widget.EditText",
                "resource_id": "com.app:id/editor",
                "content_desc": "",
                "text": "demo",
                "bounds": "[0,100][100,200]",
                "clickable": "true",
            }
        ]
        recent = [
            {
                "parsed_action": {"action_type": "input", "text": "demo"},
                "action_success": True,
            }
        ]
        self.assertTrue(_typing_goal_recently_satisfied(recent))
        status = _goal_execute_status(
            "Input text in field",
            elements,
            recent,
            target_pkg="com.app",
        )
        self.assertEqual(status, "satisfied")

    def test_explore_input_action_from_edittext_only_screen(self):
        elements = [
            {
                "class_name": "android.widget.EditText",
                "resource_id": "com.app:id/user",
                "content_desc": "",
                "text": "",
                "bounds": "[0,100][100,200]",
                "clickable": "true",
            }
        ]
        act = _pick_text_entry_explore_action(elements, "com.app")
        self.assertIsNotNone(act)
        assert act is not None
        self.assertEqual(act["action_type"], "input")
        self.assertTrue(str(act.get("text") or "").strip())
        self.assertEqual(act["reason"], "bfs_text_entry_probe")

    def test_text_entry_probe_repeat_guard_blocks_same_field(self):
        elements = [
            {
                "class_name": "android.widget.EditText",
                "resource_id": "",
                "content_desc": "",
                "text": "",
                "bounds": "[500,50][580,76]",
                "clickable": "true",
            }
        ]
        probed: set[str] = set()
        first = _pick_text_entry_explore_action(
            elements, "com.app", screen_hash="ebf883f4", probed_keys=probed
        )
        self.assertIsNotNone(first)
        assert first is not None
        probed.add(_text_entry_probe_field_key("ebf883f4", first))
        second = _pick_text_entry_explore_action(
            elements, "com.app", screen_hash="ebf883f4", probed_keys=probed
        )
        self.assertIsNone(second)

    def test_execute_route_builds_input_not_advance(self):
        elements = [
            {
                "class_name": "android.widget.EditText",
                "resource_id": "com.app:id/user",
                "content_desc": "",
                "text": "",
                "bounds": "[0,100][100,200]",
                "clickable": "true",
            }
        ]
        act = _build_text_entry_input_action(
            elements,
            target_pkg="com.app",
            reason="engine_route_text_entry",
        )
        self.assertIsNotNone(act)
        assert act is not None
        self.assertEqual(act["action_type"], "input")


if __name__ == "__main__":
    unittest.main()
