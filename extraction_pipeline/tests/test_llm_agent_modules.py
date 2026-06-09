"""Unit tests for extracted llm_agent package modules."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llm_agent.action_model import _action_signature_for_candidate, _nav_target_key
from llm_agent.goals import (
    _goal_execute_status,
    _goal_opens_search_ui,
    _search_open_goal_recently_satisfied,
)
from llm_agent.planner import _parse_actions_list
from llm_agent.screen import (
    _is_definite_search_launch_widget,
    _is_false_positive_search_launch_widget,
)


BITBANANA_SCAN_STEP = {
    "parsed_action": {
        "action_type": "tap",
        "target_resource_id": "app.michaelwuensch.bitbanana:id/scanButton",
        "reason": "engine_route_tap_search_launch",
    },
    "action_success": True,
    "screen_hash": "04ee8a3c3703423ef17d2f900043b163eb5a65c50cda1167994c556a68e613e1",
    "screen_hash_after": "f93d6ad73a3fe34fe752c4dbd0f0c927f7cf5cd4251967f20e0c60c0e41b6898",
}

SCANNER_ELEMENTS = [
    {
        "resource_id": "app.michaelwuensch.bitbanana:id/scannerPaste",
        "class_name": "FrameLayout",
        "content_desc": "",
        "text": "",
        "bounds": "[212,1598][868,1742]",
    },
]


class TestSearchLaunchHeuristics(unittest.TestCase):
    def test_scanbutton_is_search_launch(self):
        e = {
            "resource_id": "app.michaelwuensch.bitbanana:id/scanButton",
            "class_name": "LinearLayout",
            "content_desc": "",
            "text": "",
        }
        self.assertTrue(_is_definite_search_launch_widget(e))

    def test_backup_search_is_false_positive(self):
        e = {
            "resource_id": "com.aefyr.sai.fdroid:id/ib_backup_search_more",
            "class_name": "ImageButton",
            "content_desc": "search",
            "text": "",
        }
        self.assertTrue(_is_false_positive_search_launch_widget(e))
        self.assertFalse(_is_definite_search_launch_widget(e))


class TestSearchGoalFsm(unittest.TestCase):
    def test_tap_search_satisfied_after_scanbutton_open(self):
        goal = "Tap Search"
        recent = [BITBANANA_SCAN_STEP]
        app_state = {
            "search_launch_visible": False,
            "text_entry_visible": False,
            "search_open": False,
        }
        self.assertTrue(_search_open_goal_recently_satisfied(recent))
        self.assertEqual(
            _goal_execute_status(
                goal,
                SCANNER_ELEMENTS,
                recent,
                app_state=app_state,
                target_pkg="app.michaelwuensch.bitbanana",
            ),
            "satisfied",
        )

    def test_goal_opens_search_ui_recognizes_tap_search(self):
        self.assertTrue(_goal_opens_search_ui("Tap Search"))


class TestPlannerContract(unittest.TestCase):
    def test_parses_json_in_markdown_fence(self):
        raw = (
            "Here is the action:\n```json\n"
            '{"action_type": "tap", "target_resource_id": "com.example:id/btn", "x": 1, "y": 2}\n'
            "```"
        )
        acts = _parse_actions_list(raw, max_actions=1)
        self.assertEqual(len(acts), 1)
        self.assertEqual(acts[0]["action_type"], "tap")

    def test_prefers_action_json_over_elements_hierarchy_dump(self):
        raw = json.dumps(
            {
                "elements": [{"resource_id": "a"}, {"resource_id": "b"}],
                "actions": [{"action_type": "wait", "reason": "hold"}],
            }
        )
        acts = _parse_actions_list(raw, max_actions=1)
        self.assertEqual(acts[0]["action_type"], "wait")


class TestActionModel(unittest.TestCase):
    def test_nav_target_key_uses_rid_and_cd(self):
        act = {"target_resource_id": "com.app:id/home", "target_content_desc": "Home"}
        self.assertEqual(_nav_target_key(act), "com.app:id/home|Home")


class TestModuleImportSmoke(unittest.TestCase):
    """Import every llm_agent module and exercise key constants/helpers offline."""

    MODULES = (
        "llm_agent",
        "llm_agent.config",
        "llm_agent.screen",
        "llm_agent.device",
        "llm_agent.dialogs",
        "llm_agent.action_model",
        "llm_agent.actions",
        "llm_agent.goals",
        "llm_agent.planner",
        "llm_agent.navigation",
        "llm_agent.routing",
        "llm_agent.handoff",
        "llm_agent.audit",
        "llm_agent.session",
    )

    def test_all_modules_import(self):
        import importlib

        for name in self.MODULES:
            with self.subTest(module=name):
                importlib.import_module(name)

    def test_refactor_constants_are_defined(self):
        from llm_agent.audit import HUMAN_UX_CRITERIA_VERSION
        from llm_agent.config import _ABSTRACT_PLANNER_GOAL_RE, _SEARCH_UI_HINT_RE
        from llm_agent.dialogs import _PERMISSION_RISK_RID_RE
        from llm_agent.goals import _NAV_TOKEN_ORDER
        from llm_agent.screen import _EMPTY_STATE_PATTERNS

        self.assertEqual(HUMAN_UX_CRITERIA_VERSION, "human_ux_v3")
        self.assertTrue(_ABSTRACT_PLANNER_GOAL_RE.search("investigate app architecture"))
        self.assertTrue(_SEARCH_UI_HINT_RE.search("search field"))
        self.assertTrue(_PERMISSION_RISK_RID_RE.search("find_people_nearby"))
        self.assertIn("categories", _NAV_TOKEN_ORDER)
        self.assertIn("no results", _EMPTY_STATE_PATTERNS)


if __name__ == "__main__":
    unittest.main()
