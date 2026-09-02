"""Unit tests for extracted llm_agent package modules."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

REPO_ROOT = Path(__file__).resolve().parents[2]

from llm_agent.action_model import _action_signature_for_candidate, _nav_target_key
from llm_agent.goals import (
    _finalize_post_explore_goals,
    _goal_execute_status,
    _goal_is_forward,
    _goal_opens_search_ui,
    _search_open_goal_recently_satisfied,
    _synthesize_tap_goals_from_digest,
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


class TestVagueBackGoals(unittest.TestCase):
    def test_finalize_strips_back_to_hub(self):
        digest = (
            "a9d610ea|Categories categories FrameLayout · Search fab_search ImageButton\n"
            "7050e779|Categories categories FrameLayout · Search fab_search ImageButton · CardView"
        )
        goals = _finalize_post_explore_goals(
            [
                "Tap Search",
                "Back to hub",
                "Tap Categories",
                "Wait for UI to settle",
            ],
            screen_map_text=digest,
        )
        self.assertNotIn("Back to hub", goals)
        self.assertIn("Tap Categories", goals)


MOBILIZON_DIGEST = "\n".join(
    [
        "998a1059ec4b635b | Search action_search TextView · Open the menu ImageButton · Open main menu Button",
        "b328099ca3f50393 | Search action_search TextView · nav_explore LinearLayoutCompat · nav_login LinearLayoutCompat · nav_my_event LinearLayoutCompat",
    ]
)

PROTONVPN_DIGEST = "\n".join(
    [
        "b1f7abd8f50ce35b | Sign in sign_in Button · Create an account sign_up Button",
        "19aa1aba3d697094 | Next nextButton Button · input EditText · Close ImageButton",
    ]
)

LIBCHECKER_DIGEST = "\n".join(
    [
        "eb6436ea3e5c9478 | Advanced menu advanced Button · Search search Button · Settings navigation_settings FrameLayout",
        "385a9119256f42d6 | Apps navigation_app_list FrameLayout · Statistics navigation_classify FrameLayout",
    ]
)


class TestDigestDrivenGoalSynthesis(unittest.TestCase):
    def test_synthesize_mobilizon_controls(self):
        goals = _synthesize_tap_goals_from_digest(MOBILIZON_DIGEST, max_n=8)
        joined = " ".join(goals).lower()
        self.assertIn("explore", joined)
        self.assertIn("login", joined)
        self.assertIn("search", joined)
        self.assertGreaterEqual(sum(1 for g in goals if _goal_is_forward(g)), 3)

    def test_synthesize_protonvpn_controls(self):
        goals = _synthesize_tap_goals_from_digest(PROTONVPN_DIGEST, max_n=8)
        joined = " ".join(goals).lower()
        self.assertIn("sign in", joined)
        self.assertIn("create an account", joined)
        self.assertIn("next", joined)

    def test_finalize_mobilizon_not_back_only(self):
        goals = _finalize_post_explore_goals([], MOBILIZON_DIGEST)
        forward = [g for g in goals if _goal_is_forward(g)]
        self.assertGreaterEqual(len(forward), 4)
        self.assertGreater(len(forward), sum(1 for g in goals if g.lower().startswith("press back")))

    def test_finalize_protonvpn_not_back_only(self):
        goals = _finalize_post_explore_goals([], PROTONVPN_DIGEST)
        forward = [g for g in goals if _goal_is_forward(g)]
        self.assertGreaterEqual(len(forward), 4)

    def test_finalize_libchecker_regression(self):
        goals = _finalize_post_explore_goals(
            ["Tap Settings", "Tap Search", "Wait for UI to settle"],
            LIBCHECKER_DIGEST,
        )
        self.assertIn("Tap Settings", goals)
        self.assertGreaterEqual(sum(1 for g in goals if _goal_is_forward(g)), 3)

    def test_planner_goal_survives_digest_overlap(self):
        goals = _finalize_post_explore_goals(
            ["Tap nav_explore", "Tap Sign in", "Wait for UI to settle"],
            MOBILIZON_DIGEST,
        )
        self.assertIn("Tap nav_explore", goals)

    def test_route_back_goal_on_search_results(self):
        from llm_agent.routing import _route_controller_action_for_goal

        elements = [
            {
                "resource_id": "org.fdroid.fdroid:id/categories",
                "content_desc": "Categories",
                "class_name": "android.widget.FrameLayout",
                "bounds": "[216,1584][432,1794]",
            },
            {
                "resource_id": "org.fdroid.fdroid:id/fab_search",
                "content_desc": "Search",
                "class_name": "android.widget.ImageButton",
                "bounds": "[891,1395][1038,1542]",
            },
        ]
        route = _route_controller_action_for_goal(
            {"goal": "Back to hub", "nav_token": "", "target_keys": []},
            {"targets": {}, "edges": []},
            {
                "search_open": False,
                "visible_nav_tokens": ["categories", "nearby", "settings", "updates"],
            },
            elements,
            "org.fdroid.fdroid",
        )
        self.assertEqual(route, {"action_type": "advance_goal", "reason": "engine_back_goal_at_hub"})

    def test_route_back_goal_advances_when_app_not_foreground(self):
        from llm_agent.routing import _route_controller_action_for_goal

        route = _route_controller_action_for_goal(
            {"goal": "Press Back to return to the main app list", "nav_token": "", "target_keys": []},
            {"targets": {}, "edges": []},
            {
                "search_open": False,
                "foreground_package": "com.example.foreign.app",
                "visible_nav_tokens": [],
            },
            [],
            "app.fedilab.mobilizon",
        )
        self.assertEqual(route, {"action_type": "advance_goal", "reason": "engine_back_goal_app_not_foreground"})

    def test_route_back_goal_advances_on_exit_surface(self):
        from llm_agent.routing import _route_controller_action_for_goal

        route = _route_controller_action_for_goal(
            {"goal": "Back to previous screen", "nav_token": "", "target_keys": []},
            {"targets": {}, "edges": []},
            {
                "search_open": False,
                "foreground_package": "com.android.chrome",
                "visible_nav_tokens": [],
            },
            [],
            "app.fedilab.mobilizon",
        )
        self.assertEqual(route, {"action_type": "advance_goal", "reason": "engine_back_goal_on_exit_surface"})

    def test_route_back_goal_advances_when_stuck(self):
        from llm_agent.routing import _route_controller_action_for_goal

        recent = []
        for _ in range(3):
            recent.append(
                {
                    "action_success": True,
                    "screen_hash": "abc",
                    "screen_hash_after": "abc",
                    "parsed_action": {"action_type": "back", "reason": "engine_route_back_goal"},
                }
            )
        route = _route_controller_action_for_goal(
            {"goal": "Press Back", "nav_token": "", "target_keys": []},
            {"targets": {}, "edges": []},
            {
                "search_open": False,
                "foreground_package": "app.fedilab.mobilizon",
                "visible_nav_tokens": [],
            },
            [],
            "app.fedilab.mobilizon",
            recent_actions=recent,
        )
        self.assertEqual(route, {"action_type": "advance_goal", "reason": "engine_back_goal_stuck"})


class TestExecuteEngineFallback(unittest.TestCase):
    def test_goal_label_needles_from_tap_goal(self):
        from llm_agent.routing import _goal_label_needles

        needles = _goal_label_needles("Tap Categories")
        self.assertIn("categories", needles)

    def test_tap_goal_label_fallback_matches_visible_control(self):
        from llm_agent.routing import _execute_engine_fallback_action

        elements = [
            {
                "resource_id": "org.fdroid.fdroid:id/categories",
                "content_desc": "Categories",
                "class_name": "android.widget.FrameLayout",
                "bounds": "[216,1584][432,1794]",
            },
        ]
        action = _execute_engine_fallback_action(
            {"goal": "Tap Categories", "nav_token": "", "target_keys": []},
            "Tap Categories",
            {"targets": {}, "edges": []},
            {"search_open": False, "visible_nav_tokens": []},
            elements,
            "org.fdroid.fdroid",
        )
        self.assertEqual(action.get("action_type"), "tap")
        self.assertEqual(action.get("reason"), "engine_fallback_tap_goal_label")
        self.assertEqual(action.get("target_resource_id"), "org.fdroid.fdroid:id/categories")

    def test_fallback_skips_blocked_goal(self):
        from llm_agent.routing import _execute_engine_fallback_action

        action = _execute_engine_fallback_action(
            {"goal": "Tap Missing", "nav_token": "", "target_keys": []},
            "Tap Missing",
            {"targets": {}, "edges": []},
            {"search_open": False},
            [],
            "com.example.app",
            goal_status="blocked",
            goal_blocked_turns=2,
        )
        self.assertEqual(action, {"action_type": "advance_goal", "reason": "engine_fallback_skip_blocked"})

    def test_fallback_opens_search_when_goal_requires(self):
        from llm_agent.routing import _execute_engine_fallback_action

        elements = [
            {
                "resource_id": "org.fdroid.fdroid:id/fab_search",
                "content_desc": "Search",
                "class_name": "android.widget.ImageButton",
                "bounds": "[891,1395][1038,1542]",
            },
        ]
        action = _execute_engine_fallback_action(
            {"goal": "Open search", "nav_token": "", "target_keys": []},
            "Open search UI",
            {"targets": {}, "edges": []},
            {"search_open": False},
            elements,
            "org.fdroid.fdroid",
        )
        self.assertEqual(action.get("action_type"), "tap")
        self.assertEqual(action.get("reason"), "engine_route_tap_search_launch")


class TestPhase3PrimaryUxBlend(unittest.TestCase):
    def test_sparse_goals_lower_blend_index(self):
        from llm_agent.config import (
            _PRIMARY_UX_BLEND_AFTER_GOAL_INDEX,
            _PRIMARY_UX_BLEND_SPARSE_AFTER_GOAL_INDEX,
            _PRIMARY_UX_SPARSE_GOALS_THRESHOLD,
            _effective_primary_blend_goal_index,
            _primary_blend_after_sec_for_goals,
        )

        dense_idx = _effective_primary_blend_goal_index(_PRIMARY_UX_SPARSE_GOALS_THRESHOLD)
        sparse_idx = _effective_primary_blend_goal_index(_PRIMARY_UX_SPARSE_GOALS_THRESHOLD - 1)
        self.assertEqual(dense_idx, _PRIMARY_UX_BLEND_AFTER_GOAL_INDEX)
        self.assertEqual(sparse_idx, _PRIMARY_UX_BLEND_SPARSE_AFTER_GOAL_INDEX)
        self.assertLess(sparse_idx, dense_idx)

        dense_sec = _primary_blend_after_sec_for_goals(400, _PRIMARY_UX_SPARSE_GOALS_THRESHOLD)
        sparse_sec = _primary_blend_after_sec_for_goals(400, _PRIMARY_UX_SPARSE_GOALS_THRESHOLD - 1)
        self.assertLess(sparse_sec, dense_sec)


class TestDigestSearchPlanning(unittest.TestCase):
    def test_search_button_not_suppressed_by_sendinput_on_same_line(self):
        from llm_agent.goals import _ensure_search_flow_goals, _screen_map_has_search_surface

        hint = (
            "Search search_button ImageView · Address or payment data sendInput EditText"
        )
        digest = f"abc|{hint}"
        self.assertTrue(_screen_map_has_search_surface(digest))
        goals = _ensure_search_flow_goals(
            ["Input search query", "Wait for UI to settle"],
            screen_map_text=digest,
        )
        self.assertIn("Tap Search", goals)
        self.assertLess(goals.index("Tap Search"), goals.index("Input search query"))


class TestBfsLayerDeepening(unittest.TestCase):
    def test_nav_explore_triggers_interior_expand(self):
        from llm_agent.navigation import _bfs_tap_triggers_interior_expand

        action = {
            "action_type": "tap",
            "target_resource_id": "app.fedilab.mobilizon:id/nav_explore",
            "target_content_desc": "",
            "reason": "bfs_graph_uncovered_tab",
        }
        self.assertTrue(_bfs_tap_triggers_interior_expand(action))

    def test_sign_in_does_not_trigger_interior_expand(self):
        from llm_agent.navigation import _bfs_tap_triggers_interior_expand

        action = {
            "action_type": "tap",
            "target_resource_id": "ch.protonvpn.android:id/sign_in",
            "target_content_desc": "Sign in",
            "reason": "bfs_graph_uncovered_nav",
        }
        self.assertFalse(_bfs_tap_triggers_interior_expand(action))

    def test_login_screen_not_layer_hub(self):
        from llm_agent.navigation import _bfs_screen_supports_layer_expansion

        nav = [
            {
                "action_type": "tap",
                "target_resource_id": "ch.protonvpn.android:id/sign_in",
                "target_content_desc": "Sign in",
            },
            {
                "action_type": "tap",
                "target_resource_id": "ch.protonvpn.android:id/sign_up",
                "target_content_desc": "Create an account",
            },
        ]
        self.assertFalse(_bfs_screen_supports_layer_expansion([], nav))

    def test_mobilizon_nav_tabs_support_layer_expansion(self):
        from llm_agent.navigation import _bfs_screen_supports_layer_expansion

        nav = [
            {
                "action_type": "tap",
                "target_resource_id": "app.fedilab.mobilizon:id/nav_explore",
                "target_content_desc": "",
            },
            {
                "action_type": "tap",
                "target_resource_id": "app.fedilab.mobilizon:id/nav_login",
                "target_content_desc": "",
            },
        ]
        self.assertTrue(_bfs_screen_supports_layer_expansion([], nav))

    def test_fdroid_categories_still_triggers_interior_expand(self):
        from llm_agent.navigation import _bfs_tap_triggers_interior_expand

        action = {
            "action_type": "tap",
            "target_resource_id": "org.fdroid.fdroid:id/categories",
            "target_content_desc": "Categories",
            "reason": "bfs_tab_frontier",
        }
        self.assertTrue(_bfs_tap_triggers_interior_expand(action))

    def test_pick_untried_expand_skips_attempted_keys(self):
        from llm_agent.navigation import _bfs_pick_untried_expand_candidate

        expand = [
            {
                "action_type": "tap",
                "target_resource_id": "com.app:id/item_one",
                "target_content_desc": "Item one",
                "x": 1,
                "y": 2,
            },
            {
                "action_type": "tap",
                "target_resource_id": "com.app:id/item_two",
                "target_content_desc": "Item two",
                "x": 3,
                "y": 4,
            },
        ]
        first = _bfs_pick_untried_expand_candidate(expand, target_pkg="com.app", tried_keys=set())
        self.assertEqual(first["target_resource_id"], "com.app:id/item_one")
        tried = {"com.app:id/item_one|Item one"}
        second = _bfs_pick_untried_expand_candidate(expand, target_pkg="com.app", tried_keys=tried)
        self.assertEqual(second["target_resource_id"], "com.app:id/item_two")
        self.assertEqual(second["reason"], "bfs_expand_layer_depth")


class TestPlannerAliasNormalization(unittest.TestCase):
    def test_element_id_maps_to_target_resource_id(self):
        raw = json.dumps(
            {
                "actions": [
                    {
                        "action_type": "tap",
                        "element_id": "com.example:id/menu_backup",
                    }
                ]
            }
        )
        acts = _parse_actions_list(raw, max_actions=1)
        self.assertEqual(acts[0]["target_resource_id"], "com.example:id/menu_backup")


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


class TestGuardInterventionAudit(unittest.TestCase):
    def test_successful_engine_primary_not_guard_issue(self):
        from llm_agent.audit import _is_guard_or_planner_contract_issue

        ev = {
            "action_success": True,
            "execution_kind": "direct",
            "pipeline_phase": "primary_ux",
            "parsed_action": {
                "action_type": "tap",
                "reason": "engine_primary_browse_current_content_surface_tap",
            },
            "audit_assessment": {
                "codes": ["engine_replaced_planner_contract_failure"],
            },
        }
        self.assertFalse(_is_guard_or_planner_contract_issue(ev))

    def test_primary_ux_scroll_recovery_not_guard_issue(self):
        from llm_agent.audit import _is_guard_or_planner_contract_issue

        ev = {
            "action_success": True,
            "execution_kind": "repaired",
            "pipeline_phase": "primary_ux",
            "parsed_action": {"action_type": "swipe", "reason": "primary_ux_scroll"},
            "audit_assessment": {
                "codes": [
                    "guard_modified_planner_output",
                    "swipe_ok_but_no_screen_delta",
                    "execution_kind_repaired",
                ],
            },
        }
        self.assertFalse(_is_guard_or_planner_contract_issue(ev))

    def test_blocked_invisible_tap_is_guard_issue(self):
        from llm_agent.audit import _is_guard_or_planner_contract_issue

        ev = {
            "action_success": True,
            "execution_kind": "blocked",
            "pipeline_phase": "primary_ux",
            "parsed_action": {"action_type": "wait", "reason": "guard_invisible_tap_target"},
            "audit_assessment": {
                "codes": [
                    "guard_modified_planner_output",
                    "guard_invisible_tap_target",
                    "no_direct_action_step",
                    "execution_kind_blocked",
                ],
            },
        }
        self.assertTrue(_is_guard_or_planner_contract_issue(ev))

    def test_sanitize_converts_guard_wait_to_visible_action(self):
        from llm_agent.actions import _sanitize_primary_ux_action

        elements = [
            {
                "resource_id": "app.michaelwuensch.bitbanana:id/scannerPaste",
                "class_name": "FrameLayout",
                "content_desc": "",
                "text": "",
                "bounds": "[212,1598][868,1742]",
            },
        ]
        action = {"action_type": "wait", "reason": "guard_invisible_tap_target"}
        out, _ = _sanitize_primary_ux_action(
            action, elements, "app.michaelwuensch.bitbanana", stagnant=0
        )
        self.assertNotEqual(out.get("action_type"), "wait")
        self.assertFalse(str(out.get("reason") or "").startswith("guard_"))

    def test_primary_ux_scroll_is_direct_execution_kind(self):
        from llm_agent.audit import _execution_kind_for_step

        kind = _execution_kind_for_step(
            pipeline_phase="primary_ux",
            proposal={"action_type": "tap", "reason": "planner_contract_no_json"},
            executed={"action_type": "swipe", "reason": "primary_ux_scroll"},
            ok=True,
            outcome="swipe:508,1254->508,557;280",
        )
        self.assertEqual(kind, "direct")

    def test_engine_scanner_overlay_advance_is_direct(self):
        from llm_agent.audit import _execution_kind_for_step

        kind = _execution_kind_for_step(
            pipeline_phase="execute",
            proposal={"action_type": "tap", "reason": "engine_route_tap_search_launch"},
            executed={"action_type": "advance_goal", "reason": "engine_search_scanner_overlay_open"},
            ok=True,
            outcome="advance_goal",
        )
        self.assertEqual(kind, "direct")

    def test_tap_repair_stays_repaired(self):
        from llm_agent.audit import _execution_kind_for_step

        kind = _execution_kind_for_step(
            pipeline_phase="execute",
            proposal={"action_type": "tap", "target_resource_id": "com.app:id/foo"},
            executed={"action_type": "tap", "target_resource_id": "com.app:id/bar", "reason": "tap_repair_visible_rid"},
            ok=True,
            outcome="tap_rid:com.app:id/bar",
        )
        self.assertEqual(kind, "repaired")

    def test_post_fix_bitbanana_direct_action_ratio_passes(self):
        from pathlib import Path

        from llm_agent.audit import _human_ux_evaluate

        log = (
            REPO_ROOT
            / "logs/36bdbc1733f0_app.michaelwuensch.bitbanana/dynamic/llm/session_1/"
            "app.michaelwuensch.bitbanana_llm_actions.jsonl"
        )
        if not log.is_file():
            self.skipTest("BitBanana post-fix log not present")
        actions = [json.loads(line) for line in log.read_text().splitlines()]
        ux = _human_ux_evaluate(
            actions=actions,
            ux_goals=["Input search query", "Wait for UI to settle"],
            final_ux_goal_idx=1,
            llm_status="success",
        )
        direct_check = next(c for c in ux["checks"] if c["id"] == "direct_action_ratio")
        self.assertTrue(direct_check["passed"], direct_check["detail"])
        self.assertTrue(ux["human_ux_overall_pass"])

    def test_post_fix_bitbanana_guard_ratio_passes(self):
        from llm_agent.audit import _human_ux_evaluate, _human_ux_scored_events
        from llm_agent.audit import _is_guard_or_planner_contract_issue

        log = (
            REPO_ROOT
            / "logs/36bdbc1733f0_app.michaelwuensch.bitbanana/dynamic/llm/session_1/"
            "app.michaelwuensch.bitbanana_llm_actions.jsonl"
        )
        if not log.is_file():
            self.skipTest("BitBanana post-fix log not present")
        actions = [json.loads(line) for line in log.read_text().splitlines()]
        scored = _human_ux_scored_events(actions)
        issues = sum(1 for ev in scored if _is_guard_or_planner_contract_issue(ev))
        ratio = issues / max(1, len(scored))
        self.assertLessEqual(ratio, 0.25, f"guard ratio {ratio:.2f} ({issues}/{len(scored)})")

        ux = _human_ux_evaluate(
            actions=actions,
            ux_goals=["Input search query", "Wait for UI to settle"],
            final_ux_goal_idx=1,
            llm_status="success",
        )
        guard_check = next(c for c in ux["checks"] if c["id"] == "guard_intervention_rate")
        self.assertTrue(guard_check["passed"], guard_check["detail"])


if __name__ == "__main__":
    unittest.main()
