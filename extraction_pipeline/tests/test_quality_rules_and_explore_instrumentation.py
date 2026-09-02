"""Tests for merged flailing rules and explore candidate instrumentation."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluate_scenario_level import _load_actions
from llm_agent.explore_instrumentation import (
    _RECOVERY_SNAPSHOT_MAX_ELEMENTS,
    build_explore_candidate_instrumentation,
    explore_tier_index_for_reason,
    is_explore_recovery_action,
)
from llm_agent.navigation import _build_bfs_candidates, _build_tab_targets
from llm_agent.dialogs import _bfs_filter_expand_candidates
from llm_agent.screen import _filter_widgets_for_target, _normalized_elements
from quality_rules import (
    detect_flailing_interim_new,
    detect_flailing_legacy,
    detect_suspect_flailing,
)


def _mensa_like_elements(n: int = 11) -> list[dict[str, str]]:
    elements: list[dict[str, str]] = []
    y = 200
    for i in range(n):
        elements.append(
            {
                "package": "ch.famoser.mensa",
                "resource_id": "",
                "content_desc": "",
                "text": "",
                "class_name": "android.view.View",
                "bounds": f"[100,{y + i * 80}][900,{y + i * 80 + 60}]",
                "clickable": "true",
            }
        )
    return elements


class TestExploreInstrumentation(unittest.TestCase):
    def test_mensa_recovery_snapshot_anonymous_admitted(self):
        elements = _mensa_like_elements(11)
        nav, other = _build_bfs_candidates(elements)
        tabs = _build_tab_targets(elements)
        expand = _bfs_filter_expand_candidates(other, "ch.famoser.mensa", set())
        out = build_explore_candidate_instrumentation(
            elements,
            nav,
            other,
            expand,
            tabs,
            screen_hash="abc123",
            recovery_step=True,
        )
        counts = out["explore_candidate_counts"]
        self.assertEqual(counts["nav_cands"], 0)
        self.assertEqual(counts["other_cands"], 11)
        self.assertEqual(counts["expand_cands"], 11)
        self.assertEqual(counts["skipped_interactive"], 0)
        snap = out["element_snapshot"]
        self.assertEqual(snap["screen_hash"], "abc123")
        self.assertEqual(len(snap["elements"]), 11)
        self.assertTrue(all(e["bucket"] in {"other", "expand"} for e in snap["elements"]))
        self.assertFalse(snap["truncated"])

    def test_recovery_snapshot_truncates_above_cap(self):
        n = _RECOVERY_SNAPSHOT_MAX_ELEMENTS + 10
        elements = _mensa_like_elements(n)
        nav, other = _build_bfs_candidates(elements)
        tabs = _build_tab_targets(elements)
        expand = _bfs_filter_expand_candidates(other, "ch.famoser.mensa", set())
        out = build_explore_candidate_instrumentation(
            elements,
            nav,
            other,
            expand,
            tabs,
            screen_hash="dense",
            recovery_step=True,
        )
        snap = out["element_snapshot"]
        self.assertTrue(snap["truncated"])
        self.assertEqual(len(snap["elements"]), _RECOVERY_SNAPSHOT_MAX_ELEMENTS)
        self.assertEqual(out["explore_candidate_counts"]["skipped_interactive"], 0)
        self.assertEqual(out["explore_candidate_counts"]["other_cands"], n)
        self.assertGreater(out["explore_candidate_counts"]["other_cands"], len(snap["elements"]))

    def test_recovery_reason_detection_and_tier(self):
        action = {"action_type": "back", "reason": "bfs_return_to_hub"}
        self.assertTrue(is_explore_recovery_action(action))
        self.assertEqual(explore_tier_index_for_reason("bfs_return_to_hub"), 10)
        self.assertEqual(explore_tier_index_for_reason("bfs_expand_frontier"), 6)


class TestMergedFlailingRules(unittest.TestCase):
    def test_mensa_flagged_merged(self):
        base = Path("logs/bulk_llm_benign_v6/ef32499a74ab_ch.famoser.mensa/dynamic/llm/session_1")
        actions = _load_actions(base / "ch.famoser.mensa_llm_actions.jsonl")
        meta = json.loads((base / "ch.famoser.mensa_dynamic_metadata.json").read_text())
        sim = str(meta.get("llm_simulation_status") or "")
        flagged, evidence = detect_suspect_flailing(actions, sim_status=sim)
        self.assertTrue(flagged)
        joined = " ".join(evidence)
        self.assertIn("explore_back_wait_dominant", joined)
        self.assertIn("dominant_screen", joined)

    def test_required_packages_flagged_on_v129(self):
        required = {
            "ch.famoser.mensa",
            "app.traced_it",
            "cat.mvmike.minimalcalendarwidget",
            "cc.echonet.coolmicapp",
            "ca.voiditswarranty.roadtripradar",
        }
        rows = Path("experiment/working_dataset.csv").read_text(encoding="utf-8").strip().splitlines()
        header = rows[0].split(",")
        pkg_idx = header.index("package")
        art_idx = header.index("artifact_dir")
        flagged: set[str] = set()
        for line in rows[1:]:
            cols = line.split(",")
            pkg = cols[pkg_idx]
            if pkg not in required:
                continue
            base = Path(cols[art_idx])
            actions = _load_actions(base / f"{pkg}_llm_actions.jsonl")
            meta_path = base / f"{pkg}_dynamic_metadata.json"
            sim = ""
            if meta_path.exists():
                sim = str(json.loads(meta_path.read_text()).get("llm_simulation_status") or "")
            is_flail, _ = detect_suspect_flailing(actions, sim_status=sim)
            if is_flail:
                flagged.add(pkg)
        self.assertTrue(required.issubset(flagged), f"missing flags for {required - flagged}")

    def test_interim_new_under_detects_legacy_same_element_cycle(self):
        import csv

        pkg = "cc.echonet.coolmicapp"
        base = None
        for row in csv.DictReader(open("experiment/working_dataset.csv", encoding="utf-8")):
            if row["package"] == pkg:
                base = Path(row["artifact_dir"])
                break
        self.assertIsNotNone(base)
        actions = _load_actions(base / f"{pkg}_llm_actions.jsonl")
        report_path = base / f"{pkg}_human_ux_report.json"
        report = json.loads(report_path.read_text()) if report_path.exists() else None
        meta_path = base / f"{pkg}_dynamic_metadata.json"
        sim = str(json.loads(meta_path.read_text()).get("llm_simulation_status") or "") if meta_path.exists() else ""
        old_flag, old_ev = detect_flailing_legacy(actions, sim_status=sim, report=report)
        interim_flag, interim_ev = detect_flailing_interim_new(actions, sim_status=sim)
        merged_flag, merged_ev = detect_suspect_flailing(actions, sim_status=sim, report=report)
        self.assertTrue(old_flag)
        self.assertTrue(any("same_element_cycle" in e for e in old_ev))
        self.assertFalse(any("same_element_cycle" in e for e in interim_ev))
        self.assertTrue(merged_flag)
        self.assertTrue(any("same_element_cycle" in e for e in merged_ev))


if __name__ == "__main__":
    unittest.main()
