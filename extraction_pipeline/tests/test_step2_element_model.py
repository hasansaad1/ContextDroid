"""Tests for Step 2 element model and Step 3 stall behavior."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llm_agent.explore_instrumentation import build_explore_candidate_instrumentation
from llm_agent.navigation import (
    _build_bfs_candidates,
    _build_tab_targets,
    _is_text_entry_element,
)
from llm_agent.dialogs import _bfs_filter_expand_candidates
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


class TestStep2ElementModel(unittest.TestCase):
    def test_normalized_elements_propagates_clickable(self):
        elements = _normalized_elements(MENSA_XML)
        views = [e for e in elements if "View" in e["class_name"]]
        self.assertEqual(len(views), 2)
        self.assertEqual(views[0]["clickable"], "true")

    def test_edittext_excluded_from_other_not_plain_tap(self):
        elements = _normalized_elements(MENSA_XML)
        edittexts = [e for e in elements if _is_text_entry_element(e)]
        self.assertEqual(len(edittexts), 1)
        nav, other = _build_bfs_candidates(elements)
        self.assertEqual(len(nav), 0)
        self.assertEqual(len(other), 2)
        self.assertTrue(all(not c.get("target_resource_id") for c in other))

    def test_anonymous_views_admitted_to_other_and_expand(self):
        elements = _normalized_elements(MENSA_XML)
        nav, other = _build_bfs_candidates(elements)
        tabs = _build_tab_targets(elements)
        expand = _bfs_filter_expand_candidates(other, "ch.famoser.mensa", set())
        out = build_explore_candidate_instrumentation(
            elements,
            nav,
            other,
            expand,
            tabs,
            screen_hash="abc",
            recovery_step=True,
        )
        counts = out["explore_candidate_counts"]
        self.assertEqual(counts["other_cands"], 2)
        self.assertEqual(counts["expand_cands"], 2)
        self.assertEqual(counts["skipped_interactive"], 1)  # EditText only
        snap = out["element_snapshot"]
        none_buckets = [e for e in snap["elements"] if e["bucket"] == "none"]
        self.assertEqual(len(none_buckets), 1)
        self.assertIn("EditText", none_buckets[0]["class"])

    def test_labeled_control_unchanged(self):
        elements = [
            {
                "package": "ch.protonvpn.android",
                "resource_id": "ch.protonvpn.android:id/connectButton",
                "content_desc": "Connect",
                "text": "",
                "class_name": "android.widget.Button",
                "bounds": "[100,50][900,150]",
                "clickable": "true",
            }
        ]
        nav, other = _build_bfs_candidates(elements)
        self.assertEqual(len(nav), 0)
        self.assertEqual(len(other), 1)
        self.assertEqual(other[0]["target_resource_id"], "ch.protonvpn.android:id/connectButton")

    def test_anonymous_blocked_when_labeled_candidates_exist(self):
        """ProtonVPN-like: labeled nav present → anonymous Views stay out."""
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
        nav, other = _build_bfs_candidates(elements)
        self.assertEqual(len(other), 1)
        self.assertEqual(other[0]["target_resource_id"], "ch.protonvpn.android:id/connectButton")

    def test_per_screen_scarcity_allows_anonymous_on_later_zero_label_screen(self):
        """After a labeled hub screen, a zero-label sub-panel still admits anonymous Views."""
        hub = [
            {
                "package": "ch.protonvpn.android",
                "resource_id": "ch.protonvpn.android:id/tab",
                "content_desc": "Countries",
                "text": "",
                "class_name": "android.widget.TextView",
                "bounds": "[0,1700][270,1920]",
                "clickable": "true",
            }
        ]
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
        hub_nav, hub_other = _build_bfs_candidates(hub)
        self.assertGreater(len(hub_nav), 0)
        self.assertEqual(len(hub_other), 0)
        _, sparse_other = _build_bfs_candidates(sparse)
        self.assertEqual(len(sparse_other), 1)
        self.assertFalse(sparse_other[0].get("target_resource_id"))


if __name__ == "__main__":
    unittest.main()
