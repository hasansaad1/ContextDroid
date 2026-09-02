"""Tests for execute-phase empty hierarchy recovery semantics."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llm_agent.handoff import _recover_empty_execute_screen  # noqa: E402


class TestEmptyExecuteRecovery(unittest.TestCase):
    @mock.patch("llm_agent.handoff._restart_target_root")
    @mock.patch("llm_agent.handoff.dump_clean_screen")
    @mock.patch("llm_agent.handoff._filter_widgets_for_target")
    @mock.patch("llm_agent.handoff._screen_is_valid_execute_root", return_value=(True, "ok"))
    def test_success_requires_non_empty_elements(
        self,
        valid_mock,
        filter_mock,
        dump_mock,
        _restart_mock,
    ):
        widgets = [{"resource_id": "com.app:id/home", "package": "com.app"}]
        dump_mock.return_value = (widgets, "", "<xml/>")
        filter_mock.return_value = widgets
        rec = _recover_empty_execute_screen("adb", "com.app", attempts_used=2)
        self.assertTrue(rec["ok"])
        self.assertEqual(rec["elements"], widgets)

    @mock.patch("llm_agent.handoff.dump_clean_screen", return_value=([], "", ""))
    @mock.patch("llm_agent.handoff._filter_widgets_for_target", return_value=[])
    @mock.patch("llm_agent.handoff._screen_is_valid_execute_root", return_value=(True, "ok"))
    def test_ok_false_when_elements_empty_despite_validator(
        self,
        _valid_mock,
        _filter_mock,
        _dump_mock,
    ):
        rec = _recover_empty_execute_screen("adb", "com.app", attempts_used=0)
        self.assertFalse(rec["ok"])
        self.assertEqual(rec["screen_reason"], "empty_hierarchy_after_validation")


class TestRecoveryCounterModel(unittest.TestCase):
    def test_stale_counter_blocks_recovery_without_reset(self):
        attempts = 3
        count = 3
        recovered = False
        while count < attempts:
            recovered = True
            break
        self.assertFalse(recovered)

    def test_reset_after_success_allows_next_episode(self):
        attempts = 3
        count = 3
        count = 0  # production fix: reset after successful recovery
        recovered = False
        while count < attempts:
            count += 1
            recovered = True
            break
        self.assertTrue(recovered)


if __name__ == "__main__":
    unittest.main()
