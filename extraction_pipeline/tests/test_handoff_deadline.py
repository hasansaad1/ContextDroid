"""Tests for root capture deadline behavior."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llm_agent.handoff import _capture_execute_root_reference  # noqa: E402


class TestRootCaptureDeadline(unittest.TestCase):
    @mock.patch("llm_agent.handoff._ROOT_HANDOFF_RELAUNCH", False)
    @mock.patch("llm_agent.handoff._ROOT_CAPTURE_DEADLINE_SEC", 0.01)
    @mock.patch("llm_agent.handoff.time.monotonic")
    @mock.patch("llm_agent.handoff._dump_filtered_screen")
    def test_times_out_when_deadline_elapsed(self, dump_mock, mono_mock):
        mono_mock.side_effect = [0.0, 0.02, 0.03]
        dump_mock.return_value = ([], "", "")
        result = _capture_execute_root_reference("adb", "com.example.app")
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "root_reference_capture_timeout")

    @mock.patch("llm_agent.handoff._ROOT_HANDOFF_RELAUNCH", True)
    @mock.patch("llm_agent.handoff._ROOT_CAPTURE_DEADLINE_SEC", 0.01)
    @mock.patch("llm_agent.handoff.time.monotonic")
    @mock.patch("llm_agent.handoff._restart_target_root")
    def test_relaunch_skipped_when_deadline_already_elapsed(self, restart_mock, mono_mock):
        mono_mock.side_effect = [0.0, 0.02]
        result = _capture_execute_root_reference("adb", "com.example.app")
        restart_mock.assert_not_called()
        self.assertEqual(result["reason"], "root_reference_capture_timeout")


if __name__ == "__main__":
    unittest.main()
