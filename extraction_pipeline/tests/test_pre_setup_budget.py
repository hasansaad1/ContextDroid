"""Tests for pre-simulation setup wall-time budget."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import analyze_apk  # noqa: E402


class TestPreSetupBudget(unittest.TestCase):
    @mock.patch.dict("os.environ", {}, clear=False)
    @mock.patch("analyze_apk._PRE_SETUP_MAX_SEC", 0.0)
    @mock.patch("analyze_apk._grant_declared_permissions", return_value={"attempted": 0, "granted": 0})
    @mock.patch("analyze_apk._resolve_setup_dialogs")
    @mock.patch("analyze_apk.run_command")
    def test_skips_warmup_when_budget_exhausted(self, run_cmd_mock, dialog_mock, _grant_mock):
        out = analyze_apk._run_pre_simulation_setup("adb", "com.example", Path("x.apk"), Path("/tmp/out"))
        dialog_mock.assert_not_called()
        run_cmd_mock.assert_not_called()
        self.assertTrue(out["pre_setup_timed_out"])
        self.assertEqual(out["warmup_monkey_rc"], -1)


if __name__ == "__main__":
    unittest.main()
