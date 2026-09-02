"""Tests for emulator isolation and strict foreground helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llm_agent.device import (  # noqa: E402
    check_target_foreground,
    foreground_mismatch_limit,
    isolate_emulator_state,
    reboot_emulator,
    strict_foreground_enabled,
)


class TestStrictForegroundConfig(unittest.TestCase):
    def test_strict_enabled_by_default(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertTrue(strict_foreground_enabled())

    def test_strict_can_be_disabled(self):
        with mock.patch.dict("os.environ", {"CONTEXTDROID_STRICT_FOREGROUND": "0"}, clear=True):
            self.assertFalse(strict_foreground_enabled())

    def test_mismatch_limit_default(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertEqual(foreground_mismatch_limit(), 3)


class TestCheckTargetForeground(unittest.TestCase):
    @mock.patch("llm_agent.device._foreground_package", return_value="com.example.app")
    def test_accepts_target_package(self, _fg):
        ok, fg = check_target_foreground("adb", "com.example.app")
        self.assertTrue(ok)
        self.assertEqual(fg, "com.example.app")

    @mock.patch("llm_agent.device._foreground_package", return_value="com.other.app")
    def test_rejects_foreign_package(self, _fg):
        ok, fg = check_target_foreground("adb", "com.example.app")
        self.assertFalse(ok)
        self.assertEqual(fg, "com.other.app")


class TestIsolateEmulatorState(unittest.TestCase):
    @mock.patch("llm_agent.device.time.sleep")
    @mock.patch("llm_agent.device.subprocess.run")
    @mock.patch(
        "llm_agent.device._list_third_party_packages",
        return_value=["com.keep.me", "com.other.one"],
    )
    def test_force_stops_other_third_party_apps(self, _list_pkgs, run_mock, _sleep):
        isolate_emulator_state("adb", "com.keep.me")
        commands = [call.args[0] for call in run_mock.call_args_list]
        self.assertEqual(commands[0], ["adb", "shell", "input", "keyevent", "3"])
        self.assertIn(["adb", "shell", "am", "force-stop", "com.other.one"], commands)
        self.assertNotIn(["adb", "shell", "am", "force-stop", "com.keep.me"], commands)


class TestRebootEmulator(unittest.TestCase):
    @mock.patch("llm_agent.device.time.sleep")
    @mock.patch("llm_agent.device.subprocess.run")
    def test_waits_for_boot_completed(self, run_mock, _sleep):
        run_mock.side_effect = [
            mock.Mock(returncode=0),
            mock.Mock(stdout="1\n", returncode=0),
        ]
        self.assertTrue(reboot_emulator("adb", wait_boot_sec=10))


if __name__ == "__main__":
    unittest.main()
