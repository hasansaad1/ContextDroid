"""Unit tests for Frida attach detection helpers."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analyze_apk import (  # noqa: E402
    _frida_attach_modes,
    _frida_chunk_indicates_attach_success,
    _frida_count_events_in_text,
    _frida_count_meaningful_events_in_text,
    _frida_liveness_failure_reason,
    _frida_log_byte_offset,
    _frida_slice_shows_cli_exit,
    _frida_slice_shows_disconnect,
    _is_pid_alive,
    wait_for_frida_attach,
)

HOOK_LOADED_LINE = (
    '{"type":"event","timestamp":1,"api":"hook_loaded","category":"lifecycle","args":{"stage":"java_perform"}}'
)


class TestFridaChunkIndicatesAttach(unittest.TestCase):
    def test_empty_chunk_is_not_success(self):
        self.assertFalse(_frida_chunk_indicates_attach_success(""))

    def test_hook_loaded_in_chunk_is_success(self):
        self.assertTrue(_frida_chunk_indicates_attach_success(HOOK_LOADED_LINE))

    def test_failed_attach_overrides_stale_hook_loaded_marker_in_same_chunk(self):
        chunk = f"{HOOK_LOADED_LINE}\nFailed to attach: process not found"
        self.assertFalse(_frida_chunk_indicates_attach_success(chunk))

    def test_failed_attach_without_hook_loaded_is_not_success(self):
        self.assertFalse(_frida_chunk_indicates_attach_success("Failed to attach: process not found"))


class TestWaitForFridaAttach(unittest.TestCase):
    def test_append_mode_ignores_prior_hook_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "frida.jsonl"
            log_path.write_text(HOOK_LOADED_LINE + "\n", encoding="utf-8")
            offset = _frida_log_byte_offset(log_path)
            proc = mock.Mock()
            proc.poll.return_value = None

            self.assertFalse(
                wait_for_frida_attach(proc, log_path, timeout_sec=0, log_offset=offset),
            )

    def test_append_mode_accepts_new_hook_loaded_slice(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "frida.jsonl"
            log_path.write_text(HOOK_LOADED_LINE + "\n", encoding="utf-8")
            offset = _frida_log_byte_offset(log_path)
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write("Attaching...\n")
                handle.write(HOOK_LOADED_LINE + "\n")
            proc = mock.Mock()
            proc.poll.return_value = None

            self.assertTrue(
                wait_for_frida_attach(proc, log_path, timeout_sec=0, log_offset=offset),
            )

    def test_rejects_when_process_exits_after_hook_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "frida.jsonl"
            log_path.write_text(HOOK_LOADED_LINE + "\n", encoding="utf-8")
            proc = subprocess.Popen(["true"])
            proc.wait()

            self.assertFalse(wait_for_frida_attach(proc, log_path, timeout_sec=0, log_offset=0))


class TestFridaLivenessHelpers(unittest.TestCase):
    def test_count_events_ignores_non_json_lines(self):
        text = (
            "Frida banner\n"
            + HOOK_LOADED_LINE
            + "\n"
            '{"type":"status","timestamp":2,"status":"hook_ok"}\n'
            '{"type":"event","timestamp":3,"api":"foo","category":"network"}\n'
        )
        self.assertEqual(_frida_count_events_in_text(text), 2)

    def test_disconnect_markers(self):
        self.assertTrue(_frida_slice_shows_disconnect("Connection terminated\n"))
        self.assertTrue(_frida_slice_shows_disconnect("Failed to attach: process not found\n"))
        self.assertFalse(_frida_slice_shows_disconnect(HOOK_LOADED_LINE))

    def test_cli_exit_markers(self):
        self.assertTrue(_frida_slice_shows_cli_exit("Thank you for using Frida!\n"))
        self.assertTrue(_frida_slice_shows_disconnect("Thank you for using Frida!\n"))
        self.assertFalse(_frida_slice_shows_cli_exit(HOOK_LOADED_LINE))

    def test_meaningful_event_counter_excludes_reflection(self):
        text = (
            HOOK_LOADED_LINE
            + "\n"
            '{"type":"event","timestamp":2,"api":"Method.invoke","category":"reflection"}\n'
            '{"type":"event","timestamp":3,"api":"SharedPreferences.getString","category":"storage"}\n'
        )
        self.assertEqual(_frida_count_events_in_text(text), 3)
        self.assertEqual(_frida_count_meaningful_events_in_text(text), 1)

    def test_post_hook_silence_after_grace(self):
        now = 100.0
        reason = _frida_liveness_failure_reason(
            proc_dead=False,
            chunk="",
            hook_confirmed=True,
            now=now,
            grace_until=70.0,
            last_activity_at=60.0,
            saw_meaningful_events=False,
            last_meaningful_event_at=60.0,
            post_hook_silence_sec=20.0,
            stale_sec=45.0,
        )
        self.assertEqual(reason, "post_hook_silence")

    def test_stale_requires_prior_meaningful_events(self):
        now = 200.0
        reason = _frida_liveness_failure_reason(
            proc_dead=False,
            chunk="",
            hook_confirmed=True,
            now=now,
            grace_until=70.0,
            last_activity_at=now - 5.0,
            saw_meaningful_events=True,
            last_meaningful_event_at=now - 50.0,
            post_hook_silence_sec=20.0,
            stale_sec=45.0,
        )
        self.assertEqual(reason, "stale_events")


class TestAttachModes(unittest.TestCase):
    def test_prefer_name_orders_name_first(self):
        self.assertEqual(_frida_attach_modes(prefer_name=True), ("name", "pid"))

    def test_default_orders_pid_first(self):
        self.assertEqual(_frida_attach_modes(prefer_name=False), ("pid", "name"))


class TestPidAlive(unittest.TestCase):
    @mock.patch("analyze_apk.run_command")
    def test_kill_zero_success_means_alive(self, run_command):
        run_command.return_value = mock.Mock(returncode=0)
        self.assertTrue(_is_pid_alive("adb", "1234"))

    @mock.patch("analyze_apk.run_command")
    def test_kill_zero_failure_means_dead(self, run_command):
        run_command.return_value = mock.Mock(returncode=1)
        self.assertFalse(_is_pid_alive("adb", "1234"))


if __name__ == "__main__":
    unittest.main()
