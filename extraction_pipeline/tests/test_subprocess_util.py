"""Tests for subprocess_util timeout and process teardown."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from subprocess_util import run_subprocess_with_timeout  # noqa: E402


class TestSubprocessUtil(unittest.TestCase):
    def test_timeout_returns_124(self):
        result = run_subprocess_with_timeout(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            timeout_sec=0.2,
        )
        self.assertEqual(result.returncode, 124)
        self.assertIn("timeout", (result.stderr or "").lower())

    def test_successful_command(self):
        result = run_subprocess_with_timeout(
            [sys.executable, "-c", "print('ok')"],
            timeout_sec=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("ok", result.stdout or "")

    def test_terminate_process_tree_kills_group(self):
        from subprocess_util import _terminate_process_tree

        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            start_new_session=True,
        )
        _terminate_process_tree(proc)
        self.assertIsNotNone(proc.poll())


if __name__ == "__main__":
    unittest.main()
