"""Unit tests for device identity guard (qemu / count assertions)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from safety.device_guard import (  # noqa: E402
    DeviceGuardError,
    assert_device_identity_hard,
)


class TestQemuIdentityAssert(unittest.TestCase):
    @mock.patch("safety.device_guard._resolve_avd_name", return_value="abrg_benign")
    @mock.patch("safety.device_guard._getprop")
    @mock.patch("safety.device_guard._adb_single_serial", return_value="emulator-5554")
    def test_rejects_empty_ro_kernel_qemu(self, _single, getprop, _avd):
        """Physical devices return empty for ro.kernel.qemu; guard must fail closed."""

        def _prop(_adb, _serial, prop: str) -> str:
            if prop == "ro.kernel.qemu":
                return ""
            return "unused"

        getprop.side_effect = _prop
        with self.assertRaises(DeviceGuardError) as ctx:
            assert_device_identity_hard(
                "adb",
                expected_avd_name="abrg_benign",
                expected_serial="emulator-5554",
            )
        self.assertIn("ro.kernel.qemu", str(ctx.exception))
        self.assertIn("''", str(ctx.exception))

    @mock.patch("safety.device_guard._resolve_avd_name", return_value="abrg_benign")
    @mock.patch("safety.device_guard._getprop", return_value="1")
    @mock.patch("safety.device_guard._adb_single_serial", return_value="emulator-5554")
    def test_accepts_qemu_one(self, _single, _getprop, _avd):
        serial = assert_device_identity_hard(
            "adb",
            expected_avd_name="abrg_benign",
            expected_serial="emulator-5554",
        )
        self.assertEqual(serial, "emulator-5554")


if __name__ == "__main__":
    unittest.main()
