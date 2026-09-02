"""Device identity guardrails for emulator isolation and safe adb targeting.

Design (P3 A4):
  - Structural: pin ANDROID_SERIAL via scripts/safety/adb_pinned.sh on every adb call.
  - Hard identity assert only at emulator launch and immediately before adb install.
  - Background device-count watchdog (off hot path) aborts the session on multi-device.
  - No per-dump / mid-loop identity asserts (AVD identity cannot change mid-session).

Timing instrumentation (additive only — assert logic unchanged):
  - Per-session: guard_total_ms, guard_call_count, guard_max_call_ms.
  - Every watchdog poll logged (timestamp + duration_ms).
  - Every adb call >500ms logged (timestamp + duration_ms + args).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any


class DeviceGuardError(RuntimeError):
    pass


_WATCHDOG_LOCK = threading.Lock()
_WATCHDOG: "DeviceCountWatchdog | None" = None

_TIMING_LOCK = threading.Lock()
_TIMING: dict[str, Any] = {
    "guard_total_ms": 0.0,
    "guard_call_count": 0,
    "guard_max_call_ms": 0.0,
    "watchdog_polls": [],  # {ts_epoch_ms, duration_ms}
    "slow_adb_calls": [],  # {ts_epoch_ms, duration_ms, args}
}
_SLOW_ADB_MS = 500.0
_TIMING_LOG_PATH: str = ""


def _guard_disabled() -> bool:
    raw = (os.environ.get("CONTEXTDROID_DEVICE_GUARD_DISABLE") or "").strip().lower()
    return raw in {"1", "true", "yes"}


def reset_guard_timing(*, log_path: str = "") -> None:
    """Clear per-session timing accumulators. Call at analysis start."""
    global _TIMING_LOG_PATH
    with _TIMING_LOCK:
        _TIMING["guard_total_ms"] = 0.0
        _TIMING["guard_call_count"] = 0
        _TIMING["guard_max_call_ms"] = 0.0
        _TIMING["watchdog_polls"] = []
        _TIMING["slow_adb_calls"] = []
        _TIMING_LOG_PATH = (log_path or os.environ.get("CONTEXTDROID_GUARD_TIMING_LOG") or "").strip()
        if _TIMING_LOG_PATH:
            try:
                Path(_TIMING_LOG_PATH).write_text("", encoding="utf-8")
            except OSError:
                pass


def _append_timing_log(event: dict[str, Any]) -> None:
    path = _TIMING_LOG_PATH
    if not path:
        return
    try:
        with Path(path).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, sort_keys=True) + "\n")
    except OSError:
        pass


def _record_guard_call(duration_ms: float) -> None:
    with _TIMING_LOCK:
        _TIMING["guard_total_ms"] = float(_TIMING["guard_total_ms"]) + duration_ms
        _TIMING["guard_call_count"] = int(_TIMING["guard_call_count"]) + 1
        _TIMING["guard_max_call_ms"] = max(float(_TIMING["guard_max_call_ms"]), duration_ms)


def _record_watchdog_poll(ts_epoch_ms: float, duration_ms: float) -> None:
    event = {"type": "watchdog_poll", "ts_epoch_ms": ts_epoch_ms, "duration_ms": round(duration_ms, 3)}
    with _TIMING_LOCK:
        _TIMING["watchdog_polls"].append(event)
    _append_timing_log(event)
    logging.info("device_guard watchdog_poll duration_ms=%.3f", duration_ms)


def _record_slow_adb(ts_epoch_ms: float, duration_ms: float, args: tuple[str, ...]) -> None:
    event = {
        "type": "slow_adb",
        "ts_epoch_ms": ts_epoch_ms,
        "duration_ms": round(duration_ms, 3),
        "args": list(args),
    }
    with _TIMING_LOCK:
        _TIMING["slow_adb_calls"].append(event)
    _append_timing_log(event)
    logging.warning("device_guard slow_adb duration_ms=%.3f args=%s", duration_ms, " ".join(args))


def get_guard_timing_snapshot() -> dict[str, Any]:
    """Return a JSON-serializable copy of per-session guard timing."""
    with _TIMING_LOCK:
        polls = list(_TIMING["watchdog_polls"])
        slow = list(_TIMING["slow_adb_calls"])
        total = float(_TIMING["guard_total_ms"])
        count = int(_TIMING["guard_call_count"])
        max_ms = float(_TIMING["guard_max_call_ms"])
    correlated = _correlate_slow_adb_with_watchdog(polls, slow)
    return {
        "guard_total_ms": round(total, 3),
        "guard_call_count": count,
        "guard_max_call_ms": round(max_ms, 3),
        "watchdog_poll_count": len(polls),
        "watchdog_polls": polls,
        "slow_adb_call_count": len(slow),
        "slow_adb_calls": slow,
        "watchdog_slow_adb_correlated": correlated,
    }


def _correlate_slow_adb_with_watchdog(
    polls: list[dict[str, Any]],
    slow: list[dict[str, Any]],
    *,
    window_ms: float = 1000.0,
) -> list[dict[str, Any]]:
    """Return slow-adb events that fall within window_ms of a watchdog poll."""
    hits: list[dict[str, Any]] = []
    for s in slow:
        sts = float(s["ts_epoch_ms"])
        for p in polls:
            pts = float(p["ts_epoch_ms"])
            if abs(sts - pts) <= window_ms:
                hits.append(
                    {
                        "slow_adb_ts_epoch_ms": sts,
                        "slow_adb_duration_ms": s["duration_ms"],
                        "watchdog_ts_epoch_ms": pts,
                        "watchdog_duration_ms": p["duration_ms"],
                        "delta_ms": round(sts - pts, 3),
                    }
                )
                break
    return hits


def _run(adb_bin: str, *args: str, timeout: float = 12.0) -> subprocess.CompletedProcess[str]:
    t0 = time.perf_counter()
    wall_ms = time.time() * 1000.0
    try:
        return subprocess.run(
            [adb_bin, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    finally:
        duration_ms = (time.perf_counter() - t0) * 1000.0
        if duration_ms >= _SLOW_ADB_MS:
            _record_slow_adb(wall_ms, duration_ms, args)


def _adb_devices(adb_bin: str) -> list[tuple[str, str]]:
    out = _run(adb_bin, "devices")
    if out.returncode != 0:
        raise DeviceGuardError(f"adb devices failed: {(out.stderr or out.stdout).strip()}")
    devices: list[tuple[str, str]] = []
    for line in (out.stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices attached"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            devices.append((parts[0], parts[1]))
    return devices


def _adb_single_serial(adb_bin: str, *, allow_no_device: bool) -> str:
    attached = _adb_devices(adb_bin)
    online = [serial for serial, state in attached if state == "device"]
    if not online:
        if allow_no_device:
            return ""
        raise DeviceGuardError("no online adb device")
    if len(online) != 1:
        raise DeviceGuardError(f"expected exactly one online adb device, found {online}")
    return online[0]


def _getprop(adb_bin: str, serial: str, prop: str) -> str:
    out = _run(adb_bin, "-s", serial, "shell", "getprop", prop)
    if out.returncode != 0:
        raise DeviceGuardError(f"getprop {prop} failed on {serial}")
    return (out.stdout or "").strip()


def _resolve_avd_name(adb_bin: str, serial: str) -> str:
    for prop in ("ro.boot.qemu.avd_name", "ro.kernel.qemu.avd_name", "qemu.avd_name"):
        val = _getprop(adb_bin, serial, prop)
        if val:
            return val
    emu = _run(adb_bin, "-s", serial, "emu", "avd", "name")
    if emu.returncode == 0:
        text = (emu.stdout or "").strip()
        for line in text.splitlines():
            ln = line.strip()
            if ln and "OK" not in ln and "KO" not in ln:
                return ln
    return ""


def assert_single_device(adb_bin: str, *, expected_serial: str = "") -> str:
    if _guard_disabled():
        return ""
    t0 = time.perf_counter()
    try:
        serial = _adb_single_serial(adb_bin, allow_no_device=False)
        if expected_serial and serial != expected_serial:
            raise DeviceGuardError(f"serial mismatch: expected {expected_serial}, got {serial}")
        return serial
    finally:
        _record_guard_call((time.perf_counter() - t0) * 1000.0)


def _expected_fingerprint_from_env() -> str:
    return (os.environ.get("CONTEXTDROID_EXPECTED_FINGERPRINT") or "").strip()


def assert_device_identity_hard(
    adb_bin: str,
    *,
    expected_avd_name: str = "",
    expected_serial: str = "",
    expected_fingerprint: str = "",
    allow_no_device: bool = False,
) -> str:
    """Full identity check: single device + qemu + AVD name + optional fingerprint."""
    if _guard_disabled():
        return ""
    t0 = time.perf_counter()
    try:
        serial = _adb_single_serial(adb_bin, allow_no_device=allow_no_device)
        if not serial:
            return ""
        if expected_serial and serial != expected_serial:
            raise DeviceGuardError(f"serial mismatch: expected {expected_serial}, got {serial}")
        qemu = _getprop(adb_bin, serial, "ro.kernel.qemu")
        if qemu != "1":
            raise DeviceGuardError(f"ro.kernel.qemu must be 1, got {qemu!r}")
        actual_avd = _resolve_avd_name(adb_bin, serial)
        if expected_avd_name and actual_avd != expected_avd_name:
            raise DeviceGuardError(f"AVD name mismatch: expected {expected_avd_name}, got {actual_avd}")
        fp_expected = expected_fingerprint or _expected_fingerprint_from_env()
        if fp_expected:
            actual_fp = _getprop(adb_bin, serial, "ro.build.fingerprint")
            if actual_fp != fp_expected:
                raise DeviceGuardError("fingerprint mismatch against expected value")
        return serial
    finally:
        _record_guard_call((time.perf_counter() - t0) * 1000.0)


class DeviceCountWatchdog:
    """Poll adb device count off the hot path; set fail flag for session abort."""

    def __init__(
        self,
        adb_bin: str,
        *,
        expected_serial: str = "",
        interval_sec: float = 20.0,
    ) -> None:
        self._adb_bin = adb_bin
        self._expected_serial = expected_serial
        self._interval_sec = max(5.0, float(interval_sec))
        self._stop = threading.Event()
        self._failed = threading.Event()
        self._failure_reason = ""
        self._thread: threading.Thread | None = None

    def start(self) -> "DeviceCountWatchdog":
        if _guard_disabled():
            return self
        if self._thread is not None:
            return self
        self._thread = threading.Thread(
            target=self._run,
            name="device-count-watchdog",
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=self._interval_sec + 2.0)
        self._thread = None

    def failed(self) -> bool:
        return self._failed.is_set()

    def failure_reason(self) -> str:
        return self._failure_reason

    def raise_if_failed(self) -> None:
        if self._failed.is_set():
            raise DeviceGuardError(self._failure_reason or "device watchdog failed")

    def _mark_failed(self, reason: str) -> None:
        self._failure_reason = reason
        self._failed.set()

    def _run(self) -> None:
        # Immediate first poll, then interval cadence (fail closed on mid-run attach).
        while True:
            if _guard_disabled():
                if self._stop.wait(self._interval_sec):
                    return
                continue
            t0 = time.perf_counter()
            wall_ms = time.time() * 1000.0
            try:
                assert_single_device(self._adb_bin, expected_serial=self._expected_serial)
            except DeviceGuardError as exc:
                _record_watchdog_poll(wall_ms, (time.perf_counter() - t0) * 1000.0)
                self._mark_failed(str(exc))
                return
            except Exception as exc:  # noqa: BLE001 — fail closed
                _record_watchdog_poll(wall_ms, (time.perf_counter() - t0) * 1000.0)
                self._mark_failed(f"device watchdog error: {exc}")
                return
            _record_watchdog_poll(wall_ms, (time.perf_counter() - t0) * 1000.0)
            if self._stop.wait(self._interval_sec):
                return


def start_device_count_watchdog(
    adb_bin: str,
    *,
    expected_serial: str = "",
    interval_sec: float | None = None,
) -> DeviceCountWatchdog:
    """Start (or replace) the process-global device-count watchdog."""
    global _WATCHDOG
    if interval_sec is None:
        interval_sec = float(os.environ.get("CONTEXTDROID_DEVICE_WATCHDOG_SEC", "20"))
    with _WATCHDOG_LOCK:
        if _WATCHDOG is not None:
            _WATCHDOG.stop()
        _WATCHDOG = DeviceCountWatchdog(
            adb_bin,
            expected_serial=expected_serial,
            interval_sec=interval_sec,
        ).start()
        return _WATCHDOG


def stop_device_count_watchdog() -> None:
    global _WATCHDOG
    with _WATCHDOG_LOCK:
        if _WATCHDOG is not None:
            _WATCHDOG.stop()
            _WATCHDOG = None


def raise_if_watchdog_failed() -> None:
    """Cheap hot-path check: abort if background watchdog raised fail flag."""
    wd = _WATCHDOG
    if wd is not None:
        wd.raise_if_failed()


def _parse_avd_config(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip()
    return out


def _normalized_avd_identity(config: dict[str, str]) -> dict[str, str]:
    ignore = {"avd.name", "avd.id", "disk.dataPartition.path"}
    return {k: v for k, v in sorted(config.items()) if k not in ignore}


def build_avd_fingerprint_manifest(avd_names: list[str], out_path: Path) -> dict[str, Any]:
    avd_root = Path.home() / ".android" / "avd"
    payload: dict[str, Any] = {"generated_at_epoch": int(time.time()), "avds": {}}
    comparable_hashes: dict[str, str] = {}
    for avd in avd_names:
        cfg_path = avd_root / f"{avd}.avd" / "config.ini"
        if not cfg_path.is_file():
            raise DeviceGuardError(f"missing AVD config: {cfg_path}")
        cfg = _parse_avd_config(cfg_path)
        normalized = _normalized_avd_identity(cfg)
        norm_json = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        comp_hash = hashlib.sha256(norm_json.encode("utf-8")).hexdigest()
        payload["avds"][avd] = {
            "avd_name": avd,
            "config_path": str(cfg_path),
            "comparable_sha256": comp_hash,
            "normalized_fields": normalized,
        }
        comparable_hashes[avd] = comp_hash
    unique_hashes = sorted(set(comparable_hashes.values()))
    payload["comparison"] = {
        "avd_names": avd_names,
        "comparable_hashes": comparable_hashes,
        "equal_except_name_path": len(unique_hashes) == 1,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def _main() -> int:
    parser = argparse.ArgumentParser(description="ContextDroid device identity guard")
    sub = parser.add_subparsers(dest="cmd", required=True)

    hard = sub.add_parser("hard")
    hard.add_argument("--adb-bin", default=os.environ.get("ADB_BIN", "adb"))
    hard.add_argument("--expected-avd", default=os.environ.get("AVD_NAME", ""))
    hard.add_argument("--expected-serial", default=os.environ.get("ANDROID_SERIAL", ""))
    hard.add_argument("--expected-fingerprint", default=os.environ.get("CONTEXTDROID_EXPECTED_FINGERPRINT", ""))
    hard.add_argument("--allow-no-device", action="store_true")

    single = sub.add_parser("single")
    single.add_argument("--adb-bin", default=os.environ.get("ADB_BIN", "adb"))
    single.add_argument("--expected-serial", default=os.environ.get("ANDROID_SERIAL", ""))

    avd = sub.add_parser("write-avd-fingerprint")
    avd.add_argument("--out", type=Path, required=True)
    avd.add_argument("--avd", action="append", required=True)

    args = parser.parse_args()
    try:
        if args.cmd == "hard":
            serial = assert_device_identity_hard(
                args.adb_bin,
                expected_avd_name=args.expected_avd,
                expected_serial=args.expected_serial,
                expected_fingerprint=args.expected_fingerprint,
                allow_no_device=args.allow_no_device,
            )
            print(f"HARD_OK serial={serial or '(none)'}")
            return 0
        if args.cmd == "single":
            serial = assert_single_device(args.adb_bin, expected_serial=args.expected_serial)
            print(f"SINGLE_OK serial={serial}")
            return 0
        if args.cmd == "write-avd-fingerprint":
            payload = build_avd_fingerprint_manifest(args.avd, args.out)
            ok = payload["comparison"]["equal_except_name_path"]
            print(f"AVD_FINGERPRINT_OK equal_except_name_path={ok}")
            return 0 if ok else 2
    except DeviceGuardError as exc:
        print(f"DEVICE_GUARD_FAIL {exc}")
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(_main())
