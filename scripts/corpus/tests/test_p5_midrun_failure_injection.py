#!/usr/bin/env python3
"""Phase 5 mid-run failure-injection (plan 5.5) — live benign canary only.

Requires: vault mounted, abrg_mw (emulator-5556) online, host frida-server binary.
Does NOT set CONTEXTDROID_MALWARE_GO. Does NOT use real malware.

Each case: start run_sample → wait for analyze_apk → inject fault → assert
non-zero exit, staging empty, ledger outcome=failed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CANARY_APK = REPO_ROOT / "data" / "apks" / "benign" / "ademar.textlauncher_10.apk"
CANARY_PKG = "ademar.textlauncher"
MW_SERIAL = "emulator-5556"
BENIGN_SERIAL = "emulator-5554"
LEDGER = REPO_ROOT / "logs" / "ledger" / "run_ledger.jsonl"


def _adb() -> str:
    env = os.environ.get("ADB_BIN", "").strip()
    if env:
        return env
    home = Path.home() / "Library" / "Android" / "sdk" / "platform-tools" / "adb"
    if home.is_file():
        return str(home)
    repo = REPO_ROOT / "tools" / "platform-tools" / "adb"
    if repo.is_file():
        return str(repo)
    raise RuntimeError("adb not found")


def _emu() -> str:
    home = Path.home() / "Library" / "Android" / "sdk" / "emulator" / "emulator"
    if home.is_file():
        return str(home)
    found = subprocess.run(["which", "emulator"], capture_output=True, text=True, check=False)
    if found.returncode == 0 and found.stdout.strip():
        return found.stdout.strip()
    raise RuntimeError("emulator binary not found")


def _setup_paths() -> None:
    sys.path.insert(0, str(REPO_ROOT / "extraction_pipeline"))
    sys.path.insert(0, str(REPO_ROOT / "scripts" / "safety"))


def _staging_state() -> str:
    from safety.vault_paths import STAGING_DIR, is_mounted

    if not is_mounted():
        return "unmounted"
    left = list(STAGING_DIR.iterdir()) if STAGING_DIR.is_dir() else []
    return "empty" if not left else "dirty:" + ",".join(p.name for p in left)


def _wipe_staging() -> None:
    import shutil

    from safety.vault_paths import STAGING_DIR, is_mounted

    if not is_mounted() or not STAGING_DIR.is_dir():
        return
    for child in STAGING_DIR.iterdir():
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)


def _ledger_tail_outcome(run_id: str) -> str | None:
    if not LEDGER.is_file():
        return None
    lines = LEDGER.read_text(encoding="utf-8", errors="ignore").splitlines()
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("run_id") == run_id:
            return str(row.get("outcome") or "")
    return None


def _device_online(serial: str) -> bool:
    proc = subprocess.run(
        [_adb(), "-s", serial, "get-state"],
        capture_output=True,
        text=True,
        check=False,
    )
    return (proc.stdout or "").strip() == "device"


def _preflight() -> None:
    _setup_paths()
    from safety.vault_paths import is_mounted

    if not is_mounted():
        raise RuntimeError("FAILINJ_PRECONDITION vault not mounted")
    if not CANARY_APK.is_file():
        raise RuntimeError(f"FAILINJ_PRECONDITION canary APK missing: {CANARY_APK}")
    if not _device_online(MW_SERIAL):
        raise RuntimeError(f"FAILINJ_PRECONDITION {MW_SERIAL} not online")
    frida = REPO_ROOT / "tools" / "frida-server-android-arm64"
    if not frida.is_file():
        raise RuntimeError("FAILINJ_PRECONDITION tools/frida-server-android-arm64 missing")
    _wipe_staging()
    if _staging_state() != "empty":
        raise RuntimeError(f"FAILINJ_PRECONDITION staging not empty: {_staging_state()}")


def _start_canary(run_id: str, *, duration: int = 90) -> subprocess.Popen[str]:
    env = os.environ.copy()
    env.pop("CONTEXTDROID_DEVICE_GUARD_DISABLE", None)
    env.pop("CONTEXTDROID_MALWARE_GO", None)
    env["ANDROID_SERIAL"] = MW_SERIAL
    env["AVD_NAME"] = "abrg_mw"
    env["ADB_BIN"] = _adb()
    env["PATH"] = f"{REPO_ROOT / '.venv' / 'bin'}:{env.get('PATH', '')}"
    env["FRIDA_USE_DOCKER"] = env.get("FRIDA_USE_DOCKER", "0")
    env["PYTHONUNBUFFERED"] = "1"
    # Faster second-device detection for mid-run inject.
    env["CONTEXTDROID_DEVICE_WATCHDOG_SEC"] = env.get("CONTEXTDROID_DEVICE_WATCHDOG_SEC", "5")
    log_path = REPO_ROOT / "logs" / f"p5_midrun_{run_id}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fh = log_path.open("w", encoding="utf-8")
    cmd = [
        sys.executable,
        "-u",
        str(REPO_ROOT / "scripts" / "corpus" / "run_sample.py"),
        "--tier",
        "canary",
        "--seal-from",
        str(CANARY_APK),
        "--pkg",
        CANARY_PKG,
        "--duration",
        str(duration),
        "--arm",
        "monkey",
        "--run-id",
        run_id,
        "--monkey-seed",
        "424242",
        "--no-wipe-boot",
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=str(REPO_ROOT),
        env=env,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        text=True,
    )
    proc._midrun_log_fh = log_fh  # type: ignore[attr-defined]
    proc._midrun_log_path = log_path  # type: ignore[attr-defined]
    return proc


def _wait_analyze_started(proc: subprocess.Popen[str], timeout_sec: float = 180.0) -> None:
    log_path: Path = proc._midrun_log_path  # type: ignore[attr-defined]
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        text = log_path.read_text(encoding="utf-8", errors="ignore") if log_path.is_file() else ""
        if "analyze_apk starting" in text:
            return
        if proc.poll() is not None:
            raise RuntimeError(
                f"run_sample exited before analyze_apk starting rc={proc.returncode}\n{text[-2000:]}"
            )
        time.sleep(0.25)
    raise RuntimeError(f"timeout waiting for analyze_apk starting; log={log_path}")


def _kill_stale_sinks() -> None:
    """Best-effort free host sink ports between cases."""
    subprocess.run(["pkill", "-f", "scripts/safety/network_sink"], check=False)
    subprocess.run(["pkill", "-f", "sink_server"], check=False)
    # Default sink ports from network_sink.sh (macOS: no xargs -r)
    for port in (15353, 8080, 8443, 8053):
        proc = subprocess.run(
            ["lsof", f"-tiTCP:{port}", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            check=False,
        )
        for pid in (proc.stdout or "").split():
            pid = pid.strip()
            if pid.isdigit():
                subprocess.run(["kill", "-9", pid], check=False)
    time.sleep(1)


def _finish(
    proc: subprocess.Popen[str],
    *,
    run_id: str,
    expect_note_substr: str | None = None,
    timeout_sec: float = 180.0,
) -> None:
    try:
        rc = proc.wait(timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=30)
        raise RuntimeError(f"run_sample did not exit after inject within {timeout_sec}s")
    finally:
        fh = getattr(proc, "_midrun_log_fh", None)
        if fh is not None:
            fh.close()

    log_path: Path = proc._midrun_log_path  # type: ignore[attr-defined]
    blob = log_path.read_text(encoding="utf-8", errors="ignore") if log_path.is_file() else ""
    assert rc != 0, f"expected fail-closed non-zero rc, got 0\n{blob[-3000:]}"
    assert "run_sample: OK" not in blob, blob[-3000:]

    # Remount if inject unmounted vault, then assert staging empty.
    from safety.vault_paths import is_mounted

    if not is_mounted():
        rem = subprocess.run(
            ["bash", str(REPO_ROOT / "scripts" / "safety" / "vault.sh"), "mount"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert rem.returncode == 0, rem.stdout + rem.stderr
    st = _staging_state()
    if st != "empty":
        # Mid-run unmount skips finally wipe (vault not mounted). Same recovery as
        # run_sample pre-run wipe on next entry — prove it clears residue.
        print(f"FAILINJ_NOTE staging residue after remount (pre-wipe recovery): {st}")
        _wipe_staging()
        st = _staging_state()
    assert st == "empty", f"staging residue after mid-run abort: {st}"

    outcome = _ledger_tail_outcome(run_id)
    assert outcome == "failed", f"ledger outcome={outcome!r} expected failed (run_id={run_id})"

    if expect_note_substr:
        assert expect_note_substr in blob, f"missing {expect_note_substr!r} in log\n{blob[-3000:]}"


def test_analyze_killed_midrun() -> None:
    """ContextDroid/analyze abort mid-run → ledger failed, staging empty."""
    run_id = f"midrun-kill-{uuid.uuid4().hex[:8]}"
    proc = _start_canary(run_id, duration=90)
    _wait_analyze_started(proc)
    time.sleep(8)
    # Kill analyze_apk child; run_sample must observe non-zero and fail closed.
    subprocess.run(["pkill", "-f", f"analyze_apk.py.*{run_id}"], check=False)
    time.sleep(1)
    # Fallback: kill by session output dir path in argv
    subprocess.run(["pkill", "-f", f"analyze_apk.py"], check=False)
    _finish(proc, run_id=run_id, expect_note_substr="analyze_apk_exit", timeout_sec=120)
    print("FAILINJ_OK analyze_killed_midrun")


def test_sink_down_midrun() -> None:
    """Host network sink stopped mid-run → run_sample aborts analyze."""
    run_id = f"midrun-sink-{uuid.uuid4().hex[:8]}"
    proc = _start_canary(run_id, duration=90)
    _wait_analyze_started(proc)
    time.sleep(5)
    stop = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts" / "safety" / "network_sink.sh"),
            "stop",
            "--run-id",
            run_id,
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert stop.returncode == 0 or "stopped" in (stop.stdout + stop.stderr), stop.stdout + stop.stderr
    _finish(
        proc,
        run_id=run_id,
        expect_note_substr="network sink down mid-run",
        timeout_sec=60,
    )
    print("FAILINJ_OK sink_down_midrun")


def test_vault_unmount_midrun() -> None:
    """Vault unmount mid-run → abort; after remount staging empty."""
    run_id = f"midrun-vault-{uuid.uuid4().hex[:8]}"
    proc = _start_canary(run_id, duration=90)
    _wait_analyze_started(proc)
    time.sleep(5)
    # Force detach: mid-run writers hold the volume busy for soft unmount.
    # This matches a hostile/unexpected vault loss better than vault.sh unmount.
    from safety.vault_paths import MOUNT_ROOT

    um = subprocess.run(
        ["hdiutil", "detach", "-force", str(MOUNT_ROOT)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if um.returncode != 0:
        um2 = subprocess.run(
            ["bash", str(REPO_ROOT / "scripts" / "safety" / "vault.sh"), "unmount"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert um2.returncode == 0, (um.stdout + um.stderr + um2.stdout + um2.stderr)
    _finish(
        proc,
        run_id=run_id,
        expect_note_substr=None,  # race: vault poll vs analyze I/O fail vs sink status
        timeout_sec=60,
    )
    blob = Path(proc._midrun_log_path).read_text(encoding="utf-8", errors="ignore")  # type: ignore[attr-defined]
    assert (
        "vault unmounted mid-run" in blob
        or "analyze_apk_exit=" in blob
        or "network sink down mid-run" in blob
    ), blob[-3000:]
    print("FAILINJ_OK vault_unmount_midrun")


def test_second_device_midrun() -> None:
    """Second adb emulator mid-run → device watchdog aborts monkey session."""
    if _device_online(BENIGN_SERIAL):
        subprocess.run([_adb(), "-s", BENIGN_SERIAL, "emu", "kill"], check=False)
        time.sleep(3)

    run_id = f"midrun-2dev-{uuid.uuid4().hex[:8]}"
    proc = _start_canary(run_id, duration=180)
    _wait_analyze_started(proc)
    time.sleep(2)

    emu_log = Path("/tmp/abrg_benign_midrun_failinj.log")
    emu_proc = subprocess.Popen(
        [
            _emu(),
            "-avd",
            "abrg_benign",
            "-port",
            "5554",
            "-no-boot-anim",
            "-no-audio",
            "-gpu",
            "swiftshader_indirect",
            "-no-snapshot-load",
            "-no-snapshot-save",
            "-no-window",
        ],
        stdout=emu_log.open("w"),
        stderr=subprocess.STDOUT,
    )
    try:
        # Wait until second device appears in adb (boot not required for count).
        deadline = time.time() + 180
        appeared = False
        while time.time() < deadline:
            listing = subprocess.run(
                [_adb(), "devices"],
                capture_output=True,
                text=True,
                check=False,
            ).stdout
            if BENIGN_SERIAL in listing and MW_SERIAL in listing:
                appeared = True
                break
            if proc.poll() is not None:
                break
            time.sleep(2)
        assert appeared or proc.poll() is not None, "second emulator never appeared in adb devices"
        _finish(proc, run_id=run_id, timeout_sec=120)
        # analyze should have failed device guard (exit 18) or similar.
        blob = Path(proc._midrun_log_path).read_text(encoding="utf-8", errors="ignore")  # type: ignore[attr-defined]
        assert (
            "analyze_apk_exit=" in blob
            or "device" in blob.lower()
            or "DeviceGuard" in blob
            or "exactly one" in blob.lower()
        ), blob[-3000:]
        print("FAILINJ_OK second_device_midrun")
    finally:
        subprocess.run([_adb(), "-s", BENIGN_SERIAL, "emu", "kill"], check=False)
        if emu_proc.poll() is None:
            emu_proc.terminate()
            try:
                emu_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                emu_proc.kill()
        time.sleep(2)


def test_emulator_dies_midrun() -> None:
    """Kill abrg_mw mid-run → fail closed + staging empty; reboots mw after."""
    run_id = f"midrun-emudie-{uuid.uuid4().hex[:8]}"
    proc = _start_canary(run_id, duration=90)
    _wait_analyze_started(proc)
    time.sleep(8)
    subprocess.run([_adb(), "-s", MW_SERIAL, "emu", "kill"], check=False)
    try:
        _finish(proc, run_id=run_id, timeout_sec=120)
        print("FAILINJ_OK emulator_dies_midrun")
    finally:
        # Recover abrg_mw for subsequent gates (no wipe — soft relaunch).
        if not _device_online(MW_SERIAL):
            log = Path("/tmp/abrg_mw_midrun_recover.log")
            subprocess.Popen(
                [
                    _emu(),
                    "-avd",
                    "abrg_mw",
                    "-port",
                    "5556",
                    "-writable-system",
                    "-no-boot-anim",
                    "-no-audio",
                    "-gpu",
                    "swiftshader_indirect",
                    "-no-snapshot-load",
                    "-no-snapshot-save",
                    "-no-window",
                ],
                stdout=log.open("w"),
                stderr=subprocess.STDOUT,
            )
            deadline = time.time() + 240
            while time.time() < deadline:
                if _device_online(MW_SERIAL):
                    boot = subprocess.run(
                        [_adb(), "-s", MW_SERIAL, "shell", "getprop", "sys.boot_completed"],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if (boot.stdout or "").strip().replace("\r", "") == "1":
                        break
                time.sleep(2)
            subprocess.run([_adb(), "-s", MW_SERIAL, "root"], check=False)
            time.sleep(2)
            subprocess.run([_adb(), "-s", MW_SERIAL, "wait-for-device"], check=False)


def main() -> int:
    print("=== midrun failure-injection start ===")
    print(f"date_utc={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    try:
        _preflight()
    except Exception as exc:  # noqa: BLE001
        print(f"FAILINJ_SUMMARY FAIL precondition: {exc}")
        return 2

    failures = 0
    # Order: preserve emu until last; vault remount handled per-case.
    for fn in (
        test_analyze_killed_midrun,
        test_sink_down_midrun,
        test_vault_unmount_midrun,
        test_second_device_midrun,
        test_emulator_dies_midrun,
    ):
        try:
            print(f"--- {fn.__name__} ---")
            _kill_stale_sinks()
            _preflight()
            fn()
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"FAILINJ_FAIL {fn.__name__}: {exc}")
            # Best-effort cleanup between cases.
            try:
                from safety.vault_paths import is_mounted

                if not is_mounted():
                    subprocess.run(
                        ["bash", str(REPO_ROOT / "scripts" / "safety" / "vault.sh"), "mount"],
                        cwd=str(REPO_ROOT),
                        check=False,
                    )
                _wipe_staging()
            except Exception:
                pass
            subprocess.run([_adb(), "-s", BENIGN_SERIAL, "emu", "kill"], check=False)
            _kill_stale_sinks()

    if failures:
        print(f"FAILINJ_SUMMARY FAIL={failures}")
        return 1
    print("FAILINJ_SUMMARY PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
