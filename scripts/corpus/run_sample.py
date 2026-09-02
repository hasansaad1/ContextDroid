#!/usr/bin/env python3
"""Single entry point for a malware/canary tier sample run (plan 5.2).

Flow: refuse guard-disable → vault → sink/Gate A → wipe-boot abrg_mw → device
guard → unseal to staging → analyze_apk → traces under vault → wipe staging →
ledger. Fail closed. No real-malware download here — canary seals a benign APK.

--tier malware additionally requires CONTEXTDROID_MALWARE_GO=1 after human
go/no-go sign-off (SAFETY.md). --seal-from is canary-only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "extraction_pipeline"))
sys.path.insert(0, str(REPO_ROOT / "scripts" / "safety"))

from safety.config_snapshot import build_config_snapshot, write_config_snapshot  # noqa: E402
from safety.device_guard import assert_device_identity_hard  # noqa: E402
from safety.ledger import append_run  # noqa: E402
from safety.vault_paths import (  # noqa: E402
    LOGS_DIR,
    STAGING_DIR,
    TRACES_DIR,
    assert_mounted,
    ensure_layout,
    is_mounted,
    quarantine_archive_path,
)

# quarantine.py lives under scripts/safety
import quarantine as quarantine_mod  # noqa: E402

MW_AVD = "abrg_mw"
MW_SERIAL = "emulator-5556"
MW_PORT = "5556"
BENIGN_AVD = "abrg_benign"
BENIGN_SERIAL = "emulator-5554"


class RunSampleError(RuntimeError):
    """Fail-closed orchestration error."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _adb_bin() -> str:
    env = os.environ.get("ADB_BIN", "").strip()
    if env:
        return env
    repo_adb = REPO_ROOT / "tools" / "platform-tools" / "adb"
    if repo_adb.is_file():
        return str(repo_adb)
    home = Path.home() / "Library" / "Android" / "sdk" / "platform-tools" / "adb"
    if home.is_file():
        return str(home)
    found = shutil.which("adb")
    if found:
        return found
    raise RunSampleError("adb not found")


def _emu_bin() -> str:
    env = os.environ.get("EMU_BIN", "").strip()
    if env:
        return env
    home = Path.home() / "Library" / "Android" / "sdk" / "emulator" / "emulator"
    if home.is_file():
        return str(home)
    found = shutil.which("emulator")
    if found:
        return found
    raise RunSampleError("emulator binary not found")


def _guard_disable_set() -> bool:
    return os.environ.get("CONTEXTDROID_DEVICE_GUARD_DISABLE", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )


def _malware_go_set() -> bool:
    """Human go/no-go interlock for --tier malware (SAFETY.md)."""
    return os.environ.get("CONTEXTDROID_MALWARE_GO", "").strip() == "1"


def _refuse_malware_without_go(*, tier: str) -> None:
    """Hard refuse: process-only go/no-go is insufficient — require explicit env after sign-off."""
    if tier == "malware" and not _malware_go_set():
        raise RunSampleError(
            "REFUSE: --tier malware requires CONTEXTDROID_MALWARE_GO=1 after human "
            "go/no-go sign-off (see SAFETY.md). Canary path does not need this flag."
        )


def _refuse_guard_disable(*, tier: str, avd_name: str) -> None:
    if tier in ("malware", "canary") or avd_name == MW_AVD:
        if _guard_disable_set():
            raise RunSampleError(
                "REFUSE: CONTEXTDROID_DEVICE_GUARD_DISABLE is set on malware/abrg_mw path "
                "(Safety residual — never disable the device guard for this tier)"
            )


def _run(cmd: list[str], *, check: bool = True, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, env=merged)
    if check and proc.returncode != 0:
        raise RunSampleError(
            f"command failed rc={proc.returncode}: {' '.join(cmd)}\n"
            f"stdout={proc.stdout[-2000:]}\nstderr={proc.stderr[-2000:]}"
        )
    return proc


def _wipe_staging() -> None:
    if not is_mounted():
        return
    staging = STAGING_DIR
    if not staging.is_dir():
        return
    for child in staging.iterdir():
        if child.is_file() or child.is_symlink():
            child.unlink(missing_ok=True)
        elif child.is_dir():
            shutil.rmtree(child, ignore_errors=True)


def _staging_empty() -> bool:
    if not is_mounted():
        return False
    return not any(STAGING_DIR.iterdir()) if STAGING_DIR.is_dir() else True


def _device_online(serial: str) -> bool:
    adb = _adb_bin()
    proc = _run([adb, "-s", serial, "get-state"], check=False)
    return (proc.stdout or "").strip() == "device"


def _wait_boot(serial: str, timeout_sec: int = 180) -> None:
    adb = _adb_bin()
    _run([adb, "-s", serial, "wait-for-device"], check=True)
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        proc = _run([adb, "-s", serial, "shell", "getprop", "sys.boot_completed"], check=False)
        if (proc.stdout or "").strip().replace("\r", "") == "1":
            return
        time.sleep(1)
    raise RunSampleError(f"emulator {serial} did not boot within {timeout_sec}s")


def _kill_emulator(serial: str) -> None:
    adb = _adb_bin()
    _run([adb, "-s", serial, "emu", "kill"], check=False)
    time.sleep(4)


def _start_sink(run_id: str) -> None:
    script = REPO_ROOT / "scripts" / "safety" / "network_sink.sh"
    _run(["bash", str(script), "start", "--run-id", run_id], check=True)


def _stop_sink(run_id: str) -> None:
    script = REPO_ROOT / "scripts" / "safety" / "network_sink.sh"
    _run(["bash", str(script), "stop", "--run-id", run_id], check=False)


def _gate_a(run_id: str) -> None:
    script = REPO_ROOT / "scripts" / "safety" / "network_sink.sh"
    _run(["bash", str(script), "gate-a", "--run-id", run_id], check=True)


def _install_guest_rules() -> None:
    script = REPO_ROOT / "scripts" / "safety" / "guest_sink_rules.sh"
    _run(["bash", str(script), "install"], check=True)


def _teardown_guest_rules() -> None:
    script = REPO_ROOT / "scripts" / "safety" / "guest_sink_rules.sh"
    _run(["bash", str(script), "teardown"], check=False)


def _watchdog_start(run_id: str) -> None:
    script = REPO_ROOT / "scripts" / "safety" / "avd_session.sh"
    _run(["bash", str(script), "watchdog-start", "--run-id", run_id], check=True)


def _watchdog_stop(run_id: str) -> None:
    script = REPO_ROOT / "scripts" / "safety" / "avd_session.sh"
    _run(["bash", str(script), "watchdog-stop", "--run-id", run_id], check=False)


def _sink_running(run_id: str) -> bool:
    script = REPO_ROOT / "scripts" / "safety" / "network_sink.sh"
    proc = _run(["bash", str(script), "status", "--run-id", run_id], check=False)
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0 and "running" in out


def _sink_abort_flag(run_id: str) -> Path:
    return LOGS_DIR / "sink" / f"{run_id}.abort"


def _run_analyze_fail_closed(
    analyze_cmd: list[str],
    *,
    env: dict[str, str],
    run_id: str,
    poll_sec: float = 2.0,
) -> None:
    """Run analyze_apk under mid-run sink/vault/abort monitoring (plan 5.5)."""
    proc = subprocess.Popen(analyze_cmd, env=env)
    try:
        while True:
            rc = proc.poll()
            if rc is not None:
                if rc != 0:
                    raise RunSampleError(f"analyze_apk_exit={rc}")
                return
            if not is_mounted():
                proc.terminate()
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                raise RunSampleError("vault unmounted mid-run")
            abort = _sink_abort_flag(run_id)
            if abort.is_file():
                proc.terminate()
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                raise RunSampleError("sink_rule_watchdog abort flag mid-run")
            if not _sink_running(run_id):
                proc.terminate()
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                raise RunSampleError("network sink down mid-run")
            time.sleep(poll_sec)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


def _frida_server_host_bin() -> Path:
    """Host copy of frida-server for post-wipe push (SAFETY.md provisioning)."""
    env = os.environ.get("CONTEXTDROID_FRIDA_SERVER_BIN", "").strip()
    if env:
        path = Path(env)
        if path.is_file():
            return path
        raise RunSampleError(f"CONTEXTDROID_FRIDA_SERVER_BIN not a file: {path}")
    default = REPO_ROOT / "tools" / "frida-server-android-arm64"
    if default.is_file():
        return default
    raise RunSampleError(
        "REFUSE: frida-server host binary missing after wipe. Place matching "
        "android-arm64 frida-server at tools/frida-server-android-arm64 or set "
        "CONTEXTDROID_FRIDA_SERVER_BIN (must match .venv frida version)."
    )


def _provision_frida_server(serial: str) -> None:
    """adb root + remount + push/start frida-server (required after -wipe-data)."""
    adb = _adb_bin()
    host_bin = _frida_server_host_bin()
    _run([adb, "-s", serial, "root"], check=False)
    time.sleep(1)
    _run([adb, "-s", serial, "wait-for-device"], check=True)
    _run([adb, "-s", serial, "remount"], check=False)
    _run([adb, "-s", serial, "wait-for-device"], check=True)
    # Wipe clears /data/local/tmp; always re-push.
    _run([adb, "-s", serial, "push", str(host_bin), "/data/local/tmp/frida-server"], check=True)
    _run([adb, "-s", serial, "shell", "chmod", "755", "/data/local/tmp/frida-server"], check=True)
    _run([adb, "-s", serial, "shell", "pkill", "-9", "frida-server"], check=False)
    time.sleep(0.5)
    uid = _run([adb, "-s", serial, "shell", "id", "-u"], check=False)
    if (uid.stdout or "").strip().replace("\r", "") == "0":
        start = "nohup /data/local/tmp/frida-server >/dev/null 2>&1 </dev/null &"
    else:
        start = "su 0 sh -c 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 </dev/null &'"
    _run([adb, "-s", serial, "shell", start], check=False)
    time.sleep(2)
    pid = _run([adb, "-s", serial, "shell", "pidof", "frida-server"], check=False)
    if not (pid.stdout or "").strip():
        raise RunSampleError("frida-server failed to start after push")
    print(f"run_sample: frida-server provisioned from {host_bin} pid={(pid.stdout or '').strip()}")


def _wipe_boot_mw(*, run_id: str) -> None:
    """Fresh -wipe-data boot for abrg_mw after Gate A (SAFETY.md A2)."""
    # Gate A must already be green — re-check live.
    _gate_a(run_id)

    adb = _adb_bin()
    env = {
        "ADB_BIN": adb,
        "AVD_NAME": MW_AVD,
        "ANDROID_SERIAL": MW_SERIAL,
    }
    # hard-prelaunch (allows zero devices)
    _run(
        ["bash", str(REPO_ROOT / "scripts" / "safety" / "device_guard.sh"), "hard-prelaunch"],
        check=True,
        env=env,
    )
    if _device_online(MW_SERIAL):
        _kill_emulator(MW_SERIAL)

    dns_port = os.environ.get("ABRG_SINK_DNS_PORT", "15353")
    log_path = f"/tmp/abrg_run_sample_{run_id}.log"
    emu = _emu_bin()
    cmd = [
        emu,
        "-avd",
        MW_AVD,
        "-port",
        MW_PORT,
        "-dns-server",
        "127.0.0.1",
        "-wipe-data",
        "-writable-system",
        "-no-boot-anim",
        "-no-audio",
        "-gpu",
        "swiftshader_indirect",
        "-no-snapshot-load",
        "-no-snapshot-save",
        "-no-window",
    ]
    with open(log_path, "w", encoding="utf-8") as logf:
        subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, start_new_session=True)
    # dns_port recorded for operators; qemu uses :53 — guest DNAT is mandatory.
    print(f"run_sample: wipe-boot launched log={log_path} sink_dns_host_port={dns_port}")
    _wait_boot(MW_SERIAL)
    _provision_frida_server(MW_SERIAL)


def _ensure_mw_session(*, run_id: str, wipe_boot: bool) -> None:
    if wipe_boot or not _device_online(MW_SERIAL):
        _wipe_boot_mw(run_id=run_id)
    else:
        _gate_a(run_id)
        # Even without wipe, ensure frida-server is present (fail closed if missing).
        adb = _adb_bin()
        exists = _run(
            [adb, "-s", MW_SERIAL, "shell", "test", "-x", "/data/local/tmp/frida-server"],
            check=False,
        )
        if exists.returncode != 0:
            _provision_frida_server(MW_SERIAL)
    os.environ["AVD_NAME"] = MW_AVD
    os.environ["ANDROID_SERIAL"] = MW_SERIAL
    assert_device_identity_hard(
        _adb_bin(),
        expected_avd_name=MW_AVD,
        expected_serial=MW_SERIAL,
    )
    _install_guest_rules()
    _watchdog_start(run_id)


def _append_ledger(record: dict[str, Any]) -> None:
    append_run(record)


def _package_absent(pkg: str, serial: str) -> bool:
    adb = _adb_bin()
    proc = _run([adb, "-s", serial, "shell", "pm", "path", pkg], check=False)
    out = (proc.stdout or "").strip()
    return proc.returncode != 0 or not out


def run_sample(args: argparse.Namespace) -> int:
    tier = args.tier
    run_id = args.run_id or f"p5-{tier}-{uuid.uuid4().hex[:10]}"
    utc_start = _utc_now()
    outcome = "failed"
    notes = ""
    trace_path = ""
    config_hash = ""
    hooks_version = ""
    serial = ""
    device_count = 0
    staging_apk: Path | None = None
    sink_started = False
    rules_installed = False
    fingerprint = ""

    avd_name = MW_AVD if tier in ("malware", "canary") else BENIGN_AVD
    default_serial = MW_SERIAL if avd_name == MW_AVD else BENIGN_SERIAL
    os.environ.setdefault("ANDROID_SERIAL", default_serial)
    os.environ.setdefault("AVD_NAME", avd_name)

    try:
        # Code interlock before any vault/sink/install work (Safety: process-only is insufficient).
        _refuse_malware_without_go(tier=tier)
        _refuse_guard_disable(tier=tier, avd_name=avd_name)

        if args.seal_from and tier != "canary":
            raise RunSampleError(
                "REFUSE: --seal-from is only allowed for --tier canary "
                "(do not seal arbitrary APKs on malware tier)"
            )

        if tier in ("malware", "canary"):
            if not is_mounted():
                raise RunSampleError("REFUSE: vault not mounted — run scripts/safety/vault.sh mount")
            assert_mounted()
            ensure_layout()
            # Fail-closed hygiene: never start with residue (also recovers after
            # mid-run vault-unmount where finally could not wipe).
            _wipe_staging()
            if not _staging_empty():
                raise RunSampleError("REFUSE: staging not empty after pre-run wipe")

            # Optional seal-from for canary only: benign APK into quarantine as if malware.
            if args.seal_from:
                apk = Path(args.seal_from).resolve()
                if not apk.is_file():
                    raise RunSampleError(f"seal-from APK missing: {apk}")
                archive = quarantine_mod.seal(apk)
                digest = _sha256_file(apk)
                print(f"run_sample: sealed canary archive={archive} sha256={digest}")
                args.sha256 = digest

            if not args.sha256:
                raise RunSampleError("--sha256 required (or --seal-from)")
            sha = args.sha256.strip().lower()
            archive = quarantine_archive_path(sha)
            if not archive.is_file():
                raise RunSampleError(f"quarantine archive missing: {archive}")

            network_mode = "option_c_sink"
            reset_mechanism = "wipe_data_per_sample"

            # Sink before any malware-path AVD work (Gate A).
            _start_sink(run_id)
            sink_started = True
            _gate_a(run_id)

            if args.boot_if_needed:
                _ensure_mw_session(run_id=run_id, wipe_boot=not args.no_wipe_boot)
                rules_installed = True
            else:
                if not _device_online(MW_SERIAL):
                    raise RunSampleError(
                        f"REFUSE: {MW_SERIAL} not online and --no-boot-if-needed set"
                    )
                _gate_a(run_id)
                exists = _run(
                    [
                        _adb_bin(),
                        "-s",
                        MW_SERIAL,
                        "shell",
                        "test",
                        "-x",
                        "/data/local/tmp/frida-server",
                    ],
                    check=False,
                )
                if exists.returncode != 0:
                    _provision_frida_server(MW_SERIAL)
                os.environ["AVD_NAME"] = MW_AVD
                os.environ["ANDROID_SERIAL"] = MW_SERIAL
                assert_device_identity_hard(
                    _adb_bin(),
                    expected_avd_name=MW_AVD,
                    expected_serial=MW_SERIAL,
                )
                _install_guest_rules()
                _watchdog_start(run_id)
                rules_installed = True

            serial = MW_SERIAL
            device_count = 1
            fp_proc = _run(
                [_adb_bin(), "-s", serial, "shell", "getprop", "ro.build.fingerprint"],
                check=False,
            )
            fingerprint = (fp_proc.stdout or "").strip()

            out_dir = TRACES_DIR / run_id
            out_dir.mkdir(parents=True, exist_ok=True)

            snapshot = build_config_snapshot(
                tier=tier,
                avd_name=MW_AVD,
                duration_sec=args.duration,
                arm=args.arm,
                ollama_model=args.ollama_model,
                ollama_endpoint=args.ollama_endpoint,
                output_dir=out_dir,
                network_mode=network_mode,
                reset_mechanism=reset_mechanism,
                avd_fingerprint=fingerprint,
                repo_root=REPO_ROOT,
            )
            snap_path = write_config_snapshot(snapshot, out_dir / "config_snapshot.json")
            config_hash = str(snapshot.get("config_hash") or "")
            hooks_version = str(snapshot.get("hooks", {}).get("version") or "")
            print(f"run_sample: wrote {snap_path}")

            # Unseal only after sink + guard + Gate A.
            staging_apk = STAGING_DIR / f"{sha}.apk"
            quarantine_mod.unseal(sha, staging_apk)
            print(f"run_sample: unsealed -> {staging_apk}")

            if not args.pkg:
                raise RunSampleError("--pkg required")

            # Pre-install hard assert (analyze_apk also asserts).
            assert_device_identity_hard(
                _adb_bin(),
                expected_avd_name=MW_AVD,
                expected_serial=MW_SERIAL,
            )

            analyze_cmd = [
                sys.executable,
                str(REPO_ROOT / "extraction_pipeline" / "analyze_apk.py"),
                "--apk",
                str(staging_apk),
                "--pkg",
                args.pkg,
                "--duration",
                str(args.duration),
                "--output-dir",
                str(out_dir),
                "--arm",
                args.arm,
                "--session-id",
                run_id,
                "--ollama-model",
                args.ollama_model,
                "--ollama-endpoint",
                args.ollama_endpoint,
                "--fairness-protocol",
            ]
            if args.monkey_seed is not None:
                analyze_cmd.extend(["--monkey-seed", str(args.monkey_seed)])

            env = os.environ.copy()
            env["ADB_BIN"] = _adb_bin()
            env["AVD_NAME"] = MW_AVD
            env["ANDROID_SERIAL"] = MW_SERIAL
            env["FRIDA_USE_DOCKER"] = env.get("FRIDA_USE_DOCKER", "0")
            # Never allow guard disable on this path even if parent re-exports it.
            env.pop("CONTEXTDROID_DEVICE_GUARD_DISABLE", None)

            print(f"run_sample: analyze_apk starting duration={args.duration} arm={args.arm}", flush=True)
            _run_analyze_fail_closed(analyze_cmd, env=env, run_id=run_id)

            frida = out_dir / f"{args.pkg}_frida.jsonl"
            meta = out_dir / f"{args.pkg}_dynamic_metadata.json"
            if not frida.is_file():
                raise RunSampleError(f"missing frida trace after analyze: {frida}")
            if not meta.is_file():
                raise RunSampleError(f"missing metadata after analyze: {meta}")
            trace_path = str(frida)

            # Wipe staging before success ledger.
            _wipe_staging()
            if not _staging_empty():
                raise RunSampleError("staging not empty after wipe")

            if not _package_absent(args.pkg, MW_SERIAL):
                # analyze_apk should uninstall; force remove then note.
                _run([_adb_bin(), "-s", MW_SERIAL, "uninstall", args.pkg], check=False)
                notes = "forced_uninstall_after_analyze"

            outcome = "executed"
            print(
                f"run_sample: OK run_id={run_id} trace={trace_path} "
                f"staging_empty={_staging_empty()}"
            )
            return 0

        raise RunSampleError(
            f"tier={tier!r} not implemented for full orchestration "
            "(use --tier canary|malware for Phase 5 harness path)"
        )

    except Exception as exc:  # noqa: BLE001 — ledger every abort
        outcome = "failed"
        notes = f"{type(exc).__name__}: {exc}"
        print(f"run_sample: FAIL {notes}", file=sys.stderr)
        return 1
    finally:
        try:
            _wipe_staging()
        except Exception as wipe_exc:  # noqa: BLE001
            print(f"run_sample: staging wipe error: {wipe_exc}", file=sys.stderr)
        if rules_installed:
            try:
                _watchdog_stop(run_id)
            except Exception:
                pass
            try:
                _teardown_guest_rules()
            except Exception:
                pass
        if sink_started:
            try:
                _stop_sink(run_id)
            except Exception:
                pass
        utc_end = _utc_now()
        try:
            # Ledger is host-side (logs/ledger) — always record, including vault-unmount aborts.
            record = {
                "run_id": run_id,
                "utc_start": utc_start,
                "utc_end": utc_end,
                "sample_sha256": (args.sha256 or "unknown").strip().lower()
                if getattr(args, "sha256", None)
                else "unknown",
                "tier": tier,
                "avd_name": avd_name,
                "avd_fingerprint": fingerprint or "unknown",
                "snapshot_id": "wipe_data_per_sample"
                if tier in ("malware", "canary")
                else "none",
                "config_hash": config_hash or "none",
                "hooks_version": hooks_version or "unknown",
                "network_mode": "option_c_sink"
                if tier in ("malware", "canary")
                else "benign_default",
                "adb_device_serial": serial or os.environ.get("ANDROID_SERIAL", ""),
                "adb_device_count": int(device_count),
                "outcome": outcome,
                "trace_path": trace_path or "",
                "notes": notes[:2000],
            }
            # sample_sha256 must be non-empty; use placeholder only for pre-seal refuse.
            if record["sample_sha256"] in ("", None):
                record["sample_sha256"] = "unknown"
            _append_ledger(record)
            print(f"run_sample: ledger outcome={outcome} run_id={run_id}", flush=True)
        except Exception as led_exc:  # noqa: BLE001
            print(f"run_sample: ledger append failed: {led_exc}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="ContextDroid malware/canary tier run entry point")
    p.add_argument("--sha256", default="", help="Sample sha256 already sealed in quarantine/")
    p.add_argument(
        "--seal-from",
        type=Path,
        default=None,
        help="Seal this benign APK into quarantine first (--tier canary only)",
    )
    p.add_argument("--tier", choices=("malware", "canary", "benign"), required=True)
    p.add_argument("--pkg", default="", help="Android package name")
    p.add_argument("--duration", type=int, default=60)
    p.add_argument("--arm", choices=("llm", "monkey"), default="monkey")
    p.add_argument("--run-id", default="")
    p.add_argument("--ollama-model", default=os.environ.get("OLLAMA_MODEL", "llama3.2"))
    p.add_argument(
        "--ollama-endpoint",
        default=os.environ.get("OLLAMA_ENDPOINT", "http://127.0.0.1:11434"),
    )
    p.add_argument("--monkey-seed", type=int, default=424242)
    p.add_argument(
        "--no-wipe-boot",
        action="store_true",
        help="Reuse already-booted abrg_mw (still requires Gate A + guest rules)",
    )
    p.add_argument(
        "--no-boot-if-needed",
        action="store_true",
        help="Do not launch emulator; fail if abrg_mw offline",
    )
    p.add_argument(
        "--boot-if-needed",
        action="store_true",
        default=True,
        help=argparse.SUPPRESS,
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.no_boot_if_needed:
        args.boot_if_needed = False
    return run_sample(args)


if __name__ == "__main__":
    raise SystemExit(main())
