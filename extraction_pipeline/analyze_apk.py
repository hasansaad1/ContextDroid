#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from context_builder import build_app_context
from llm_agent import run_llm_agent_session
from llm_agent.device import (
    check_target_foreground,
    isolate_emulator_state,
    strict_foreground_enabled,
)
from subprocess_util import run_subprocess_with_timeout
from llm_agent.config import _PRE_SETUP_MAX_SEC
from pipeline_errors import AnalysisFailure
from safety.device_guard import (
    DeviceGuardError,
    assert_device_identity_hard,
    get_guard_timing_snapshot,
    raise_if_watchdog_failed,
    reset_guard_timing,
    start_device_count_watchdog,
    stop_device_count_watchdog,
)
from protocol_config import (
    DEFAULT_ARM,
    DEFAULT_CONTEXT_CONFIDENCE,
    DEFAULT_METADATA_SOURCE,
    PRE_ONBOARDING_MONKEY_EVENTS,
    PRE_ONBOARDING_MONKEY_SEED,
    SESSION_TIMEOUT_MULTIPLIER,
)

DOCKER_FRIDA_IMAGE = os.environ.get("FRIDA_DOCKER_IMAGE", "frida-tools-local:14.8.1")
FRIDA_VERSION = os.environ.get("FRIDA_VERSION", "17.9.1")
FRIDA_TOOLS_VERSION = os.environ.get("FRIDA_TOOLS_VERSION", "14.9.0")

EXIT_OK = 0
EXIT_INSTALL_FAILED = 10
EXIT_APP_UNSTABLE = 11
EXIT_FRIDA_ATTACH_FAILED = 12
EXIT_UNEXPECTED = 13
EXIT_SNAPSHOT_FAILED = 14
EXIT_PM_CLEAR_FAILED = 15
EXIT_OLLAMA_STARTUP_FAILED = 16
EXIT_FOREGROUND_MISMATCH = 17
EXIT_DEVICE_GUARD = 18


def _frida_events_stale_sec() -> float:
    raw = os.environ.get("FRIDA_EVENTS_STALE_SEC", "45").strip()
    try:
        return max(10.0, float(raw))
    except ValueError:
        return 45.0


def _frida_attach_grace_sec() -> float:
    raw = os.environ.get("FRIDA_ATTACH_GRACE_SEC", "30").strip()
    try:
        return max(5.0, float(raw))
    except ValueError:
        return 30.0


def _frida_post_hook_silence_sec() -> float:
    raw = os.environ.get("FRIDA_POST_HOOK_SILENCE_SEC", "20").strip()
    try:
        return max(5.0, float(raw))
    except ValueError:
        return 20.0


def _frida_healthcheck_interval_sec() -> float:
    raw = os.environ.get("FRIDA_HEALTHCHECK_INTERVAL_SEC", "8").strip()
    try:
        return max(3.0, float(raw))
    except ValueError:
        return 8.0


def _frida_cli_timeout() -> str:
    raw = os.environ.get("FRIDA_CLI_TIMEOUT", "inf").strip()
    return raw if raw else "inf"


def _frida_count_events_in_text(text: str) -> int:
    count = 0
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        if '"type":"event"' in line or '"type": "event"' in line:
            count += 1
    return count


_LOW_SIGNAL_FRIDA_CATEGORIES = frozenset({"lifecycle", "reflection", "unknown"})


def _frida_event_category(line: str) -> str:
    match = re.search(r'"category"\s*:\s*"([^"]+)"', line)
    return match.group(1) if match else ""


def _frida_count_meaningful_events_in_text(text: str) -> int:
    count = 0
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        if '"type":"event"' not in line and '"type": "event"' not in line:
            continue
        if _frida_event_category(line) not in _LOW_SIGNAL_FRIDA_CATEGORIES:
            count += 1
    return count


def _frida_slice_shows_cli_exit(chunk: str) -> bool:
    if not chunk:
        return False
    lower = chunk.lower()
    return (
        "thank you for using frida" in lower
        or "detached from" in lower
        or "process terminated" in lower
    )


def _frida_slice_shows_disconnect(chunk: str) -> bool:
    if not chunk:
        return False
    markers = (
        "Connection terminated",
        "Failed to attach",
        "process not found",
        "unable to connect",
        "session is gone",
        "device is offline",
        "connection closed",
    )
    lower = chunk.lower()
    return _frida_slice_shows_cli_exit(chunk) or any(m.lower() in lower for m in markers)


def _frida_liveness_failure_reason(
    *,
    proc_dead: bool,
    chunk: str,
    hook_confirmed: bool,
    now: float,
    grace_until: float,
    last_activity_at: float,
    saw_meaningful_events: bool,
    last_meaningful_event_at: float,
    post_hook_silence_sec: float,
    stale_sec: float,
) -> str | None:
    if proc_dead:
        return "process_exit"
    if _frida_slice_shows_disconnect(chunk):
        return "detach"
    if not hook_confirmed or now < grace_until:
        return None
    if now - last_activity_at >= post_hook_silence_sec:
        return "post_hook_silence"
    if saw_meaningful_events and now - last_meaningful_event_at >= stale_sec:
        return "stale_events"
    return None


def _is_pid_alive(adb_bin: str, pid: str) -> bool:
    """Return True when the device process for pid still exists."""
    if not pid or not str(pid).strip().isdigit():
        return False
    result = run_command([adb_bin, "shell", "kill", "-0", pid], check=False, timeout_sec=5)
    return result.returncode == 0


def _backfill_llm_session_info_from_disk(output_dir: Path, package_name: str, llm_session_info: dict) -> None:
    """Preserve partial LLM session fields when analysis fails mid-simulation."""
    action_log = output_dir / f"{package_name}_llm_actions.jsonl"
    if not action_log.exists():
        return
    if not llm_session_info.get("llm_action_log_path"):
        llm_session_info["llm_action_log_path"] = str(action_log)
    if not llm_session_info.get("llm_actions_count"):
        count = sum(1 for line in action_log.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
        llm_session_info["llm_actions_count"] = count
    for suffix, key in (
        ("_human_ux_report.json", "human_ux_report_path"),
        ("_llm_ux_plan.json", "llm_ux_plan_path"),
        ("_llm_navigation_artifact.json", "llm_navigation_artifact_path"),
    ):
        path = output_dir / f"{package_name}{suffix}"
        if path.exists() and not llm_session_info.get(key):
            llm_session_info[key] = str(path)


def _ensure_ollama_server(ollama_endpoint: str) -> None:
    """Start `ollama serve` via ensure_ollama.sh when the HTTP API is not yet reachable."""
    if os.environ.get("SKIP_OLLAMA_AUTO_START", "").strip() == "1":
        return
    script = Path(__file__).resolve().parent / "ensure_ollama.sh"
    if not script.is_file():
        logging.warning("ensure_ollama.sh not found; skipping Ollama auto-start")
        return
    env = os.environ.copy()
    env["OLLAMA_ENDPOINT"] = ollama_endpoint
    repo = Path(__file__).resolve().parents[1]
    env.setdefault("LOG_DIR", str(repo / "logs"))
    res = subprocess.run(["/bin/bash", str(script)], env=env, check=False, capture_output=True, text=True)
    if res.returncode != 0:
        tail = ((res.stderr or "") + (res.stdout or "")).strip()
        if len(tail) > 2000:
            tail = tail[-2000:]
        raise AnalysisFailure(f"failed_ollama_startup: {tail}", EXIT_OLLAMA_STARTUP_FAILED)


def configure_logging() -> None:
    log_file = Path("pipeline.log")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(log_file, encoding="utf-8")],
    )


def run_command(
    cmd: list[str],
    check: bool = True,
    text: bool = True,
    timeout_sec: Optional[float] = None,
) -> subprocess.CompletedProcess:
    logging.info("Running command: %s", " ".join(cmd))
    return run_subprocess_with_timeout(cmd, check=check, text=text, timeout_sec=timeout_sec)


def safe_terminate(process: Optional[subprocess.Popen], name: str) -> None:
    if process is None or process.poll() is not None:
        return
    logging.info("Stopping %s process (pid=%s)", name, process.pid)
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def resolve_adb_bin() -> str:
    """Resolve adb binary, pinning ANDROID_SERIAL via adb_pinned.sh when set.

    Explicit -s on every device command is structural prevention: a second
    attached device cannot receive malware-path commands even if env is ignored.
    """
    env_adb = os.environ.get("ADB_BIN", "").strip()
    repo_root = Path(__file__).resolve().parents[1]
    if env_adb:
        real_adb = env_adb
    else:
        repo_adb = repo_root / "tools" / "platform-tools" / "adb"
        if repo_adb.exists():
            real_adb = str(repo_adb)
        else:
            discovered = shutil.which("adb")
            if discovered:
                real_adb = discovered
            else:
                fallback = Path.home() / "Library" / "Android" / "sdk" / "platform-tools" / "adb"
                real_adb = str(fallback) if fallback.exists() else "adb"

    serial = (os.environ.get("ANDROID_SERIAL") or "").strip()
    if not serial:
        return real_adb

    pinned = repo_root / "scripts" / "safety" / "adb_pinned.sh"
    if not pinned.is_file():
        return real_adb
    # Avoid wrapping the wrapper if ADB_BIN was already pointed at it.
    if Path(real_adb).resolve() == pinned.resolve():
        return real_adb
    os.environ["CONTEXTDROID_REAL_ADB"] = real_adb
    return str(pinned)


def resolve_frida_bin() -> str:
    base_dir = Path(__file__).resolve().parents[1]
    local_bin = base_dir / ".venv" / "bin" / "frida"
    if local_bin.exists():
        return str(local_bin)
    discovered = shutil.which("frida")
    return discovered if discovered else "frida"


def should_use_docker_frida() -> bool:
    return os.environ.get("FRIDA_USE_DOCKER", "1") == "1"


def ensure_docker_frida_image() -> str:
    image = DOCKER_FRIDA_IMAGE
    inspect = run_command(["docker", "image", "inspect", image], check=False)
    if inspect.returncode == 0:
        return image
    dockerfile = f"FROM python:3.11-slim\nRUN pip install -q frida=={FRIDA_VERSION} frida-tools=={FRIDA_TOOLS_VERSION}\n"
    build = subprocess.run(["docker", "build", "-t", image, "-"], input=dockerfile, text=True, capture_output=True)
    if build.returncode != 0:
        raise RuntimeError("Could not build Docker Frida image")
    return image


def get_pid(package_name: str) -> Optional[str]:
    result = run_command([resolve_adb_bin(), "shell", "pidof", package_name], check=False)
    pid = (result.stdout or "").strip()
    return pid.split()[0] if pid else None


def retry_get_pid(package_name: str, retries: int = 10, delay_sec: float = 1.0) -> Optional[str]:
    for _ in range(retries):
        pid = get_pid(package_name)
        if pid:
            return pid
        time.sleep(delay_sec)
    return None


def resolve_main_activity(package_name: str) -> Optional[str]:
    result = run_command(
        [resolve_adb_bin(), "shell", "cmd", "package", "resolve-activity", "--brief", package_name],
        check=False,
    )
    if result.returncode != 0:
        return None
    lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    for line in reversed(lines):
        if "/" in line and not line.startswith("priority="):
            return line
    return None


def force_launch_activity(package_name: str) -> bool:
    target = resolve_main_activity(package_name)
    if not target:
        return False
    launch = run_command([resolve_adb_bin(), "shell", "am", "start", "-n", target], check=False)
    return launch.returncode == 0


def ensure_app_running(adb_bin: str, package_name: str, attempts: int = 2, min_stable_sec: int = 10) -> Optional[str]:
    for attempt in range(1, attempts + 1):
        run_command(
            [adb_bin, "shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
            check=False,
        )
        force_launch_activity(package_name)
        time.sleep(1.5)
        pid = retry_get_pid(package_name, retries=3, delay_sec=0.8)
        if not pid:
            continue
        stable = True
        stable_pid = pid
        for _ in range(min_stable_sec):
            time.sleep(1)
            current_pid = get_pid(package_name)
            if not current_pid:
                stable = False
                break
            stable_pid = current_pid
        if stable:
            return stable_pid
        if attempt < attempts:
            logging.info("Retrying launch for %s", package_name)
    return None


def _reject_frida_skip_env() -> None:
    skip = os.environ.get("CONTEXTDROID_SKIP_FRIDA", "").strip().lower()
    if skip in ("1", "true", "yes"):
        raise SystemExit(
            "CONTEXTDROID_SKIP_FRIDA is not supported. Frida must attach successfully before "
            "simulation starts. Fix frida-server / Docker Frida setup instead."
        )


def _frida_log_tail(frida_log_path: Path, max_lines: int = 20) -> str:
    if not frida_log_path.exists():
        return "<no frida log yet>"
    lines = frida_log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    if not lines:
        return "<empty frida log>"
    return "\n".join(lines[-max_lines:])


def _frida_log_byte_offset(frida_log_path: Path) -> int:
    if not frida_log_path.exists():
        return 0
    return frida_log_path.stat().st_size


def _frida_log_slice(frida_log_path: Path, offset: int) -> str:
    if not frida_log_path.exists():
        return ""
    with frida_log_path.open("rb") as handle:
        handle.seek(max(0, offset))
        return handle.read().decode("utf-8", errors="ignore")


def _frida_chunk_indicates_attach_success(chunk: str) -> bool:
    """True when this attach attempt's log slice shows hooks loaded successfully."""
    if not chunk:
        return False
    if "Failed to attach" in chunk:
        return False
    return "hook_loaded" in chunk


def wait_for_frida_attach(
    frida_proc: subprocess.Popen,
    frida_log_path: Path,
    timeout_sec: int = 10,
    *,
    log_offset: int = 0,
) -> bool:
    start = time.time()
    deadline = start + timeout_sec
    while True:
        chunk = _frida_log_slice(frida_log_path, log_offset)
        if _frida_chunk_indicates_attach_success(chunk):
            if frida_proc.poll() is None:
                return True
            logging.error(
                "Frida hook_loaded seen but process exited (code=%s). Log tail:\n%s",
                frida_proc.returncode,
                _frida_log_tail(frida_log_path),
            )
            return False
        if frida_proc.poll() is not None:
            logging.error(
                "Frida process exited early (code=%s). Log tail:\n%s",
                frida_proc.returncode,
                _frida_log_tail(frida_log_path),
            )
            return False
        if time.time() >= deadline:
            break
        time.sleep(min(0.5, max(0.0, deadline - time.time())))
    logging.error(
        "Frida attach timed out after %ss (no hook_loaded in new log slice). Log tail:\n%s",
        timeout_sec,
        _frida_log_tail(frida_log_path),
    )
    return False


def attach_frida_or_fail(
    adb_bin: str,
    base_dir: Path,
    frida_bin: str,
    hook_script: Path,
    package_name: str,
    frida_log_path: Path,
    *,
    attach_timeout_sec: Optional[int] = None,
    attach_attempts: Optional[int] = None,
    force_frida_restart: bool = False,
    append_log: bool = False,
    relaunch_before_attach: bool = False,
    cold_relaunch_before_attach: bool = False,
    prefer_attach_by_name: bool = False,
    spawn_attach: bool = False,
) -> tuple[subprocess.Popen, object, str, str]:
    """Start frida-server if needed, attach hooks, and fail before simulation if attach does not succeed."""
    if attach_timeout_sec is None:
        attach_timeout_sec = int(os.environ.get("FRIDA_ATTACH_TIMEOUT_SEC", "20" if should_use_docker_frida() else "12"))
    if attach_attempts is None:
        attach_attempts = int(os.environ.get("FRIDA_ATTACH_ATTEMPTS", "3"))

    frida_server_ready, frida_server_state = ensure_frida_server_running(adb_bin, force_restart=force_frida_restart)
    if not frida_server_ready:
        logging.error("frida-server not available on device (state=%s)", frida_server_state)
        raise AnalysisFailure("failed_frida_server", EXIT_FRIDA_ATTACH_FAILED)

    attach_modes = ("spawn",) if spawn_attach else _frida_attach_modes(prefer_name=prefer_attach_by_name)
    last_tail = "<no attach attempts>"
    for attempt in range(1, max(1, attach_attempts) + 1):
        relaunch = relaunch_before_attach or attempt > 1
        if attempt > 1:
            frida_server_ready, frida_server_state = ensure_frida_server_running(adb_bin, force_restart=True)
            if not frida_server_ready:
                logging.error("frida-server lost during attach retries (state=%s)", frida_server_state)
                break
        if spawn_attach:
            app_pid = None
        else:
            app_pid = _resolve_attach_pid(
                adb_bin,
                package_name,
                relaunch=relaunch,
                cold=cold_relaunch_before_attach,
            )
        if not app_pid and "pid" in attach_modes:
            logging.warning("Frida attach attempt %s/%s: no live pid for %s", attempt, attach_attempts, package_name)

        for attach_mode in attach_modes:
            if attach_mode == "pid" and not app_pid:
                continue
            log_offset = _frida_log_byte_offset(frida_log_path) if append_log else 0
            frida_proc, frida_output_handle = _start_frida_process(
                base_dir,
                frida_bin,
                hook_script,
                frida_log_path,
                attach_mode=attach_mode,
                app_pid=app_pid or "",
                package_name=package_name,
                append_log=append_log,
            )
            if wait_for_frida_attach(
                frida_proc, frida_log_path, timeout_sec=attach_timeout_sec, log_offset=log_offset
            ):
                live_pid = retry_get_pid(package_name, retries=3, delay_sec=0.3) or app_pid or ""
                logging.info(
                    "Frida attached via %s (frida-server state=%s, pid=%s, attempt=%s/%s)",
                    attach_mode,
                    frida_server_state,
                    live_pid,
                    attempt,
                    attach_attempts,
                )
                return frida_proc, frida_output_handle, frida_server_state, live_pid

            last_tail = _frida_log_tail(frida_log_path)
            safe_terminate(frida_proc, "frida")
            try:
                frida_output_handle.close()
            except Exception:
                pass
            logging.warning(
                "Frida attach attempt %s/%s mode=%s failed for %s pid=%s. Log tail:\n%s",
                attempt,
                attach_attempts,
                attach_mode,
                package_name,
                app_pid or "<name>",
                last_tail,
            )
    logging.error("Frida attach failed after %s attempts. Last log tail:\n%s", attach_attempts, last_tail)
    raise AnalysisFailure("failed_frida_attach", EXIT_FRIDA_ATTACH_FAILED)


def start_frida(
    base_dir: Path, frida_bin: str, hook_script: Path, app_pid: str, frida_log_path: Path, *, append_log: bool = False
) -> tuple[subprocess.Popen, object]:
    return _start_frida_process(
        base_dir,
        frida_bin,
        hook_script,
        frida_log_path,
        attach_mode="pid",
        app_pid=app_pid,
        package_name="",
        append_log=append_log,
    )


def file_sha256(path: Path) -> str:
    if not path.exists():
        return ""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _hook_script_version(path: Path) -> str:
    if not path.exists():
        return "unknown"
    text = path.read_text(encoding="utf-8", errors="ignore")
    match = re.search(r'version:\s*"(\d+)"', text)
    return match.group(1) if match else "unknown"


def run_deterministic_stimulus(adb_bin: str, package_name: str) -> None:
    commands = [
        [adb_bin, "shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
        [adb_bin, "shell", "input", "tap", "300", "800"],
        [adb_bin, "shell", "input", "swipe", "300", "1100", "300", "400", "250"],
        [adb_bin, "shell", "input", "text", "frida_test_signal"],
        [adb_bin, "shell", "input", "keyevent", "66"],
    ]
    for cmd in commands:
        run_command(cmd, check=False)
        time.sleep(0.4)


def _frida_server_pid(adb_bin: str) -> str:
    check = run_command([adb_bin, "shell", "pidof", "frida-server"], check=False, timeout_sec=8)
    return (check.stdout or "").strip().split()[0] if (check.stdout or "").strip() else ""


def _adb_shell_uid(adb_bin: str) -> str:
    res = run_command([adb_bin, "shell", "id", "-u"], check=False, timeout_sec=8)
    return (res.stdout or "").strip()


def _su_available(adb_bin: str) -> bool:
    res = run_command([adb_bin, "shell", "su", "0", "id", "-u"], check=False, timeout_sec=10)
    return (res.stdout or "").strip() == "0"


def _ensure_adb_root(adb_bin: str) -> bool:
    """Frida attach requires frida-server running as root."""
    run_command([adb_bin, "root"], check=False, timeout_sec=15)
    run_command([adb_bin, "wait-for-device"], check=False, timeout_sec=60)
    run_command([adb_bin, "remount"], check=False, timeout_sec=30)
    run_command([adb_bin, "wait-for-device"], check=False, timeout_sec=30)
    uid = _adb_shell_uid(adb_bin)
    if uid == "0":
        return True
    if _su_available(adb_bin):
        logging.info("adb shell uid=%s but su 0 works; will start frida-server via su", uid or "?")
        return True
    logging.error("adb root unavailable (shell uid=%s, su unavailable)", uid or "<unknown>")
    return False


def _launch_frida_server_daemon(adb_bin: str) -> bool:
    """Start frida-server and confirm it is root-owned."""
    starters = [
        "nohup /data/local/tmp/frida-server >/dev/null 2>&1 </dev/null &",
        "su 0 sh -c 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 </dev/null &'",
    ]
    shell_is_root = _adb_shell_uid(adb_bin) == "0"
    if not shell_is_root:
        starters = [starters[1], starters[0]]
    for cmd in starters:
        run_command([adb_bin, "shell", cmd], check=False, timeout_sec=3)
        for _ in range(20):
            time.sleep(0.5)
            if _frida_server_pid(adb_bin) and _frida_server_is_root(adb_bin):
                return True
        _stop_frida_server(adb_bin)
    return False


def _frida_server_owner(adb_bin: str) -> str:
    pid = _frida_server_pid(adb_bin)
    if not pid:
        return ""
    res = run_command(
        [adb_bin, "shell", "ps", "-o", "USER=", "-p", pid],
        check=False,
        timeout_sec=8,
    )
    owner = (res.stdout or "").strip()
    if owner:
        return owner
    uid_res = run_command(
        [adb_bin, "shell", f"grep '^Uid:' /proc/{pid}/status 2>/dev/null | awk '{{print $2}}'"],
        check=False,
        timeout_sec=8,
    )
    uid = (uid_res.stdout or "").strip()
    if uid == "0":
        return "root"
    return uid


def _frida_server_is_root(adb_bin: str) -> bool:
    owner = _frida_server_owner(adb_bin)
    return owner in ("root", "0")


def _stop_frida_server(adb_bin: str) -> None:
    pid = _frida_server_pid(adb_bin)
    if pid:
        run_command([adb_bin, "shell", "kill", "-9", pid], check=False, timeout_sec=5)
    run_command([adb_bin, "shell", "pkill", "-9", "frida-server"], check=False, timeout_sec=5)
    time.sleep(0.3)


def ensure_frida_server_running(adb_bin: str, *, force_restart: bool = False) -> tuple[bool, str]:
    """Ensure a root-owned frida-server is listening on the device."""
    if not _ensure_adb_root(adb_bin):
        return False, "adb_root_failed"

    exists = run_command([adb_bin, "shell", "test", "-x", "/data/local/tmp/frida-server"], check=False, timeout_sec=8)
    if exists.returncode != 0:
        return False, "frida_server_missing"

    pid = _frida_server_pid(adb_bin)
    if pid and not force_restart and _frida_server_is_root(adb_bin):
        return True, "already_running"

    if pid:
        owner = _frida_server_owner(adb_bin) or "unknown"
        if force_restart:
            logging.info("Restarting frida-server (force_restart=1, owner=%s, pid=%s)", owner, pid)
        else:
            logging.warning(
                "frida-server running as %s (pid=%s); restarting as root for attach capability",
                owner,
                pid,
            )
        _stop_frida_server(adb_bin)

    if _launch_frida_server_daemon(adb_bin):
        return True, "started"
    owner = _frida_server_owner(adb_bin)
    if _frida_server_pid(adb_bin):
        logging.error("frida-server started but not root-owned (owner=%s)", owner or "unknown")
        return False, "started_non_root"
    return False, "start_failed"


def _resolve_attach_pid(adb_bin: str, package_name: str, *, relaunch: bool = False, cold: bool = False) -> Optional[str]:
    old_pid = retry_get_pid(package_name, retries=1, delay_sec=0.1)
    if cold:
        run_command([adb_bin, "shell", "am", "force-stop", package_name], check=False, timeout_sec=10)
        time.sleep(0.8)
        force_launch_activity(package_name)
        time.sleep(2.0)
    elif relaunch:
        force_launch_activity(package_name)
        time.sleep(1.5)
    pid = retry_get_pid(package_name, retries=6 if cold else 4, delay_sec=0.5)
    if pid and _is_pid_alive(adb_bin, pid):
        if cold and old_pid and pid == old_pid:
            logging.warning(
                "Cold relaunch for %s still has pid=%s; waiting for process rotation.",
                package_name,
                pid,
            )
            time.sleep(2.0)
            rotated = retry_get_pid(package_name, retries=4, delay_sec=0.5)
            if rotated and _is_pid_alive(adb_bin, rotated):
                pid = rotated
        return pid
    if pid and not _is_pid_alive(adb_bin, pid):
        logging.warning("pidof returned %s for %s but kill -0 failed; treating as dead.", pid, package_name)
    if not relaunch and not cold:
        return _resolve_attach_pid(adb_bin, package_name, relaunch=True)
    if not cold:
        return _resolve_attach_pid(adb_bin, package_name, relaunch=True, cold=True)
    return None


def _frida_attach_modes(*, prefer_name: bool) -> tuple[str, ...]:
    if prefer_name:
        return ("name", "pid")
    return ("pid", "name")


def _start_frida_process(
    base_dir: Path,
    frida_bin: str,
    hook_script: Path,
    frida_log_path: Path,
    *,
    attach_mode: str,
    app_pid: str,
    package_name: str,
    append_log: bool = False,
) -> tuple[subprocess.Popen, object]:
    mode = "a" if append_log else "w"
    if attach_mode == "name":
        if not package_name:
            raise ValueError("package_name required for name attach")
        # Android package names require -N (attach-identifier), not -n (attach-name).
        target_args = ["-N", package_name]
    elif attach_mode == "spawn":
        if not package_name:
            raise ValueError("package_name required for spawn attach")
        target_args = ["-f", package_name]
    else:
        if not app_pid:
            raise ValueError("app_pid required for pid attach")
        target_args = ["-p", app_pid]

    if should_use_docker_frida():
        run_command([resolve_adb_bin(), "forward", "tcp:27042", "tcp:27042"], check=False)
        image = ensure_docker_frida_image()
        hook_rel = hook_script.relative_to(base_dir)
        hook_container = f"/project/{hook_rel.as_posix()}"
        target_flag = target_args[0]
        target_value = target_args[1]
        cli_timeout = _frida_cli_timeout()
        script = (
            f'/usr/local/bin/frida -H host.docker.internal:27042 {target_flag} {target_value} '
            f'-l "{hook_container}" -q -t {cli_timeout}'
        )
        frida_out = frida_log_path.open(mode, encoding="utf-8")
        proc = subprocess.Popen(
            ["docker", "run", "--rm", "-v", f"{base_dir}:/project", "-w", "/project", image, "sh", "-lc", script],
            stdout=frida_out,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
        )
        return proc, frida_out

    frida_out = frida_log_path.open(mode, encoding="utf-8")
    proc = subprocess.Popen(
        [
            frida_bin,
            "-U",
            *target_args,
            "-l",
            str(hook_script),
            "-q",
            "-t",
            _frida_cli_timeout(),
        ],
        stdout=frida_out,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
    )
    return proc, frida_out


def _restore_snapshot(adb_bin: str) -> bool:
    """Restore emulator snapshot if available; skip when load crashes the AVD (GLES drift)."""
    skip = os.environ.get("CONTEXTDROID_SKIP_SNAPSHOT_LOAD", "").strip().lower()
    if skip in ("1", "true", "yes"):
        res = run_command([adb_bin, "shell", "getprop", "sys.boot_completed"], check=False)
        if (res.stdout or "").strip() == "1":
            logging.info("Skipping AVD snapshot load (CONTEXTDROID_SKIP_SNAPSHOT_LOAD=1); device already booted")
            return True
        return False

    # Best effort: if snapshot support is unavailable, the run still proceeds.
    run_command([adb_bin, "emu", "avd", "snapshot", "load", "default_boot"], check=False)
    run_command([adb_bin, "wait-for-device"], check=False)
    boot_done = "0"
    for _ in range(60):
        res = run_command([adb_bin, "shell", "getprop", "sys.boot_completed"], check=False)
        boot_done = (res.stdout or "").strip()
        if boot_done == "1":
            return True
        time.sleep(1)
    return False


def _extract_declared_permissions(apk_path: Path) -> list[str]:
    aapt_bin = shutil.which("aapt")
    if not aapt_bin:
        return []
    res = run_command([aapt_bin, "dump", "permissions", str(apk_path)], check=False)
    perms: list[str] = []
    for line in (res.stdout or "").splitlines():
        if "name='" in line:
            value = line.split("name='", 1)[1].split("'", 1)[0].strip()
            if value:
                perms.append(value)
    # Keep deterministic order without duplicates.
    return sorted(set(perms))


def _bounds_center(bounds: str) -> Optional[tuple[int, int]]:
    if not bounds.startswith("[") or "][" not in bounds:
        return None
    try:
        left, right = bounds.split("][", 1)
        x1, y1 = left.lstrip("[").split(",")
        x2, y2 = right.rstrip("]").split(",")
        xi1, yi1, xi2, yi2 = int(x1), int(y1), int(x2), int(y2)
        if xi2 <= xi1 or yi2 <= yi1:
            return None
        return ((xi1 + xi2) // 2, (yi1 + yi2) // 2)
    except Exception:
        return None


def _parse_uiautomator_nodes(xml_text: str) -> list[dict[str, object]]:
    if not xml_text.strip():
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    nodes: list[dict[str, object]] = []
    for node in root.iter("node"):
        bounds = node.attrib.get("bounds", "")
        center = _bounds_center(bounds)
        if center is None:
            continue
        nodes.append(
            {
                "text": (node.attrib.get("text", "") or "").strip(),
                "desc": (node.attrib.get("content-desc", "") or "").strip(),
                "rid": (node.attrib.get("resource-id", "") or "").strip(),
                "clazz": (node.attrib.get("class", "") or "").strip(),
                "pkg": (node.attrib.get("package", "") or "").strip(),
                "clickable": (node.attrib.get("clickable", "false") or "") == "true",
                "center": center,
            }
        )
    return nodes


def _ui_structure_hash(nodes: list[dict[str, object]]) -> tuple[int, str]:
    """Return (cheap_compare_int, stable_hex) for transition guard vs logging."""
    key: list[tuple[str, str, str, str, tuple[int, int]]] = []
    for n in nodes:
        c = n["center"]
        if not isinstance(c, tuple):
            continue
        key.append(
            (
                str(n.get("text", "")),
                str(n.get("desc", "")),
                str(n.get("rid", "")),
                str(n.get("clazz", "")),
                (int(c[0]), int(c[1])),
            )
        )
    tup = tuple(sorted(key))
    digest = hashlib.sha256(repr(tup).encode("utf-8", errors="replace")).hexdigest()[:16]
    return hash(tup), digest


def _choose_setup_tap_target(nodes: list[dict[str, object]]) -> tuple[Optional[tuple[int, int]], str]:
    """Button-priority scoring (v3 experiment). Permission allows win on system surfaces; dismiss beats generic allowish."""
    dismiss_terms = (
        "no thanks",
        "skip",
        "not now",
        "cancel",
        "later",
        "disable",
        "don't allow",
        "do not allow",
        "no",
    )
    avoid_terms = (
        "add account",
        "sign in",
        "login",
        "create account",
        "sync now",
        "turn on sync",
        "enable updates",
        "automatic updates",
        "check for updates",
        "keep updated",
    )
    permission_allow_substrings = ("allow", "while using the app", "only this time", "grant")
    generic_allow_terms = ("allow", "continue", "ok", "while using the app", "only this time", "grant")

    blob = " | ".join(
        (str(n.get("text", "")) + " " + str(n.get("desc", ""))).strip().lower() for n in nodes
    )
    pkg_blob = " | ".join(str(n.get("pkg", "")).lower() for n in nodes)
    is_permission_surface = (
        "permissioncontroller" in pkg_blob
        or "packageinstaller" in pkg_blob
        or any("permission_allow" in str(n.get("rid", "")).lower() for n in nodes)
        or "while using the app" in blob
        or re.search(r"\ballow\b", blob) is not None
    )

    candidates: list[tuple[int, str, dict[str, object]]] = []
    for n in nodes:
        text_full = (str(n.get("text", "")) + " " + str(n.get("desc", ""))).strip().lower()
        rid = str(n.get("rid", "")).lower()
        clazz = str(n.get("clazz", "")).lower()
        raw_text = str(n.get("text", "")).strip()
        center = n.get("center")
        if not isinstance(center, tuple):
            continue

        score = -999
        reason = ""

        if any(term in text_full or term in rid for term in avoid_terms):
            score = -200
            reason = "avoid_branch"
        if any(term in text_full for term in dismiss_terms):
            score = 220
            reason = "dismiss"
        elif is_permission_surface and any(term in text_full for term in permission_allow_substrings):
            score = 230
            reason = "permission_allow"
        elif any(term in text_full for term in generic_allow_terms):
            score = 90
            reason = "allowish"

        if "button" in clazz:
            score += 40
        if bool(n.get("clickable")):
            score += 25
        if len(raw_text) > 80 and "button" not in clazz:
            score -= 70

        candidates.append((score, reason, n))

    candidates.sort(key=lambda x: x[0], reverse=True)
    if not candidates or candidates[0][0] < 60:
        return None, "no_confident_target"
    top_score, top_reason, top_node = candidates[0]
    c = top_node.get("center")
    if isinstance(c, tuple):
        return (int(c[0]), int(c[1])), top_reason
    return None, "no_confident_target"


def _resolve_setup_dialogs(
    adb_bin: str,
    max_rounds: int = 5,
    *,
    deadline_monotonic: float | None = None,
) -> dict[str, object]:
    """Pre-warmup dialog resolution: scored taps + transition guard (BACK on stuck repeat)."""
    dump_path = "/sdcard/contextdroid_perm_dump.xml"
    actions: list[dict[str, object]] = []
    tap_count = 0
    last_compare_hash: Optional[int] = None
    repeat_hash_streak = 0
    prev_target: Optional[tuple[int, int]] = None
    repeated_same_target = 0

    for round_idx in range(1, max_rounds + 1):
        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            actions.append(
                {
                    "round": round_idx,
                    "action": "abort",
                    "reason": "pre_setup_budget",
                    "node_count": 0,
                    "screen_hash": "",
                }
            )
            break
        step_timeout = 12.0
        if deadline_monotonic is not None:
            step_timeout = max(1.0, min(12.0, deadline_monotonic - time.monotonic()))
        run_command([adb_bin, "shell", "uiautomator", "dump", dump_path], check=False, timeout_sec=step_timeout)
        xml_res = run_command([adb_bin, "shell", "cat", dump_path], check=False, timeout_sec=step_timeout)
        xml_text = (xml_res.stdout or "").strip()
        nodes = _parse_uiautomator_nodes(xml_text)
        h_compare, h_stable = _ui_structure_hash(nodes)

        if last_compare_hash is not None and h_compare == last_compare_hash:
            repeat_hash_streak += 1
        else:
            repeat_hash_streak = 0
        last_compare_hash = h_compare

        target, reason = _choose_setup_tap_target(nodes)
        if target is None:
            actions.append(
                {
                    "round": round_idx,
                    "action": "none",
                    "reason": reason,
                    "node_count": len(nodes),
                    "screen_hash": h_stable,
                }
            )
            break

        if prev_target is not None and target == prev_target:
            repeated_same_target += 1
        else:
            repeated_same_target = 0
        prev_target = target

        # Transition guard: same UI + same tap target twice -> BACK once (experiment v3).
        if repeat_hash_streak >= 1 and repeated_same_target >= 1:
            run_command([adb_bin, "shell", "input", "keyevent", "4"], check=False, timeout_sec=8)
            actions.append(
                {
                    "round": round_idx,
                    "action": "back",
                    "reason": "transition_guard_stuck_repeat",
                    "screen_hash": h_stable,
                    "repeat_hash_streak": repeat_hash_streak,
                }
            )
            repeat_hash_streak = 0
            repeated_same_target = 0
            prev_target = None
            time.sleep(0.7)
            continue

        run_command(
            [adb_bin, "shell", "input", "tap", str(target[0]), str(target[1])],
            check=False,
            timeout_sec=8,
        )
        run_command([adb_bin, "shell", "input", "keyevent", "66"], check=False, timeout_sec=5)
        tap_count += 1
        actions.append(
            {
                "round": round_idx,
                "action": "tap",
                "reason": reason,
                "target": list(target),
                "node_count": len(nodes),
                "screen_hash": h_stable,
            }
        )
        time.sleep(0.8)

    return {"tap_count": tap_count, "actions": actions}


def _grant_declared_permissions(adb_bin: str, package_name: str, apk_path: Path) -> dict[str, int]:
    granted = 0
    attempted = 0
    for perm in _extract_declared_permissions(apk_path):
        attempted += 1
        res = run_command([adb_bin, "shell", "pm", "grant", package_name, perm], check=False, timeout_sec=8)
        if res.returncode == 0:
            granted += 1
    return {"attempted": attempted, "granted": granted}


def _run_pre_simulation_setup(adb_bin: str, package_name: str, apk_path: Path, output_dir: Path) -> dict[str, object]:
    started = time.monotonic()
    deadline = started + _PRE_SETUP_MAX_SEC

    def over_budget() -> bool:
        return time.monotonic() >= deadline

    def step_timeout(default: float) -> float:
        return max(1.0, min(default, deadline - time.monotonic()))

    perm_stats = _grant_declared_permissions(adb_bin, package_name, apk_path)
    dialog_before: dict[str, object] = {"tap_count": 0, "actions": []}
    dialog_after: dict[str, object] = {"tap_count": 0, "actions": []}
    monkey_res = subprocess.CompletedProcess(["monkey"], -1, "", "skipped:pre_setup_budget")
    dump_res = subprocess.CompletedProcess(["uiautomator"], -1, "", "skipped:pre_setup_budget")
    pull_res = subprocess.CompletedProcess(["pull"], -1, "", "skipped:pre_setup_budget")

    if not over_budget():
        dialog_before = _resolve_setup_dialogs(adb_bin, max_rounds=5, deadline_monotonic=deadline)
    if over_budget():
        logging.warning(
            "Pre-simulation setup exceeded %.0fs budget; skipping remaining warmup steps.",
            _PRE_SETUP_MAX_SEC,
        )
    else:
        monkey_res = run_command(
            [
                adb_bin,
                "shell",
                "monkey",
                "-p",
                package_name,
                "--throttle",
                "150",
                "-s",
                str(PRE_ONBOARDING_MONKEY_SEED),
                "--pct-syskeys",
                "0",
                "--pct-majornav",
                "0",
                "--pct-appswitch",
                "0",
                "--ignore-security-exceptions",
                "-v",
                str(PRE_ONBOARDING_MONKEY_EVENTS),
            ],
            check=False,
            timeout_sec=step_timeout(20),
        )
    if not over_budget():
        dialog_after = _resolve_setup_dialogs(adb_bin, max_rounds=5, deadline_monotonic=deadline)
    if not over_budget():
        snapshot_device_path = "/sdcard/contextdroid_verified_start.xml"
        dump_res = run_command(
            [adb_bin, "shell", "uiautomator", "dump", snapshot_device_path],
            check=False,
            timeout_sec=step_timeout(15),
        )
        pull_res = run_command(
            [adb_bin, "pull", snapshot_device_path, str(output_dir / f"{package_name}_verified_start.xml")],
            check=False,
            timeout_sec=step_timeout(20),
        )

    wall_sec = time.monotonic() - started
    if wall_sec >= _PRE_SETUP_MAX_SEC:
        logging.warning(
            "Pre-simulation setup used %.1fs (budget %.0fs); remaining steps may have been skipped.",
            wall_sec,
            _PRE_SETUP_MAX_SEC,
        )
    return {
        "permissions_attempted": perm_stats["attempted"],
        "permissions_granted": perm_stats["granted"],
        "warmup_monkey_rc": monkey_res.returncode,
        "dialogs_tapped_before_warmup": dialog_before["tap_count"],
        "dialogs_tapped_after_warmup": dialog_after["tap_count"],
        "dialog_resolution_before_warmup": dialog_before["actions"],
        "dialog_resolution_after_warmup": dialog_after["actions"],
        "verified_start_dump_rc": dump_res.returncode,
        "verified_start_pull_rc": pull_res.returncode,
        "verified_start_path": str(output_dir / f"{package_name}_verified_start.xml"),
        "pre_setup_wall_sec": round(wall_sec, 3),
        "pre_setup_timed_out": wall_sec >= _PRE_SETUP_MAX_SEC,
        "pre_setup_budget_sec": _PRE_SETUP_MAX_SEC,
    }


def analyze_apk(
    apk_path: Path,
    package_name: str,
    duration: int,
    output_dir: Path,
    monkey_seed: Optional[int],
    arm: str,
    session_id: str,
    ollama_model: str,
    ollama_endpoint: str,
    strict_clean_start: bool,
    fairness_protocol: bool,
) -> None:
    _reject_frida_skip_env()
    base_dir = Path(__file__).resolve().parents[1]
    output_dir.mkdir(parents=True, exist_ok=True)
    frida_log_path = output_dir / f"{package_name}_frida.jsonl"
    monkey_log_path = output_dir / f"{package_name}_monkey.log"
    pulled_strace_path = output_dir / f"{package_name}_strace.log"
    device_strace_path = f"/data/local/tmp/strace_{package_name}.log"
    metadata_path = output_dir / f"{package_name}_dynamic_metadata.json"
    hook_script = base_dir / "frida_scripts" / "hook_apis.js"
    frida_bin = resolve_frida_bin()
    adb_bin = resolve_adb_bin()

    frida_proc: Optional[subprocess.Popen] = None
    frida_output_handle = None
    strace_proc: Optional[subprocess.Popen] = None
    monkey_proc: Optional[subprocess.Popen] = None
    started_at = time.time()
    app_pid: Optional[str] = None
    strace_enabled = False
    strace_skip_reason = ""
    analysis_status = "success"
    analysis_exit_code = EXIT_OK
    arm = arm.strip().lower() if arm else DEFAULT_ARM
    if arm not in ("monkey", "llm"):
        arm = DEFAULT_ARM

    app_context = {
        "package_name": package_name,
        "app_name": package_name,
        "category": "Unknown",
        "purpose": "",
        "ux_type": "hybrid",
        "key_user_flows": [],
        "expected_permissions": [],
        "behavioral_notes": "",
        "metadata_source": DEFAULT_METADATA_SOURCE,
        "context_confidence": DEFAULT_CONTEXT_CONFIDENCE,
    }
    llm_session_info = {
        "llm_status": "",
        "llm_infra_status": "",
        "llm_simulation_status": "",
        "llm_simulation_status_detail": "",
        "data_quality_status": "",
        "llm_actions_count": 0,
        "llm_action_log_path": "",
        "llm_step_trace_path": "",
        "llm_audit_log_path": "",
        "llm_ux_goals": [],
        "llm_ux_plan_path": "",
        "llm_navigation_artifact_path": "",
        "llm_primary_ux_fallback_spec": "",
        "llm_primary_ux_fallback_reason": "",
        "llm_root_handoff": {},
        "human_ux_report_path": "",
        "human_ux_overall_pass": False,
        "human_ux_behavior_pass": False,
        "human_ux_mechanistic_pass": False,
        "human_ux_session_pass": False,
        "human_ux_pragmatic_recovery": False,
        "human_ux_criteria_version": "",
        "planner_model": "",
        "webview_dominant": False,
    }
    context_audit: dict[str, object] = {}
    pre_setup: dict[str, object] = {}
    snapshot_restored = False
    pm_clear_rc = -1
    frida_server_ready = False
    frida_server_state = "unknown"
    frida_server_owner = ""
    frida_reattach_attempts = 0
    frida_reattach_successes = 0
    frida_last_healthy_check = 0.0
    frida_health_log_offset = 0
    frida_health_last_event_at = 0.0
    frida_health_last_meaningful_event_at = 0.0
    frida_health_last_activity_at = 0.0
    frida_attach_grace_until = 0.0
    frida_health_saw_meaningful_events = False
    frida_hook_confirmed = False

    try:
        reset_guard_timing(log_path=str(output_dir / f"{package_name}_guard_timing.jsonl"))
        if arm == "llm":
            _ensure_ollama_server(ollama_endpoint)
        if arm == "llm" or fairness_protocol:
            snapshot_restored = _restore_snapshot(adb_bin)
            if strict_clean_start and not snapshot_restored:
                raise AnalysisFailure("failed_snapshot_restore", EXIT_SNAPSHOT_FAILED)
            # Snapshot load resets device processes; always restart frida-server as root afterward.
            frida_server_ready, frida_server_state = ensure_frida_server_running(
                adb_bin, force_restart=snapshot_restored
            )
            frida_server_owner = _frida_server_owner(adb_bin)
            if not frida_server_ready:
                logging.warning("frida-server unavailable after snapshot restore (state=%s)", frida_server_state)
        if arm == "llm" and os.environ.get("CONTEXTDROID_ISOLATE_EMULATOR", "1").strip().lower() not in (
            "0",
            "false",
            "no",
        ):
            isolate_emulator_state(adb_bin, package_name)
        assert_device_identity_hard(
            adb_bin,
            expected_avd_name=os.environ.get("AVD_NAME", ""),
            expected_serial=os.environ.get("ANDROID_SERIAL", ""),
            expected_fingerprint=os.environ.get("CONTEXTDROID_EXPECTED_FINGERPRINT", ""),
            allow_no_device=False,
        )
        install = run_command([adb_bin, "install", "-r", str(apk_path)], check=False, timeout_sec=45)
        if install.returncode != 0:
            err = (install.stderr or install.stdout or "").strip()
            logging.error("APK install failed. adb output: %s", err if err else "<no output>")
            raise AnalysisFailure("failed_install", EXIT_INSTALL_FAILED)
        clear_res = run_command([adb_bin, "shell", "pm", "clear", package_name], check=False, timeout_sec=20)
        pm_clear_rc = clear_res.returncode
        if strict_clean_start and pm_clear_rc != 0:
            raise AnalysisFailure("failed_pm_clear", EXIT_PM_CLEAR_FAILED)

        with monkey_log_path.open("w", encoding="utf-8") as monkey_out:
            app_pid = ensure_app_running(adb_bin, package_name, attempts=2, min_stable_sec=10)
            if app_pid is None:
                logging.error("App failed stability requirement.")
                raise AnalysisFailure("failed_app_unstable", EXIT_APP_UNSTABLE)

            if arm == "llm":
                app_context, context_audit = build_app_context(package_name, apk_path)
                pre_setup = _run_pre_simulation_setup(adb_bin, package_name, apk_path, output_dir)
            elif arm == "monkey" and fairness_protocol:
                pre_setup = _run_pre_simulation_setup(adb_bin, package_name, apk_path, output_dir)

            if arm == "llm" or (arm == "monkey" and fairness_protocol):
                # Dialog automation + warmup monkey can background the app while the process
                # stays alive; LLM/UIAutomator then see the launcher. Re-launch before Frida.
                force_launch_activity(package_name)
                time.sleep(1.5)

            frida_proc, frida_output_handle, frida_server_state, app_pid = attach_frida_or_fail(
                adb_bin,
                base_dir,
                frida_bin,
                hook_script,
                package_name,
                frida_log_path,
                force_frida_restart=snapshot_restored,
            )
            frida_server_ready = True
            frida_server_owner = _frida_server_owner(adb_bin)
            frida_health_log_offset = _frida_log_byte_offset(frida_log_path)
            attach_now = time.time()
            frida_health_last_event_at = attach_now
            frida_health_last_meaningful_event_at = attach_now
            frida_health_last_activity_at = attach_now
            frida_attach_grace_until = attach_now + _frida_attach_grace_sec()
            frida_health_saw_meaningful_events = False
            frida_hook_confirmed = True

            def _bind_strace_to_pid(pid: str) -> None:
                nonlocal strace_proc, strace_enabled, strace_skip_reason
                safe_terminate(strace_proc, "strace")
                strace_proc = None
                if not pid:
                    strace_skip_reason = "pid_not_found"
                    strace_enabled = False
                    return
                strace_proc = subprocess.Popen(
                    [
                        adb_bin,
                        "shell",
                        "strace",
                        "-p",
                        pid,
                        "-e",
                        "trace=network,file,process",
                        "-f",
                        "-ttt",
                        "-o",
                        device_strace_path,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                strace_enabled = True
                strace_skip_reason = ""

            app_pid = retry_get_pid(package_name, retries=6, delay_sec=0.8)
            if app_pid is None:
                strace_skip_reason = "pid_not_found"
            else:
                _bind_strace_to_pid(app_pid)

            def _frida_mark_healthy_after_reattach() -> None:
                nonlocal frida_health_log_offset, frida_health_last_event_at
                nonlocal frida_health_last_meaningful_event_at, frida_health_last_activity_at
                nonlocal frida_attach_grace_until, frida_health_saw_meaningful_events, frida_hook_confirmed
                frida_health_log_offset = _frida_log_byte_offset(frida_log_path)
                now = time.time()
                frida_health_last_event_at = now
                frida_health_last_meaningful_event_at = now
                frida_health_last_activity_at = now
                frida_attach_grace_until = now + _frida_attach_grace_sec()
                frida_health_saw_meaningful_events = False
                frida_hook_confirmed = True

            def _frida_perform_reattach() -> None:
                nonlocal frida_proc, frida_output_handle, frida_server_state, app_pid
                nonlocal frida_reattach_attempts, frida_reattach_successes
                frida_reattach_attempts += 1
                strategies: tuple[tuple[str, bool, bool, bool, bool, bool], ...] = (
                    # label, force_restart, relaunch, prefer_name, cold, spawn
                    ("soft_pid", False, False, False, False, False),
                    ("soft_name", False, False, True, False, False),
                    ("spawn", False, False, True, False, True),
                    ("cold_name", False, False, True, True, False),
                    ("hard_cold_name", True, False, True, True, False),
                )
                last_error = "no reattach strategy attempted"
                for label, force_restart, relaunch, prefer_name, cold, spawn in strategies:
                    logging.warning(
                        "Frida reattach %s strategy=%s (force_restart=%s relaunch=%s prefer_name=%s cold=%s spawn=%s).",
                        frida_reattach_attempts,
                        label,
                        force_restart,
                        relaunch,
                        prefer_name,
                        cold,
                        spawn,
                    )
                    safe_terminate(frida_proc, "frida")
                    if frida_output_handle is not None:
                        try:
                            frida_output_handle.close()
                        except Exception:
                            pass
                    try:
                        frida_proc, frida_output_handle, frida_server_state, app_pid = attach_frida_or_fail(
                            adb_bin,
                            base_dir,
                            frida_bin,
                            hook_script,
                            package_name,
                            frida_log_path,
                            attach_attempts=2,
                            force_frida_restart=force_restart,
                            append_log=True,
                            relaunch_before_attach=relaunch,
                            cold_relaunch_before_attach=cold,
                            prefer_attach_by_name=prefer_name,
                            spawn_attach=spawn,
                        )
                    except AnalysisFailure as exc:
                        last_error = str(exc.reason)
                        logging.warning("Frida reattach strategy %s failed: %s", label, exc.reason)
                        continue
                    live_pid = retry_get_pid(package_name, retries=3, delay_sec=0.5)
                    if not live_pid or not _is_pid_alive(adb_bin, live_pid):
                        last_error = f"pid_not_alive_after_{label}"
                        logging.error(
                            "Frida reattach strategy %s attached but target pid is not alive (attached=%s live=%s).",
                            label,
                            app_pid,
                            live_pid or "<none>",
                        )
                        safe_terminate(frida_proc, "frida")
                        continue
                    if live_pid != app_pid:
                        app_pid = live_pid
                    if frida_proc.poll() is not None:
                        last_error = f"frida_cli_exited_after_{label}"
                        logging.error(
                            "Frida reattach strategy %s exited immediately (code=%s).",
                            label,
                            frida_proc.returncode,
                        )
                        continue
                    frida_reattach_successes += 1
                    _frida_mark_healthy_after_reattach()
                    _bind_strace_to_pid(live_pid)
                    logging.info("Frida reattach succeeded via strategy %s (pid=%s).", label, live_pid)
                    return
                raise AnalysisFailure("failed_frida_reattach", EXIT_FRIDA_ATTACH_FAILED)

            def _frida_healthcheck_and_reattach() -> None:
                nonlocal frida_health_log_offset, frida_health_last_event_at
                nonlocal frida_health_last_meaningful_event_at, frida_health_last_activity_at
                nonlocal frida_health_saw_meaningful_events, frida_reattach_attempts, frida_reattach_successes
                nonlocal frida_last_healthy_check
                if frida_proc is None:
                    return
                now = time.time()
                if now - frida_last_healthy_check < _frida_healthcheck_interval_sec():
                    return
                frida_last_healthy_check = now

                log_end = _frida_log_byte_offset(frida_log_path)
                chunk = _frida_log_slice(frida_log_path, frida_health_log_offset)
                frida_health_log_offset = log_end
                if chunk.strip():
                    frida_health_last_activity_at = now
                new_events = _frida_count_events_in_text(chunk)
                meaningful_new = _frida_count_meaningful_events_in_text(chunk)
                if new_events > 0:
                    frida_health_last_event_at = now
                if meaningful_new > 0:
                    frida_health_last_meaningful_event_at = now
                    frida_health_saw_meaningful_events = True

                proc_dead = frida_proc.poll() is not None
                failure = _frida_liveness_failure_reason(
                    proc_dead=proc_dead,
                    chunk=chunk,
                    hook_confirmed=frida_hook_confirmed,
                    now=now,
                    grace_until=frida_attach_grace_until,
                    last_activity_at=frida_health_last_activity_at,
                    saw_meaningful_events=frida_health_saw_meaningful_events,
                    last_meaningful_event_at=frida_health_last_meaningful_event_at,
                    post_hook_silence_sec=_frida_post_hook_silence_sec(),
                    stale_sec=_frida_events_stale_sec(),
                )
                if failure is None:
                    return

                logging.warning(
                    "Frida liveness check failed (%s, proc_dead=%s, hook_confirmed=%s, "
                    "last_activity_age=%.1fs, last_meaningful_age=%.1fs).",
                    failure,
                    proc_dead,
                    frida_hook_confirmed,
                    now - frida_health_last_activity_at,
                    now - frida_health_last_meaningful_event_at,
                )
                _frida_perform_reattach()

            if arm == "llm":
                if strict_foreground_enabled():
                    fg_ok, fg_pkg = check_target_foreground(adb_bin, package_name)
                    if not fg_ok:
                        logging.error(
                            "Target %s not in foreground before LLM session (fg=%s).",
                            package_name,
                            fg_pkg or "<unknown>",
                        )
                        raise AnalysisFailure("failed_foreground_mismatch", EXIT_FOREGROUND_MISMATCH)
                _frida_healthcheck_and_reattach()
                start_device_count_watchdog(
                    adb_bin,
                    expected_serial=os.environ.get("ANDROID_SERIAL", ""),
                )
                try:
                    raise_if_watchdog_failed()
                    llm_session_info = run_llm_agent_session(
                        adb_bin=adb_bin,
                        app_context=app_context,
                        output_dir=output_dir,
                        duration_sec=duration,
                        ollama_model=ollama_model,
                        ollama_endpoint=ollama_endpoint,
                        timeout_sec=duration * SESSION_TIMEOUT_MULTIPLIER,
                        healthcheck_cb=_frida_healthcheck_and_reattach,
                    )
                    raise_if_watchdog_failed()
                finally:
                    stop_device_count_watchdog()
            else:
                monkey_cmd = [adb_bin, "shell", "monkey", "-p", package_name, "--throttle", "200"]
                if fairness_protocol:
                    monkey_cmd.extend(
                        [
                            "--pct-syskeys",
                            "0",
                            "--pct-majornav",
                            "0",
                            "--pct-appswitch",
                            "0",
                            "--ignore-security-exceptions",
                        ]
                    )
                monkey_cmd.append("-v")
                if monkey_seed is not None:
                    monkey_cmd.extend(["-s", str(monkey_seed)])
                if fairness_protocol:
                    monkey_events = max(1, duration * 5)
                    monkey_cmd.append(str(monkey_events))
                else:
                    run_deterministic_stimulus(adb_bin, package_name)
                    monkey_cmd.append("1000")
                # Mid-run device-count watchdog (same as LLM arm) — fail closed on
                # second adb device / disconnect during monkey canary/malware runs.
                start_device_count_watchdog(
                    adb_bin,
                    expected_serial=os.environ.get("ANDROID_SERIAL", ""),
                )
                try:
                    monkey_proc = subprocess.Popen(
                        monkey_cmd,
                        stdout=monkey_out,
                        stderr=subprocess.STDOUT,
                        text=True,
                    )
                    for _ in range(duration):
                        raise_if_watchdog_failed()
                        time.sleep(1)
                    raise_if_watchdog_failed()
                finally:
                    stop_device_count_watchdog()

            if llm_session_info.get("llm_status", "").startswith("partial:"):
                analysis_status = str(llm_session_info["llm_status"])
            elif llm_session_info.get("llm_status", "").startswith("skip:"):
                analysis_status = str(llm_session_info["llm_status"])
            if llm_session_info.get("webview_dominant", False) and analysis_status == "success":
                analysis_status = "flag:webview_dominant"

    except AnalysisFailure as exc:
        analysis_status = exc.reason
        analysis_exit_code = exc.exit_code
        logging.error("Analysis failure: %s", exc.reason)
    except DeviceGuardError as exc:
        analysis_status = "failed_device_guard"
        analysis_exit_code = EXIT_DEVICE_GUARD
        logging.error("Device guard failure: %s", exc)
    except Exception as exc:
        analysis_status = "failed_unexpected"
        analysis_exit_code = EXIT_UNEXPECTED
        logging.exception("Analysis error: %s", exc)
    finally:
        stop_device_count_watchdog()
        if arm == "llm":
            _backfill_llm_session_info_from_disk(output_dir, package_name, llm_session_info)
        safe_terminate(monkey_proc, "monkey")
        safe_terminate(strace_proc, "strace")
        safe_terminate(frida_proc, "frida")
        if frida_output_handle is not None:
            frida_output_handle.close()

        run_command([adb_bin, "pull", device_strace_path, str(pulled_strace_path)], check=False)
        run_command([adb_bin, "uninstall", package_name], check=False)

        frida_lines = 0
        frida_event_count = 0
        frida_meaningful_event_count = 0
        if frida_log_path.exists():
            frida_text = frida_log_path.read_text(encoding="utf-8", errors="ignore")
            frida_lines = sum(1 for _ in frida_text.splitlines())
            frida_event_count = _frida_count_events_in_text(frida_text)
            frida_meaningful_event_count = _frida_count_meaningful_events_in_text(frida_text)
        strace_size = pulled_strace_path.stat().st_size if pulled_strace_path.exists() else 0
        elapsed = time.time() - started_at
        guard_timing = get_guard_timing_snapshot()
        session_wall_ms = round(elapsed * 1000.0, 3)
        guard_total_ms = float(guard_timing.get("guard_total_ms", 0.0))
        guard_overhead_ratio = (
            round(guard_total_ms / session_wall_ms, 6) if session_wall_ms > 0 else 0.0
        )

        metadata = {
            "package_name": package_name,
            "apk_path": str(apk_path),
            "apk_sha256": file_sha256(apk_path),
            "duration_sec": duration,
            "started_at_epoch_ms": int(started_at * 1000),
            "elapsed_sec": round(elapsed, 3),
            "session_wall_ms": session_wall_ms,
            "guard_total_ms": guard_total_ms,
            "guard_call_count": int(guard_timing.get("guard_call_count", 0)),
            "guard_max_call_ms": float(guard_timing.get("guard_max_call_ms", 0.0)),
            "guard_overhead_ratio": guard_overhead_ratio,
            "guard_watchdog_poll_count": int(guard_timing.get("watchdog_poll_count", 0)),
            "guard_slow_adb_call_count": int(guard_timing.get("slow_adb_call_count", 0)),
            "guard_watchdog_slow_adb_correlated": list(
                guard_timing.get("watchdog_slow_adb_correlated") or []
            ),
            "guard_timing": guard_timing,
            "frida_mode": "docker" if should_use_docker_frida() else "host",
            "hook_script_path": str(hook_script),
            "hook_script_sha256": file_sha256(hook_script),
            "hook_version": _hook_script_version(hook_script),
            "agent_seed": int(os.environ["CONTEXTDROID_LLM_AGENT_SEED"])
            if os.environ.get("CONTEXTDROID_LLM_AGENT_SEED", "").strip().isdigit()
            else None,
            "session_mode": os.environ.get("CONTEXTDROID_SESSION_MODE") or "",
            "collection_config": os.environ.get("CONTEXTDROID_COLLECTION_CONFIG") or "",
            "explore_until_sec_floor": os.environ.get("CONTEXTDROID_LLM_EXPLORE_UNTIL_SEC_FLOOR") or "",
            "llm_explore_ratio": os.environ.get("CONTEXTDROID_LLM_EXPLORE_RATIO") or "",
            "app_pid": app_pid,
            "strace_enabled": strace_enabled,
            "strace_skip_reason": strace_skip_reason,
            "frida_log_path": str(frida_log_path),
            "frida_lines": frida_lines,
            "frida_event_count": frida_event_count,
            "frida_meaningful_event_count": frida_meaningful_event_count,
            "strace_log_path": str(pulled_strace_path),
            "strace_size_bytes": strace_size,
            "analysis_status": analysis_status,
            "analysis_exit_code": analysis_exit_code,
            "monkey_seed": monkey_seed,
            "arm": arm,
            "session_id": session_id,
            "metadata_source": app_context.get("metadata_source", DEFAULT_METADATA_SOURCE),
            "context_confidence": app_context.get("context_confidence", DEFAULT_CONTEXT_CONFIDENCE),
            "planner_model": llm_session_info.get("planner_model", ""),
            "llm_status": llm_session_info.get("llm_status", ""),
            "llm_infra_status": llm_session_info.get("llm_infra_status", ""),
            "llm_simulation_status": llm_session_info.get("llm_simulation_status", ""),
            "llm_simulation_status_detail": llm_session_info.get("llm_simulation_status_detail", ""),
            "data_quality_status": llm_session_info.get("data_quality_status", ""),
            "llm_actions_count": llm_session_info.get("llm_actions_count", 0),
            "llm_action_log_path": llm_session_info.get("llm_action_log_path", ""),
            "llm_step_trace_path": llm_session_info.get("llm_step_trace_path", ""),
            "llm_audit_log_path": llm_session_info.get("llm_audit_log_path", ""),
            "llm_ux_goals": llm_session_info.get("llm_ux_goals", []),
            "llm_ux_plan_path": llm_session_info.get("llm_ux_plan_path", ""),
            "llm_navigation_artifact_path": llm_session_info.get("llm_navigation_artifact_path", ""),
            "llm_primary_ux_fallback_spec": llm_session_info.get("llm_primary_ux_fallback_spec", ""),
            "llm_primary_ux_fallback_reason": llm_session_info.get("llm_primary_ux_fallback_reason", ""),
            "llm_root_handoff": llm_session_info.get("llm_root_handoff", {}),
            "human_ux_report_path": llm_session_info.get("human_ux_report_path", ""),
            "human_ux_overall_pass": llm_session_info.get("human_ux_overall_pass", False),
            "human_ux_behavior_pass": llm_session_info.get("human_ux_behavior_pass", False),
            "human_ux_mechanistic_pass": llm_session_info.get("human_ux_mechanistic_pass", False),
            "human_ux_session_pass": llm_session_info.get("human_ux_session_pass", False),
            "human_ux_pragmatic_recovery": llm_session_info.get("human_ux_pragmatic_recovery", False),
            "human_ux_criteria_version": llm_session_info.get("human_ux_criteria_version", ""),
            "webview_dominant": llm_session_info.get("webview_dominant", False),
            "app_context": app_context,
            "context_audit": context_audit,
            "pre_setup": pre_setup,
            "snapshot_restored": snapshot_restored,
            "pm_clear_rc": pm_clear_rc,
            "fairness_protocol": fairness_protocol,
            "frida_server_ready": frida_server_ready,
            "frida_server_state": frida_server_state,
            "frida_server_owner": frida_server_owner,
            "frida_reattach_attempts": frida_reattach_attempts,
            "frida_reattach_successes": frida_reattach_successes,
        }
        metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
    if analysis_exit_code != EXIT_OK:
        raise SystemExit(analysis_exit_code)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run dynamic analysis for one APK.")
    parser.add_argument("--apk", required=True, help="Path to APK")
    parser.add_argument("--pkg", required=True, help="Package name")
    parser.add_argument("--duration", type=int, default=180, help="Duration in seconds")
    parser.add_argument("--output-dir", default="./logs", help="Output directory")
    parser.add_argument(
        "--monkey-seed",
        type=int,
        default=None,
        help="Optional fixed monkey seed for deterministic replay",
    )
    parser.add_argument("--arm", default="monkey", help="Execution arm: monkey or llm")
    parser.add_argument("--session-id", default="", help="Session identifier")
    parser.add_argument("--ollama-model", default=os.environ.get("OLLAMA_MODEL", "llama3.2"), help="Ollama model")
    parser.add_argument(
        "--ollama-endpoint",
        default=os.environ.get("OLLAMA_ENDPOINT", "http://127.0.0.1:11434"),
        help="Ollama endpoint URL",
    )
    parser.add_argument("--strict-clean-start", action="store_true", help="Fail if snapshot/pm clear preconditions fail")
    parser.add_argument("--fairness-protocol", action="store_true", help="Apply shared fairness setup for both arms")
    return parser.parse_args()


def main() -> None:
    configure_logging()
    args = parse_args()
    env_seed = os.environ.get("MONKEY_SEED", "").strip()
    monkey_seed = args.monkey_seed if args.monkey_seed is not None else (int(env_seed) if env_seed else None)
    session_id = args.session_id.strip() or uuid.uuid4().hex[:12]
    analyze_apk(
        Path(args.apk).resolve(),
        args.pkg,
        args.duration,
        Path(args.output_dir).resolve(),
        monkey_seed,
        args.arm,
        session_id,
        args.ollama_model,
        args.ollama_endpoint,
        args.strict_clean_start,
        args.fairness_protocol,
    )


if __name__ == "__main__":
    main()
