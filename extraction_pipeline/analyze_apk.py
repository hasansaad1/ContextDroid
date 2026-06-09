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
from protocol_config import (
    DEFAULT_ARM,
    DEFAULT_CONTEXT_CONFIDENCE,
    DEFAULT_METADATA_SOURCE,
    PRE_ONBOARDING_MONKEY_EVENTS,
    PRE_ONBOARDING_MONKEY_SEED,
    SESSION_TIMEOUT_MULTIPLIER,
)

DOCKER_FRIDA_IMAGE = os.environ.get("FRIDA_DOCKER_IMAGE", "frida-tools-local:14.8.1")

EXIT_OK = 0
EXIT_INSTALL_FAILED = 10
EXIT_APP_UNSTABLE = 11
EXIT_FRIDA_ATTACH_FAILED = 12
EXIT_UNEXPECTED = 13
EXIT_SNAPSHOT_FAILED = 14
EXIT_PM_CLEAR_FAILED = 15
EXIT_OLLAMA_STARTUP_FAILED = 16


class AnalysisFailure(RuntimeError):
    def __init__(self, reason: str, exit_code: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.exit_code = exit_code


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
    try:
        return subprocess.run(cmd, check=check, text=text, capture_output=text, timeout=timeout_sec)
    except subprocess.TimeoutExpired as exc:
        logging.error("Command timed out after %.1fs: %s", timeout_sec or 0.0, " ".join(cmd))
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        if not stderr:
            stderr = f"timeout after {timeout_sec}s"
        return subprocess.CompletedProcess(cmd, 124, stdout=stdout, stderr=stderr)


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
    env_adb = os.environ.get("ADB_BIN", "").strip()
    if env_adb:
        return env_adb
    repo_root = Path(__file__).resolve().parents[1]
    repo_adb = repo_root / "tools" / "platform-tools" / "adb"
    if repo_adb.exists():
        return str(repo_adb)
    discovered = shutil.which("adb")
    if discovered:
        return discovered
    fallback = Path.home() / "Library" / "Android" / "sdk" / "platform-tools" / "adb"
    return str(fallback) if fallback.exists() else "adb"


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
    dockerfile = "FROM python:3.11-slim\nRUN pip install -q frida-tools==14.8.1\n"
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


def wait_for_frida_attach(frida_proc: subprocess.Popen, frida_log_path: Path, timeout_sec: int = 10) -> bool:
    start = time.time()
    while time.time() - start < timeout_sec:
        if frida_proc.poll() is not None:
            logging.error(
                "Frida process exited early (code=%s). Log tail:\n%s",
                frida_proc.returncode,
                _frida_log_tail(frida_log_path),
            )
            return False
        if frida_log_path.exists() and "hook_loaded" in frida_log_path.read_text(encoding="utf-8", errors="ignore"):
            return True
        time.sleep(0.5)
    logging.error(
        "Frida attach timed out after %ss (no hook_loaded). Log tail:\n%s",
        timeout_sec,
        _frida_log_tail(frida_log_path),
    )
    return False


def attach_frida_or_fail(
    adb_bin: str,
    base_dir: Path,
    frida_bin: str,
    hook_script: Path,
    app_pid: str,
    frida_log_path: Path,
    *,
    attach_timeout_sec: int = 10,
) -> tuple[subprocess.Popen, object, str]:
    """Start frida-server if needed, attach hooks, and fail before simulation if attach does not succeed."""
    frida_server_ready, frida_server_state = ensure_frida_server_running(adb_bin)
    if not frida_server_ready:
        logging.error("frida-server not available on device (state=%s)", frida_server_state)
        raise AnalysisFailure("failed_frida_server", EXIT_FRIDA_ATTACH_FAILED)

    frida_proc, frida_output_handle = start_frida(base_dir, frida_bin, hook_script, app_pid, frida_log_path)
    if not wait_for_frida_attach(frida_proc, frida_log_path, timeout_sec=attach_timeout_sec):
        safe_terminate(frida_proc, "frida")
        raise AnalysisFailure("failed_frida_attach", EXIT_FRIDA_ATTACH_FAILED)

    logging.info("Frida attached (frida-server state=%s, pid=%s)", frida_server_state, app_pid)
    return frida_proc, frida_output_handle, frida_server_state


def start_frida(
    base_dir: Path, frida_bin: str, hook_script: Path, app_pid: str, frida_log_path: Path
) -> tuple[subprocess.Popen, object]:
    if should_use_docker_frida():
        run_command([resolve_adb_bin(), "forward", "tcp:27042", "tcp:27042"], check=False)
        image = ensure_docker_frida_image()
        hook_rel = hook_script.relative_to(base_dir)
        script = f'frida -H host.docker.internal:27042 -p {app_pid} -l "{hook_rel}"'
        frida_out = frida_log_path.open("w", encoding="utf-8")
        proc = subprocess.Popen(
            ["docker", "run", "--rm", "-v", f"{base_dir}:/project", "-w", "/project", image, "sh", "-lc", script],
            stdout=frida_out,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            text=True,
        )
        return proc, frida_out
    frida_out = frida_log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [frida_bin, "-U", "-l", str(hook_script), "-p", app_pid],
        stdout=frida_out,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
        text=True,
    )
    return proc, frida_out


def file_sha256(path: Path) -> str:
    if not path.exists():
        return ""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


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


def ensure_frida_server_running(adb_bin: str) -> tuple[bool, str]:
    check = run_command([adb_bin, "shell", "pidof", "frida-server"], check=False, timeout_sec=8)
    if (check.stdout or "").strip():
        return True, "already_running"

    exists = run_command([adb_bin, "shell", "test", "-x", "/data/local/tmp/frida-server"], check=False, timeout_sec=8)
    if exists.returncode != 0:
        return False, "frida_server_missing"

    # Start in background and re-check.
    run_command([adb_bin, "shell", "/data/local/tmp/frida-server &"], check=False, timeout_sec=8)
    for _ in range(10):
        time.sleep(0.5)
        check2 = run_command([adb_bin, "shell", "pidof", "frida-server"], check=False, timeout_sec=8)
        if (check2.stdout or "").strip():
            return True, "started"
    return False, "start_failed"


def _restore_snapshot(adb_bin: str) -> bool:
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


def _resolve_setup_dialogs(adb_bin: str, max_rounds: int = 5) -> dict[str, object]:
    """Pre-warmup dialog resolution: scored taps + transition guard (BACK on stuck repeat)."""
    dump_path = "/sdcard/contextdroid_perm_dump.xml"
    actions: list[dict[str, object]] = []
    tap_count = 0
    last_compare_hash: Optional[int] = None
    repeat_hash_streak = 0
    prev_target: Optional[tuple[int, int]] = None
    repeated_same_target = 0

    for round_idx in range(1, max_rounds + 1):
        run_command([adb_bin, "shell", "uiautomator", "dump", dump_path], check=False, timeout_sec=12)
        xml_res = run_command([adb_bin, "shell", "cat", dump_path], check=False, timeout_sec=12)
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
    perm_stats = _grant_declared_permissions(adb_bin, package_name, apk_path)
    # Some OEM/runtime prompts are not resolved by pm grant alone.
    dialog_before = _resolve_setup_dialogs(adb_bin, max_rounds=5)
    # Constrain sys/navigation/app-switch events so warmup rarely leaves the target app
    # (default Monkey mix can inject HOME/BACK; exit code 251 often follows).
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
        timeout_sec=20,
    )
    dialog_after = _resolve_setup_dialogs(adb_bin, max_rounds=5)
    snapshot_device_path = "/sdcard/contextdroid_verified_start.xml"
    dump_res = run_command(
        [adb_bin, "shell", "uiautomator", "dump", snapshot_device_path],
        check=False,
        timeout_sec=15,
    )
    pull_res = run_command(
        [adb_bin, "pull", snapshot_device_path, str(output_dir / f"{package_name}_verified_start.xml")],
        check=False,
        timeout_sec=20,
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

    try:
        if arm == "llm":
            _ensure_ollama_server(ollama_endpoint)
        if arm == "llm" or fairness_protocol:
            snapshot_restored = _restore_snapshot(adb_bin)
            if strict_clean_start and not snapshot_restored:
                raise AnalysisFailure("failed_snapshot_restore", EXIT_SNAPSHOT_FAILED)
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

            # Pre-setup actions (permission dialogs, warmup monkey) can change app PID.
            # Always refresh PID immediately before Frida attach.
            app_pid = retry_get_pid(package_name, retries=6, delay_sec=0.8)
            if app_pid is None:
                app_pid = ensure_app_running(adb_bin, package_name, attempts=1, min_stable_sec=3)
            if app_pid is None:
                raise AnalysisFailure("failed_app_unstable", EXIT_APP_UNSTABLE)

            frida_proc, frida_output_handle, frida_server_state = attach_frida_or_fail(
                adb_bin,
                base_dir,
                frida_bin,
                hook_script,
                app_pid,
                frida_log_path,
            )
            frida_server_ready = True

            app_pid = retry_get_pid(package_name, retries=6, delay_sec=0.8)
            if app_pid is None:
                strace_skip_reason = "pid_not_found"
            else:
                strace_proc = subprocess.Popen(
                    [
                        adb_bin,
                        "shell",
                        "strace",
                        "-p",
                        app_pid,
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

            if arm == "llm":
                llm_session_info = run_llm_agent_session(
                    adb_bin=adb_bin,
                    app_context=app_context,
                    output_dir=output_dir,
                    duration_sec=duration,
                    ollama_model=ollama_model,
                    ollama_endpoint=ollama_endpoint,
                    timeout_sec=duration * SESSION_TIMEOUT_MULTIPLIER,
                )
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
                monkey_proc = subprocess.Popen(
                    monkey_cmd,
                    stdout=monkey_out,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                for _ in range(duration):
                    time.sleep(1)

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
    except Exception as exc:
        analysis_status = "failed_unexpected"
        analysis_exit_code = EXIT_UNEXPECTED
        logging.exception("Analysis error: %s", exc)
    finally:
        safe_terminate(monkey_proc, "monkey")
        safe_terminate(strace_proc, "strace")
        safe_terminate(frida_proc, "frida")
        if frida_output_handle is not None:
            frida_output_handle.close()

        run_command([adb_bin, "pull", device_strace_path, str(pulled_strace_path)], check=False)
        run_command([adb_bin, "uninstall", package_name], check=False)

        frida_lines = 0
        if frida_log_path.exists():
            with frida_log_path.open("r", encoding="utf-8", errors="ignore") as handle:
                frida_lines = sum(1 for _ in handle)
        strace_size = pulled_strace_path.stat().st_size if pulled_strace_path.exists() else 0
        elapsed = time.time() - started_at

        metadata = {
            "package_name": package_name,
            "apk_path": str(apk_path),
            "apk_sha256": file_sha256(apk_path),
            "duration_sec": duration,
            "started_at_epoch_ms": int(started_at * 1000),
            "elapsed_sec": round(elapsed, 3),
            "frida_mode": "docker" if should_use_docker_frida() else "host",
            "hook_script_path": str(hook_script),
            "hook_script_sha256": file_sha256(hook_script),
            "app_pid": app_pid,
            "strace_enabled": strace_enabled,
            "strace_skip_reason": strace_skip_reason,
            "frida_log_path": str(frida_log_path),
            "frida_lines": frida_lines,
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
