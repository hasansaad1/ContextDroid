from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import IO, Any, Optional

from .actions import _execute_action
from .dialogs import _hierarchy_shows_permission_dialog, _package_is_permission_dialog_surface, _pick_system_dialog_dismiss_action
from .screen import dump_clean_screen
from .config import (
    _BROWSER_PACKAGES,
    _FOREGROUND_DIALOG_PACKAGES,
    _FOREGROUND_DUMPSYS_TIMEOUT_SEC,
    _FOREGROUND_TRANSIENT_PACKAGES,
    _LAUNCHER_PACKAGES,
    _ROOT_HANDOFF_FORCE_STOP,
    _SETTINGS_PACKAGES,
    _STICKY_FOREGROUND_STRICT,
    _TREAT_DIALOG_PACKAGES_AS_FOREIGN,
)

def _foreground_package(adb_bin: str) -> Optional[str]:
    """Best-effort foreground package; never raises on adb/dumpsys timeout."""
    probes: list[list[str]] = [
        [adb_bin, "shell", "dumpsys", "window"],
        [adb_bin, "shell", "dumpsys", "activity", "activities"],
    ]
    for args in probes:
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=_FOREGROUND_DUMPSYS_TIMEOUT_SEC,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logging.warning(
                "Foreground probe timed out after %.0fs (%s); continuing session.",
                _FOREGROUND_DUMPSYS_TIMEOUT_SEC,
                args[-1] if args else "dumpsys",
            )
            continue
        except OSError as exc:
            logging.warning("Foreground probe failed (%s): %s", " ".join(args[-2:]), exc)
            continue
        text = result.stdout or ""
        for line in text.splitlines():
            if "mCurrentFocus" in line or "mFocusedApp" in line:
                m = re.search(r"(?:u0|u\d+)\s+([a-zA-Z0-9_.]+)/", line)
                if m:
                    return m.group(1)
            if "topResumedActivity" in line:
                m = re.search(r"ActivityRecord\{[^ ]+\s+u0\s+([a-zA-Z0-9_.]+)/", line)
                if m:
                    return m.group(1)
            if "mResumedActivity" in line:
                m = re.search(r"u0\s+([a-zA-Z0-9_.]+)/", line)
                if m:
                    return m.group(1)
    return None

def _foreground_acceptable(package_name: str, fg: Optional[str]) -> bool:
    if fg is None:
        return True
    if fg == package_name:
        return True
    if fg in _FOREGROUND_DIALOG_PACKAGES and not _TREAT_DIALOG_PACKAGES_AS_FOREIGN:
        return True
    if fg in _FOREGROUND_TRANSIENT_PACKAGES:
        return True
    return False

def _should_recover_from_foreign_app(package_name: str, fg: Optional[str]) -> bool:
    """When sticky foreground triggers, only reset task from obvious exit surfaces."""
    if fg is None:
        return False
    if _foreground_acceptable(package_name, fg):
        return False
    if fg in _BROWSER_PACKAGES:
        return True
    if fg in _LAUNCHER_PACKAGES:
        return True
    if fg in _SETTINGS_PACKAGES:
        return True
    low = fg.lower()
    if low.endswith(".settings") or ".settings." in low:
        return True
    if low.endswith(".launcher") or ".launcher." in low:
        return True
    if "securitycenter" in low and ("miui" in low or "coloros" in low or "oplus" in low):
        return True
    return False

def _hierarchy_dominant_foreign_package(raw_xml: str, target_pkg: str) -> Optional[str]:
    """When dumpsys lags, resource-id prefixes in the accessibility dump still reveal system Settings, etc."""
    if not (raw_xml or "").strip():
        return None
    counts: dict[str, int] = {}
    for m in re.finditer(r'resource-id="([^"]+)"', raw_xml):
        rid = m.group(1).strip()
        if ":id/" not in rid:
            continue
        pref = rid.split(":id/", 1)[0]
        if pref in ("", "android"):
            continue
        counts[pref] = counts.get(pref, 0) + 1
    if not counts:
        return None
    target_hits = counts.get(target_pkg, 0)
    best_foreign: tuple[str, int] | None = None
    for pref, n in counts.items():
        if pref == target_pkg:
            continue
        if best_foreign is None or n > best_foreign[1]:
            best_foreign = (pref, n)
    if best_foreign is None:
        return None
    f_pkg, f_cnt = best_foreign
    min_hits = 4 if target_hits == 0 else 6
    if f_cnt < min_hits:
        return None
    if target_hits >= 3 and f_cnt < target_hits + 3:
        return None
    return f_pkg

def _resolve_main_activity(adb_bin: str, package_name: str) -> Optional[str]:
    result = subprocess.run(
        [adb_bin, "shell", "cmd", "package", "resolve-activity", "--brief", package_name],
        capture_output=True,
        text=True,
        timeout=18,
        check=False,
    )
    lines = [ln.strip() for ln in (result.stdout or "").splitlines() if ln.strip()]
    for line in reversed(lines):
        if "/" in line and not line.startswith("priority="):
            return line
    return None

def _bring_target_foreground(adb_bin: str, package_name: str) -> None:
    subprocess.run(
        [adb_bin, "shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
        check=False,
        capture_output=True,
        timeout=35,
    )
    comp = _resolve_main_activity(adb_bin, package_name)
    if comp:
        subprocess.run(
            [adb_bin, "shell", "am", "start", "-n", comp],
            check=False,
            capture_output=True,
            timeout=35,
        )
    time.sleep(1.3)

def _start_target_root_activity(adb_bin: str, package_name: str, *, clear_task: bool = False) -> None:
    comp = _resolve_main_activity(adb_bin, package_name)
    if not comp:
        _bring_target_foreground(adb_bin, package_name)
        return
    cmd = [
        adb_bin,
        "shell",
        "am",
        "start",
        "--activity-clear-top",
        "--activity-reset-task-if-needed",
        "-a",
        "android.intent.action.MAIN",
        "-c",
        "android.intent.category.LAUNCHER",
        "-n",
        comp,
    ]
    if clear_task:
        cmd.insert(4, "--activity-new-task")
        cmd.insert(5, "--activity-clear-task")
    subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        timeout=35,
    )
    time.sleep(1.2)

def _restart_target_root(adb_bin: str, package_name: str) -> None:
    """Return to the target's launcher/root activity without default process kill.

    Force-stop is opt-in because this function runs after Frida/strace attachment;
    killing the process here would break instrumentation unless the caller reattaches.
    """
    if _ROOT_HANDOFF_FORCE_STOP:
        subprocess.run(
            [adb_bin, "shell", "am", "force-stop", package_name],
            check=False,
            capture_output=True,
            timeout=12,
        )
        time.sleep(0.6)
    _start_target_root_activity(adb_bin, package_name, clear_task=False)

def _try_dismiss_permission_overlay(adb_bin: str, package_name: str) -> bool:
    """Tap Allow/Deny on a runtime permission sheet instead of force-relaunching the app."""
    elements, _, _ = dump_clean_screen(adb_bin)
    if not _hierarchy_shows_permission_dialog(elements, package_name):
        return False
    dismiss = _pick_system_dialog_dismiss_action(elements, package_name)
    if dismiss is None:
        return False
    ok, outcome = _execute_action(adb_bin, dismiss, elements)
    if ok:
        logging.info("Dismissed permission overlay (%s).", outcome)
        time.sleep(0.5)
        return True
    return False

def _recover_foreground_if_needed(adb_bin: str, package_name: str) -> bool:
    fg = _foreground_package(adb_bin)
    if _foreground_acceptable(package_name, fg):
        return False
    if fg and _package_is_permission_dialog_surface(fg):
        if _try_dismiss_permission_overlay(adb_bin, package_name):
            return _foreground_acceptable(package_name, _foreground_package(adb_bin))
    if _STICKY_FOREGROUND_STRICT and not _should_recover_from_foreign_app(package_name, fg):
        logging.info(
            "Sticky foreground: fg=%s differs from target but not launcher/browser — skipping recover.",
            fg,
        )
        return False
    logging.warning("Foreground package %s left target %s; re-launching task.", fg, package_name)
    _bring_target_foreground(adb_bin, package_name)
    return True
