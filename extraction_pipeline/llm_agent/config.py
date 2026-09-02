#!/usr/bin/env python3
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

from protocol_config import (
    ACTION_HISTORY_WINDOW,
    LLM_TEMPERATURE,
    MAX_AGENT_XML_TOKENS,
    OLLAMA_DEAD_AFTER_CONSECUTIVE_STEPS,
    OLLAMA_GENERATE_RETRIES,
    OLLAMA_GENERATE_RETRY_BASE_SEC,
    PARTIAL_AGENT_STUCK,
    PARTIAL_OLLAMA_UNAVAILABLE,
    REPETITION_THRESHOLD,
    REPETITION_WINDOW,
    STAGNATION_CONSECUTIVE_FOR_BACK,
    STAGNATION_CONSECUTIVE_FOR_BAILOUT,
    SESSION_TIMEOUT_MULTIPLIER,
)
def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return max(minimum, int(str(raw).strip(), 10))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return float(str(raw).strip())
    except ValueError:
        return default


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes")

_STAG_BACK = _env_int("CONTEXTDROID_STAGNATION_BACK", STAGNATION_CONSECUTIVE_FOR_BACK)
_STAG_BAILOUT = _env_int("CONTEXTDROID_STAGNATION_BAILOUT", STAGNATION_CONSECUTIVE_FOR_BAILOUT)
_STAG_BAILOUT = max(_STAG_BAILOUT, _STAG_BACK + 1)

_REP_WIN = _env_int("CONTEXTDROID_REPETITION_WINDOW", REPETITION_WINDOW, minimum=2)
_REP_THR = _env_int("CONTEXTDROID_REPETITION_THRESHOLD", REPETITION_THRESHOLD, minimum=2)

_ACTION_HIST_WIN = _env_int("CONTEXTDROID_LLM_ACTION_HISTORY_WINDOW", ACTION_HISTORY_WINDOW, minimum=2)

_MAX_AGENT_XML_TOKENS = _env_int("CONTEXTDROID_MAX_AGENT_XML_TOKENS", MAX_AGENT_XML_TOKENS, minimum=256)

_LLM_TEMPERATURE_RUNTIME = _env_float("CONTEXTDROID_LLM_TEMPERATURE", LLM_TEMPERATURE)

_SLIM_ACTION_LOG = os.environ.get("CONTEXTDROID_LLM_SLIM_ACTION_LOG", "").strip().lower() in ("1", "true", "yes")

_SESSION_TIMEOUT_MULTIPLIER = _env_int(
    "CONTEXTDROID_SESSION_TIMEOUT_MULTIPLIER", SESSION_TIMEOUT_MULTIPLIER, minimum=2
)

# After tapping a field, brief pause before `input text` (one LLM step, multiple ADB ops).
_INPUT_FOCUS_PAUSE_SEC = _env_float("CONTEXTDROID_LLM_INPUT_FOCUS_PAUSE_SEC", 0.35)

# Optional settle before post-action hierarchy dump / next planner step (helps slow animations).
_POST_ACTION_SETTLE_SEC = _env_float("CONTEXTDROID_LLM_POST_ACTION_SETTLE_SEC", 0.0)

# Structured per-step audit (screen before/after, proposal vs executed, heuristic codes).
_AUDIT_SESSION = _env_truthy("CONTEXTDROID_LLM_AUDIT_SESSION")
_AUDIT_POST_ACTION_SLEEP_SEC = _env_float("CONTEXTDROID_LLM_AUDIT_POST_ACTION_SLEEP_SEC", 0.35)
_FOREGROUND_DUMPSYS_TIMEOUT_SEC = max(3.0, _env_float("CONTEXTDROID_LLM_FOREGROUND_DUMPSYS_TIMEOUT_SEC", 14.0))
_UI_DUMP_TIMEOUT_SEC = max(5.0, _env_float("CONTEXTDROID_LLM_UI_DUMP_TIMEOUT_SEC", 15.0))
_ROOT_CAPTURE_DEADLINE_SEC = max(5.0, _env_float("CONTEXTDROID_ROOT_CAPTURE_DEADLINE_SEC", 30.0))
_PRE_SETUP_MAX_SEC = max(30.0, _env_float("CONTEXTDROID_PRE_SETUP_MAX_SEC", 120.0))
_OLLAMA_GENERATE_TIMEOUT_SEC = max(15.0, _env_float("CONTEXTDROID_OLLAMA_GENERATE_TIMEOUT_SEC", 60.0))


def _env_flag(name: str, *, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    return str(raw).strip().lower() in ("1", "true", "yes")


# adb `input text` appends — clear focused field before typing; infer Enter on search-like targets if model omits submit_search.
_INPUT_CLEAR_BEFORE_TEXT = _env_flag("CONTEXTDROID_LLM_INPUT_CLEAR_BEFORE_TEXT", default=True)
_INPUT_CLEAR_DEL_COUNT = _env_int("CONTEXTDROID_LLM_INPUT_CLEAR_DEL_COUNT", 160, minimum=0)
_INPUT_SUBMIT_SEARCH_INFER = _env_flag("CONTEXTDROID_LLM_INPUT_SUBMIT_SEARCH_INFER", default=True)

# Brief pause after adb `input text` before firing submit keyevents (IME may lag behind injected text).
_INPUT_POST_TEXT_SUBMIT_PAUSE_SEC = _env_float("CONTEXTDROID_LLM_INPUT_POST_TEXT_SUBMIT_PAUSE_SEC", 0.22)

# If True, submit_search:false from the LLM suppresses IME submit even on search-like fields (default off — models spam false).
_INPUT_SUBMIT_RESPECT_MODEL_FALSE_ON_SEARCH = _env_flag(
    "CONTEXTDROID_LLM_INPUT_SUBMIT_RESPECT_MODEL_FALSE_ON_SEARCH", default=False
)

# Sending BACK during stagnation pops overlays/search — default off for LLM UX exploration.
_STAGNATION_INJECT_BACK = _env_flag("CONTEXTDROID_LLM_STAGNATION_USE_BACK", default=False)
# repetition_guard → BACK also collapses search — default wait instead.
_REPETITION_GUARD_USE_BACK = _env_flag("CONTEXTDROID_LLM_REPETITION_GUARD_USE_BACK", default=False)

# Only pull user back when really in launcher/browser — stops false recover → MainActivity resets.
_STICKY_FOREGROUND_STRICT = _env_flag("CONTEXTDROID_LLM_STICKY_FOREGROUND_STRICT", default=True)


# Human-readable step trace next to *_llm_actions.jsonl (grep-friendly).
_STEP_DEBUG = _env_truthy("CONTEXTDROID_LLM_STEP_DEBUG")
_STEP_DEBUG_PROMPT = _env_truthy("CONTEXTDROID_LLM_STEP_DEBUG_PROMPT")

# Two-phase UX exploration: upfront goal list, then each step conditioned on active goal.
_USE_GOAL_PLAN = _env_truthy("CONTEXTDROID_LLM_GOAL_PLAN")

# Nav-first: batched exploration → screen digest → plan goals → batched execution (default on).
# Disable with CONTEXTDROID_LLM_NAV_FIRST_PIPELINE=0|false|no (legacy single-phase UX path).
_NAV_FIRST_PIPELINE = _env_flag("CONTEXTDROID_LLM_NAV_FIRST_PIPELINE", default=True)
_EXPLORE_RATIO = max(0.1, min(0.85, _env_float("CONTEXTDROID_LLM_EXPLORE_RATIO", 0.30)))
_EXPLORE_UNTIL_SEC_FLOOR = max(0.0, _env_float("CONTEXTDROID_LLM_EXPLORE_UNTIL_SEC_FLOOR", 0.0))
_LLM_AGENT_SEED_RUNTIME = os.environ.get("CONTEXTDROID_LLM_AGENT_SEED", "").strip()


def _ollama_generate_options() -> dict[str, Any]:
    opts: dict[str, Any] = {"temperature": _LLM_TEMPERATURE_RUNTIME}
    if _LLM_AGENT_SEED_RUNTIME:
        try:
            opts["seed"] = int(_LLM_AGENT_SEED_RUNTIME)
        except ValueError:
            pass
    return opts


_BATCH_ACTIONS_MAX = _env_int("CONTEXTDROID_LLM_BATCH_ACTIONS_MAX", 12, minimum=1)
# Nav-first execute phase: one planner call per goal step by default (replan-friendly).
_EXECUTE_UX_BATCH_MAX = _env_int("CONTEXTDROID_LLM_EXECUTE_UX_BATCH_MAX", 1, minimum=1)
_EXECUTE_UX_GOAL_PREVIEW = _env_int("CONTEXTDROID_LLM_EXECUTE_UX_GOAL_PREVIEW", 2, minimum=0)
_NAV_DIGEST_MAX_SCREENS = _env_int("CONTEXTDROID_LLM_NAV_DIGEST_MAX_SCREENS", 56, minimum=8)

# After structured UX goals finish (or stagnation bailout), run a feed-style "primary app UX" phase (set 0/false/no to disable).
_PRIMARY_UX_FALLBACK = _env_flag("CONTEXTDROID_LLM_PRIMARY_UX_FALLBACK", default=True)

# Nav-first only: after explore, spend a short time on checklist goals then blend into primary UX (realistic sustained use).
# Either trigger fires first. Set CONTEXTDROID_LLM_PRIMARY_UX_BLEND_AFTER_GOAL_INDEX very high (e.g. 999) to use only the
# timer; set CONTEXTDROID_LLM_PRIMARY_UX_BLEND_AFTER_POST_NAV_SEC to 0 to disable the timer.
_PRIMARY_UX_BLEND_AFTER_GOAL_INDEX = _env_int(
    "CONTEXTDROID_LLM_PRIMARY_UX_BLEND_AFTER_GOAL_INDEX", 4, minimum=0
)
_PRIMARY_UX_BLEND_AFTER_POST_NAV_SEC = _env_float(
    "CONTEXTDROID_LLM_PRIMARY_UX_BLEND_AFTER_POST_NAV_SEC", 210.0
)
# Percentage-based alternative for time-triggered primary blend; overridden by *_POST_NAV_SEC when set.
_PRIMARY_UX_BLEND_AFTER_POST_NAV_RATIO = max(
    0.05, min(0.95, _env_float("CONTEXTDROID_LLM_PRIMARY_UX_BLEND_AFTER_POST_NAV_RATIO", 0.35))
)
# Minimum seconds spent in execute before time-triggered blend can fire.
_PRIMARY_UX_BLEND_AFTER_POST_NAV_MIN_SEC = _env_float(
    "CONTEXTDROID_LLM_PRIMARY_UX_BLEND_AFTER_POST_NAV_MIN_SEC", 90.0
)
# Time-based primary-UX blend only after advancing structured goals at least this far (0 = legacy behavior).
_PRIMARY_UX_BLEND_MIN_GOAL_INDEX_FOR_TIME = _env_int(
    "CONTEXTDROID_LLM_PRIMARY_UX_BLEND_MIN_GOAL_INDEX_FOR_TIME", 1, minimum=0
)
# When forward goal count is below this threshold, blend into primary UX sooner (sparse execute plan).
_PRIMARY_UX_SPARSE_GOALS_THRESHOLD = _env_int(
    "CONTEXTDROID_LLM_PRIMARY_UX_SPARSE_GOALS_THRESHOLD", 4, minimum=2
)
_PRIMARY_UX_BLEND_SPARSE_AFTER_GOAL_INDEX = _env_int(
    "CONTEXTDROID_LLM_PRIMARY_UX_BLEND_SPARSE_AFTER_GOAL_INDEX", 1, minimum=0
)
_PRIMARY_UX_BLEND_SPARSE_TIME_RATIO = max(
    0.1, min(1.0, _env_float("CONTEXTDROID_LLM_PRIMARY_UX_BLEND_SPARSE_TIME_RATIO", 0.55))
)
# Guarantee a minimum primary-UX window remains before we switch into primary mode.
_PRIMARY_UX_MIN_WINDOW_SEC = _env_float("CONTEXTDROID_LLM_PRIMARY_UX_MIN_WINDOW_SEC", 60.0)
# Consecutive engine back-goal steps with no screen change before auto-advance.
_BACK_GOAL_STUCK_LIMIT = _env_int("CONTEXTDROID_LLM_BACK_GOAL_STUCK_LIMIT", 3, minimum=2)
# Nav-first execute: when True, prefer deterministic engine routing over Ollama on execute.
_EXECUTE_ENGINE_ONLY = _env_flag("CONTEXTDROID_LLM_EXECUTE_ENGINE_ONLY", default=False)

_POST_EXPLORE_GOALS_MAX = _env_int("CONTEXTDROID_LLM_POST_EXPLORE_GOALS_MAX", 10, minimum=4)
_POST_EXPLORE_GOALS_MIN_KEEP = _env_int(
    "CONTEXTDROID_LLM_POST_EXPLORE_GOALS_MIN_KEEP", 4, minimum=2
)
_POST_EXPLORE_STRICT_DIGEST = _env_flag(
    "CONTEXTDROID_LLM_POST_EXPLORE_STRICT_DIGEST", default=True
)

_ROOT_HANDOFF_RELAUNCH = _env_flag("CONTEXTDROID_LLM_ROOT_HANDOFF_RELAUNCH", default=True)
_ROOT_HANDOFF_FORCE_STOP = _env_flag("CONTEXTDROID_LLM_ROOT_HANDOFF_FORCE_STOP", default=False)
_ROOT_HANDOFF_CLEAR_TASK = _env_flag("CONTEXTDROID_LLM_ROOT_HANDOFF_CLEAR_TASK", default=False)
_ROOT_HANDOFF_ATTEMPTS = _env_int("CONTEXTDROID_LLM_ROOT_HANDOFF_ATTEMPTS", 3, minimum=1)
_ROOT_HANDOFF_BACK_STEPS = _env_int("CONTEXTDROID_LLM_ROOT_HANDOFF_BACK_STEPS", 3, minimum=0)
_HANDOFF_EXPLORE_SETTLED_MIN_VISITS = _env_int(
    "CONTEXTDROID_LLM_HANDOFF_EXPLORE_SETTLED_MIN_VISITS", 3, minimum=1
)
_HANDOFF_EXPLORE_SETTLED_MIN_LANDMARK = _env_int(
    "CONTEXTDROID_LLM_HANDOFF_EXPLORE_SETTLED_MIN_LANDMARK", 2, minimum=1
)
_EMPTY_EXECUTE_RECOVERY_ATTEMPTS = _env_int(
    "CONTEXTDROID_LLM_EMPTY_EXECUTE_RECOVERY_ATTEMPTS", 3, minimum=1
)
# After entering a nav hub/tab, spend this many explore turns on interior taps before tab cycling.
_BFS_INTERIOR_EXPAND_BUDGET = _env_int(
    "CONTEXTDROID_LLM_BFS_INTERIOR_EXPAND_BUDGET", 3, minimum=1
)
# Per-screen interior keys already tapped; deprioritize tab cycling until exhausted.
_BFS_LAYER_EXPAND_BEFORE_CYCLE = _env_flag(
    "CONTEXTDROID_LLM_BFS_LAYER_EXPAND_BEFORE_CYCLE", default=True
)
# After this many no-progress expand taps on one screen, allow tab cycling again.
_BFS_EXPAND_STALL_LIMIT_PER_SCREEN = _env_int(
    "CONTEXTDROID_LLM_BFS_EXPAND_STALL_LIMIT_PER_SCREEN", 4, minimum=2
)
PARTIAL_BAD_HANDOFF = "bad_handoff"
PARTIAL_EMPTY_EXECUTE = "empty_execute_hierarchy"
PARTIAL_EXPLORE_NON_NAVIGABLE = "explore_non_navigable"
# Fail-fast when explore loops on empty hierarchy + back/wait recovery (see phase_aware_metrics K analysis).
_EXPLORE_NON_NAVIGABLE_STREAK_LIMIT = _env_int(
    "CONTEXTDROID_LLM_EXPLORE_NON_NAVIGABLE_STREAK_LIMIT", 10, minimum=4
)

_DEFAULT_PRIMARY_UX_TEXT = (
    "Do what most users open this app for: reach the main content surface (home/feed/list), then browse it with "
    "vertical swipe/scroll gestures. Vary swipe start/end slightly; occasional short wait is fine."
)


def _explore_until_seconds(duration_sec: int) -> float:
    """Nav-first: time budget for exploration-only prompts before post-explore goals + execute phase.

    Capped so at least CONTEXTDROID_LLM_EXECUTE_RESERVE_SEC (default ~52% of session, min 90s) remains
    on the clock for planning slack + carrying out goals.
    """
    if not _NAV_FIRST_PIPELINE:
        return 0.0
    ratio_slice = float(duration_sec) * _EXPLORE_RATIO
    env_r = os.environ.get("CONTEXTDROID_LLM_EXECUTE_RESERVE_SEC", "").strip()
    if env_r:
        try:
            reserve = float(env_r)
        except ValueError:
            reserve = max(90.0, float(duration_sec) * 0.52)
    else:
        reserve = max(90.0, float(duration_sec) * 0.52)
    reserve = max(45.0, min(reserve, float(duration_sec) - 35.0))
    explore_cap = float(duration_sec) - reserve
    merged = min(ratio_slice, explore_cap)
    if _EXPLORE_UNTIL_SEC_FLOOR > 0:
        merged = max(merged, min(_EXPLORE_UNTIL_SEC_FLOOR, explore_cap))
    return max(25.0, min(merged, float(duration_sec) - 30.0))


def _effective_primary_blend_after_sec(duration_sec: int) -> float:
    """Time spent in execute before primary-UX timer can trigger.

    Default behavior is percentage-based with a minimum floor. Legacy absolute env
    CONTEXTDROID_LLM_PRIMARY_UX_BLEND_AFTER_POST_NAV_SEC still overrides when set.
    """
    legacy = os.environ.get("CONTEXTDROID_LLM_PRIMARY_UX_BLEND_AFTER_POST_NAV_SEC", "").strip()
    if legacy:
        try:
            return max(0.0, float(legacy))
        except ValueError:
            pass
    return max(
        _PRIMARY_UX_BLEND_AFTER_POST_NAV_MIN_SEC,
        float(duration_sec) * _PRIMARY_UX_BLEND_AFTER_POST_NAV_RATIO,
    )


def _effective_primary_blend_goal_index(forward_goal_count: int) -> int:
    """Goal index at which structured execute may blend into primary UX."""
    if forward_goal_count < _PRIMARY_UX_SPARSE_GOALS_THRESHOLD:
        return _PRIMARY_UX_BLEND_SPARSE_AFTER_GOAL_INDEX
    return _PRIMARY_UX_BLEND_AFTER_GOAL_INDEX


def _primary_blend_after_sec_for_goals(duration_sec: int, forward_goal_count: int) -> float:
    """Execute timer before primary-UX blend; shorter when goals are sparse."""
    base = _effective_primary_blend_after_sec(duration_sec)
    if forward_goal_count >= _PRIMARY_UX_SPARSE_GOALS_THRESHOLD:
        return base
    return max(
        _PRIMARY_UX_BLEND_AFTER_POST_NAV_MIN_SEC * 0.5,
        base * _PRIMARY_UX_BLEND_SPARSE_TIME_RATIO,
    )

_ACTION_TYPES_PLANNER = frozenset({"tap", "input", "back", "wait", "advance_goal", "swipe"})


def _env_default_yes(name: str) -> bool:
    """Unset env → True; set to 0/false/no to disable."""
    v = os.environ.get(name)
    if v is None or str(v).strip() == "":
        return True
    return str(v).strip().lower() not in ("0", "false", "no")


# Keep analysis inside the APK-under-test (recover when Chrome / launcher steals focus).
_STICKY_FOREGROUND = _env_default_yes("CONTEXTDROID_LLM_STICKY_FOREGROUND")
# By default, treat permission/settings/package-installer surfaces as foreign (recover to target app).
_TREAT_DIALOG_PACKAGES_AS_FOREIGN = _env_flag(
    "CONTEXTDROID_LLM_TREAT_DIALOG_PACKAGES_AS_FOREIGN", default=True
)
_FILTER_FOREIGN_WIDGETS = _env_default_yes("CONTEXTDROID_LLM_FILTER_FOREIGN_WIDGETS")

_FOREGROUND_DIALOG_PACKAGES = frozenset(
    {
        "com.android.permissioncontroller",
        "com.google.android.permissioncontroller",
        "com.android.packageinstaller",
        "com.google.android.packageinstaller",
        "com.android.documentsui",
        "com.google.android.documentsui",
    }
)

# Runtime permission sheets only — one-shot dismiss applies here (not file pickers / installers).
_PERMISSION_DIALOG_PACKAGES = frozenset(
    {
        "com.android.permissioncontroller",
        "com.google.android.permissioncontroller",
    }
)

# Do not treat these as "left the app" — avoids relaunching MainActivity while typing / notifications.
_FOREGROUND_TRANSIENT_PACKAGES = frozenset(
    {
        "com.android.systemui",
        "com.google.android.inputmethod.latin",
        "com.android.inputmethod.latin",
        "com.samsung.android.honeyboard",
    }
)

_LAUNCHER_PACKAGES = frozenset(
    {
        "com.google.android.apps.nexuslauncher",
        "com.android.launcher",
        "com.android.launcher3",
        "com.sec.android.app.launcher",
        "com.mi.android.globallauncher",
    }
)

_BROWSER_PACKAGES = frozenset(
    {
        "com.android.chrome",
        "com.chrome.beta",
        "com.chrome.dev",
        "org.chromium.chrome",
        "com.brave.browser",
        "com.microsoft.emmx",
        "org.mozilla.firefox",
    }
)

# Share sheets / intent choosers that steal focus during OAuth or export flows.
_FOREGROUND_CHOOSER_PACKAGES = frozenset(
    {
        "com.android.intentresolver",
        "com.google.android.apps.docs",
        "com.android.internal.app.ChooserActivity",
    }
)

_SETTINGS_PACKAGES = frozenset(
    {
        "com.android.settings",
        "com.google.android.settings",
        "com.google.android.permissioncontroller",
        "com.android.packageinstaller",
        "com.google.android.packageinstaller",
        # OEM / overlay settings and device-care surfaces that leave the app under test.
        "com.samsung.android.settings",
        "com.samsung.android.app.settings",
        "com.miui.securitycenter",
        "com.coloros.safecenter",
        "com.oplus.safecenter",
        "com.oneplus.security",
    }
)

_DIALOG_STUCK_RECOVERY_STREAK = _env_int(
    "CONTEXTDROID_LLM_DIALOG_STUCK_RECOVERY_STREAK", 3, minimum=1
)

# Permission dialogs + system Settings / installers: consecutive dumpsys hits trigger return-to-app.
_FOREGROUND_STUCK_SURFACES: frozenset[str] = _FOREGROUND_DIALOG_PACKAGES | _SETTINGS_PACKAGES

_DEFAULT_UX_GOALS: list[str] = [
    "Explore primary browsing or home content",
    "Use search or filtering if available",
    "Open one item's detail view",
    "Exercise main navigation (tabs, drawer, or categories)",
    "Return toward the app's starting screen",
]

_BAD_UX_GOAL_RE = re.compile(
    r"\b(launch(\s+the)?\s+app|install|open\s+the\s+app|start\s+the\s+app|open\s+app)\b",
    re.IGNORECASE,
)

_ABSTRACT_PLANNER_GOAL_RE = re.compile(
    r"\b("
    r"architecture|metadata|integration|investigate|investigating|"
    r"hybrid\s+android|application\s+architecture|refin(e|ing)\s+metadata|"
    r"source\s+integration|log\s+generation|behavioral\s+notes|"
    r"usability\s+study|user\s+discovery\s+features|navigation\s+patterns|"
    r"correlat(e|ing)|determin(e|ing)\s+expected\s+permissions|"
    r"app_context|user\s+feedback|functionality\s+or\s+performance"
    r")\b",
    re.IGNORECASE,
)

_SEARCH_UI_HINT_RE = re.compile(
    r"\b(search|query|find|filter|lookup)\b",
    re.IGNORECASE,
)

