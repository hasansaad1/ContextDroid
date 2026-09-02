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

from .audit import _execution_counts_as_ux_progress
from .goals import _goal_action_hint
from .navigation import _navigation_explore_targets_summary
from .planner import _iter_json_roots, _ollama_generate_with_retries
from .screen import _allowed_resource_ids_from_elements
from .config import (
    _ACTION_HIST_WIN,
    _DEFAULT_PRIMARY_UX_TEXT,
    _EXECUTE_UX_GOAL_PREVIEW,
)

def _parse_primary_ux_spec(raw: str) -> str:
    for root in _iter_json_roots(raw):
        if isinstance(root, dict):
            spec = root.get("primary_ux") or root.get("primaryUX") or root.get("mission")
            if isinstance(spec, str) and spec.strip():
                return spec.strip()
    return ""

def _plan_primary_app_ux(
    app_context: dict[str, Any], screen_map_text: str, model: str, endpoint: str
) -> str:
    """Ask the planner for the single dominant real-user session (feed scroll, reels swipe, etc.)."""
    prompt = (
        "Black-box Android UX analyst. Infer the MAIN habitual usage of this app — what a typical user does "
        "for most sessions (not settings, not one-off onboarding).\n"
        "Examples: social apps → vertically scroll home feed or browse reels/stories; readers → scroll article/list; "
        "marketplaces → scroll product grids; maps → pan/zoom map (still use swipe).\n"
        "Reply JSON ONLY (no fences): {\"primary_ux\":\"...\"} where primary_ux is 2-5 short sentences with "
        "concrete gestures (vertical swipe between y coordinates, horizontal swipe if tabs/carousel). "
        "Mention opening the right tab first if needed.\n\n"
        f"SCREEN_MAP (may be empty):\n{screen_map_text}\n\n"
        f"APP_CONTEXT:\n{json.dumps(app_context, ensure_ascii=False)}\n"
    )
    try:
        raw = _ollama_generate_with_retries(prompt, model, endpoint)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        logging.warning("Primary UX planning failed; using default mission text.")
        return _DEFAULT_PRIMARY_UX_TEXT
    spec = _parse_primary_ux_spec(raw)
    if not spec:
        logging.warning(
            "Could not parse primary_ux JSON; using default. preview=%r",
            (raw[:800] + "…") if len(raw) > 800 else raw,
        )
        return _DEFAULT_PRIMARY_UX_TEXT
    return spec

def _merge_primary_ux_into_plan(plan_path: Path | None, spec: str, reason: str) -> None:
    if plan_path is None:
        return
    obj: dict[str, Any] = {}
    if plan_path.exists():
        try:
            obj = json.loads(plan_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            obj = {}
    obj["primary_ux_fallback"] = {"spec": spec, "reason": reason}
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    plan_path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")

def _derive_primary_ux_micro_intent(
    *,
    primary_mission: str,
    app_state: dict[str, Any] | None,
    elements: list[dict[str, str]],
    recent_actions: list[dict[str, Any]],
    stagnant: int,
) -> dict[str, Any]:
    state = app_state or {}
    visible_nav = list(state.get("visible_nav_tokens") or [])
    active_nav = str(state.get("active_nav_token") or "")
    screen_role = str(state.get("screen_role") or "")
    recent_direct = [
        ev
        for ev in recent_actions[-4:]
        if str(ev.get("pipeline_phase") or "") == "primary_ux"
        and _execution_counts_as_ux_progress(ev)
    ]
    last_types = [str((ev.get("parsed_action") or {}).get("action_type") or "") for ev in recent_direct]
    if state.get("dialog_visible"):
        return {
            "intent": "resolve_blocking_dialog",
            "instruction": "Dismiss or back out of the dialog once, then return to the app's main surface.",
            "preferred_actions": ["tap", "back"],
        }
    if screen_role in ("text_entry", "form") or (
        state.get("text_entry_visible") and not state.get("search_open")
    ):
        return {
            "intent": "complete_text_entry",
            "instruction": (
                "Use action_type=input with non-empty text on the visible text field; "
                "do not swipe a form or login surface."
            ),
            "preferred_actions": ["input", "tap"],
        }
    if stagnant >= 2:
        return {
            "intent": "escape_stagnant_surface",
            "instruction": "Use one scroll or a different visible item/tab; do not repeat the previous target.",
            "preferred_actions": ["swipe", "tap", "back"],
        }
    if state.get("search_open"):
        return {
            "intent": "briefly_review_search_surface",
            "instruction": "If results/content are visible, browse briefly; otherwise back to the main content surface.",
            "preferred_actions": ["swipe", "tap", "back"],
        }
    if last_types and all(t == "swipe" for t in last_types[-3:]):
        return {
            "intent": "vary_after_scrolling",
            "instruction": "After several scrolls, open one visible item or switch to another main tab.",
            "preferred_actions": ["tap"],
        }
    if active_nav:
        return {
            "intent": f"browse_{active_nav}_surface",
            "instruction": f"Stay on {active_nav} briefly: scroll content or open a visible item, then back if needed.",
            "preferred_actions": ["swipe", "tap", "back"],
            "active_nav_token": active_nav,
        }
    if visible_nav:
        return {
            "intent": "choose_main_navigation_surface",
            "instruction": "Tap one visible main navigation tab, then browse the resulting content.",
            "preferred_actions": ["tap"],
            "visible_nav_tokens": visible_nav,
        }
    if elements:
        return {
            "intent": "browse_current_content_surface",
            "instruction": "Browse the current content with a scroll or a single visible content tap.",
            "preferred_actions": ["swipe", "tap"],
        }
    return {
        "intent": "wait_for_content_or_recover",
        "instruction": "Wait once or press back if the hierarchy remains empty.",
        "preferred_actions": ["wait", "back"],
        "mission": primary_mission[:240],
    }

def _recent_steps_summary(events: list[dict[str, Any]], *, max_steps: int) -> str:
    """Compact lines so small LLMs attend to outcomes (screen deltas, useless taps)."""
    if not events:
        return "(no prior steps)"
    lines: list[str] = []
    for ev in events[-max_steps:]:
        pa = ev.get("parsed_action") or {}
        at = str(pa.get("action_type") or "?")
        tid = (
            str(pa.get("target_resource_id") or "").strip()
            or str(pa.get("target_content_desc") or "").strip()
            or ""
        )
        bits: list[str] = [at]
        if tid:
            tail_id = tid.split("/")[-1]
            bits.append(tail_id[:56])
        tx = pa.get("text")
        if tx is not None and str(tx).strip():
            bits.append(f"text={str(tx).strip()[:44]}")
        line = " · ".join(bits)
        oc = str(ev.get("action_outcome") or "").strip()
        if oc:
            line += f" → {oc[:140]}"
        hb = str(ev.get("screen_hash") or "")
        ha = ev.get("screen_hash_after")
        if isinstance(ha, str) and ha and hb:
            line += " [UI changed]" if hb != ha else " [UI unchanged]"
        elif hb:
            line += " [UI delta n/a]"
        if "[UI unchanged]" in line and len(lines) >= 1:
            prev = lines[-1]
            if prev.split(" → ")[0] == line.split(" → ")[0]:
                line += " [REPEAT — use advance_goal or a different control]"
        lines.append(line)
    return "\n".join(lines)

def _stagnation_prompt_fragment(
    stagnant: int, *, goal_plan: bool, goal_status: str = "feasible"
) -> str:
    if stagnant < 3:
        return ""
    if goal_plan and goal_status == "satisfied":
        return (
            f"\nSTAGNATION_ALERT: UI unchanged for {stagnant} dumps but the ACTIVE goal is already satisfied — "
            "return advance_goal now; do not repeat the same tap.\n"
        )
    frag = (
        f"\nSTAGNATION_ALERT: UI fingerprint unchanged for {stagnant} consecutive dumps — do NOT repeat the same "
        "tap target/coordinates. Use ONLY ids from ALLOWED_TARGET_RESOURCE_IDS"
    )
    if goal_plan:
        frag += (
            ". If the ACTIVE goal is done or going nowhere, return advance_goal. "
            "If the goal needs a query field, use input with text on a visible EditText"
        )
    frag += ".\n"
    return frag

def _build_explore_prompt(
    app_context: dict[str, Any],
    elements: list[dict[str, str]],
    recent_actions: list[dict[str, Any]],
    *,
    stagnant: int,
    navigation_digest_text: str,
    batch_limit: int,
) -> str:
    hist = recent_actions[-_ACTION_HIST_WIN:]
    summary = _recent_steps_summary(recent_actions, max_steps=_ACTION_HIST_WIN)
    stagnation = _stagnation_prompt_fragment(stagnant, goal_plan=False)
    nav_targets, nav_detected = _navigation_explore_targets_summary(elements)
    nav_priority = (
        "NAVIGATION_BAR_PRIORITY: Explore primary navigation thoroughly BEFORE unrelated scrolling.\n"
        "- If NAVIGATION_TARGETS_DETECTED lists tabs/chips/bar items, spend MOST of each batch tapping "
        "distinct destinations there until each has been tried at least once across recent turns "
        "(breadth-first).\n"
        "- After opening a destination from the nav strip, press BACK when stuck so you can return and tap "
        "the next nav target.\n"
        "- Include drawer/menu opener taps when visible; open drawer once then tap each drawer destination.\n"
        "- Horizontal tab strips at top count as navigation — cycle through tabs similarly.\n"
    )
    if nav_detected:
        nav_priority += (
            "- Detected nav-like widgets below — prioritize these resource_ids/content_descs over random list rows.\n"
        )
    else:
        nav_priority += (
            "- No strong nav heuristic match — still bias taps toward bottom labeled bars, tab rows, drawer icons.\n"
        )
    return (
        "PHASE=APP_NAVIGATION (coverage first). Build a mental map of the app — maximize DISTINCT screens.\n"
        f"Return JSON ONLY: {{\"actions\":[{{...}}, ...]}} with 1–{batch_limit} actions per response. "
        "The runner executes ALL listed actions IN ORDER before asking you again — no LLM between them.\n"
        + nav_priority
        + "Also explore non-nav surfaces (lists, settings, FAB/search) AFTER nav breadth is progressing.\n"
        "Each action uses fields action_type(tap|input|back|wait), target_resource_id, target_content_desc, "
        "x, y, text, submit_search, reason.\n"
        "Avoid repeating ineffective taps (see RECENT_STEP_SUMMARY). Stay inside the app under test.\n"
        + stagnation
        + "\nNAVIGATION_TARGETS_DETECTED:\n"
        + nav_targets
        + "\n\nDISCOVERED_SCREENS (hash → hints):\n"
        + navigation_digest_text
        + "\n\nAPP_CONTEXT:\n"
        + json.dumps(app_context, ensure_ascii=False)
        + "\n\nRECENT_STEP_SUMMARY:\n"
        + summary
        + "\n\nRECENT_ACTIONS_JSON:\n"
        + json.dumps(hist, ensure_ascii=False)
        + "\n\nCLEAN_SCREEN_ELEMENTS:\n"
        + json.dumps(elements, ensure_ascii=False)
        + "\n"
    )

def _build_prompt(
    app_context: dict[str, Any],
    elements: list[dict[str, str]],
    recent_actions: list[dict[str, Any]],
    *,
    ux_goals: list[str] | None = None,
    ux_goal_index: int = 0,
    ux_goal_feasible_now: bool = True,
    ux_goal_status: str = "feasible",
    goal_blocked_turns: int = 0,
    stagnant: int = 0,
    navigation_context: str | None = None,
    app_state: dict[str, Any] | None = None,
    ux_goal_route: dict[str, Any] | None = None,
    batch_limit: int = 1,
    replan_alert: str = "",
) -> str:
    hist = recent_actions[-_ACTION_HIST_WIN:]
    summary = _recent_steps_summary(recent_actions, max_steps=_ACTION_HIST_WIN)
    stagnation = _stagnation_prompt_fragment(
        stagnant, goal_plan=bool(ux_goals), goal_status=ux_goal_status
    )
    allowed_ids = _allowed_resource_ids_from_elements(elements)
    nav_ctx = ""
    if navigation_context:
        nav_ctx = (
            "APP_NAVIGATION_CONTEXT (distinct screens discovered during navigation phase):\n"
            + navigation_context
            + "\n\n"
        )
    if batch_limit > 1:
        batch_instr = (
            f"Return JSON {{\"actions\":[...]}} with up to {batch_limit} actions executed sequentially before "
            "the next planner call, OR return one action object (same schema fields).\n"
        )
    else:
        batch_instr = (
            "Return ONE JSON action object with action_type; you may also use {\"actions\":[single]}.\n"
        )
    nav_shell = (
        "You explore the whole in-app UX — vary destinations; avoid fixation on one widget.\n"
        + batch_instr
        + "If you tap a search/query field then type, prefer one merged input object "
        "(resource_id/content_desc/x,y + text) or consecutive tap+input inside actions[].\n"
        "Read RECENT_STEP_SUMMARY from oldest→newest: if you see fallback_rid_missing, tap_xy with UI unchanged, "
        "or repetition_guard waits, switch tactics — pick another visible control, BACK once, advance_goal "
        "(when using UX goals), or input into an EditText/search affordance shown in CLEAN_SCREEN_ELEMENTS.\n\n"
    )
    if ux_goals:
        gi = max(0, min(ux_goal_index, len(ux_goals) - 1))
        active_goal = ux_goals[gi]
        action_hint = _goal_action_hint(
            active_goal, ux_goal_status, elements, app_state, recent_actions=recent_actions
        )
        status_line = (
            f"GOAL_STATUS: {ux_goal_status} "
            f"(feasible_on_screen={'yes' if ux_goal_feasible_now else 'no'}, blocked_turns={goal_blocked_turns})\n"
            f"GOAL_ACTION_HINT: {action_hint}\n"
        )
        preview_n = max(0, min(_EXECUTE_UX_GOAL_PREVIEW, len(ux_goals) - gi - 1))
        upcoming_lines = ""
        if preview_n > 0:
            upcoming_lines = "NEXT GOALS (orientation only — do NOT execute until advanced):\n"
            for j in range(preview_n):
                upcoming_lines += f"  {gi + 2 + j}. {ux_goals[gi + 1 + j]}\n"
            upcoming_lines += "\n"
        if allowed_ids:
            allowed_block = (
                "ALLOWED_TARGET_RESOURCE_IDS (use ONLY these exact strings for target_resource_id):\n"
                + json.dumps(allowed_ids, ensure_ascii=False)
                + "\nDo not synthesize variants, prefixes, or bottom_nav_* ids.\n\n"
            )
        else:
            allowed_block = (
                "ALLOWED_TARGET_RESOURCE_IDS: []\n"
                "No target app controls are visible. Do not invent target_resource_id. "
                "Return wait or advance_goal only.\n\n"
            )
        goal_block = (
            "ACTIVE UX GOAL ({}/{}):\n{}\n\n"
            "{}{}{}{}"
            "CRITICAL: Return JSON for the ACTIVE UX GOAL only (one action preferred). "
            "Do NOT output a multi-step checklist for later goals.\n\n".format(
                gi + 1,
                len(ux_goals),
                active_goal,
                status_line,
                (
                    "ACTIVE_GOAL_ROUTE:\n"
                    + json.dumps(ux_goal_route or {}, ensure_ascii=False)
                    + "\n"
                    if ux_goal_route
                    else ""
                ),
                upcoming_lines,
                allowed_block,
            )
        )
        replan_block = ""
        if replan_alert.strip():
            replan_block = replan_alert.strip() + "\n\n"
        rules = (
            replan_block
            + nav_shell
            + "You are an Android UI agent.\n"
            "Fields: action_type(tap|input|back|wait|advance_goal|swipe), target_resource_id, "
            "target_content_desc, x, y, text, reason, submit_search (optional bool). "
            "swipe: x1,y1,x2,y2 (vertical list browse: y1 below y2 on screen), optional duration_ms.\n"
            "For search/input: put the ENTIRE query in text — one LLM step injects the whole string via ADB "
            "(not letter-by-letter). You may set target_resource_id/content_desc or x,y on the same object "
            "to tap-focus the field immediately before typing.\n"
            "adb input text APPENDS unless the runner clears the field first (default on): repeated input "
            "steps otherwise duplicate text.\n"
            "After typing into search/query fields, the runner submits via keyevents (not by tapping the soft "
            "keyboard): adb input text never presses IME keys; search-like fields default to Enter then TAB+Enter "
            "to approximate the keyboard Search action unless CONTEXTDROID_LLM_INPUT_SUBMIT_KEYSEQUENCE overrides.\n"
            "submit_search:false is ignored on search-like fields by default (models often emit it wrongly); set "
            "CONTEXTDROID_LLM_INPUT_SUBMIT_RESPECT_MODEL_FALSE_ON_SEARCH=1 to honor it.\n"
            "Search flows: Tap Search means open search chrome (FAB/button). When GOAL_STATUS=satisfied because the "
            "overlay/query field is already open, return advance_goal — do not tap Search again. Input search query "
            "means action_type=input with non-empty text on a visible EditText from ALLOWED list.\n"
            "NEVER use resource_ids not listed under ALLOWED_TARGET_RESOURCE_IDS (e.g. do not invent :id/search).\n"
            + (
                "POST-NAV USER SIMULATION: the shell is already mapped (see APP_NAVIGATION_CONTEXT). Behave like a "
                "real user continuing a session — short micro-intents, not a rigid checklist. Use swipe on lists/feeds "
                "between taps. Satisfy the ACTIVE UX GOAL lightly (one clear attempt or a few gestures), then "
                "advance_goal when it is good enough or going nowhere — do not grind the same intent.\n"
                if navigation_context
                else ""
            )
            + "Stay inside the app under test; do not open browsers or external apps.\n"
            "Follow GOAL_ACTION_HINT and GOAL_STATUS. When GOAL_STATUS=satisfied, return advance_goal immediately.\n"
            "When GOAL_STATUS=blocked, navigate with a visible tab/control from ALLOWED list or advance_goal.\n"
            "Prefer resource_id/content_desc over coordinates.\n"
            "Do not repeat failing actions.\n"
            + stagnation
            + "\n"
        )
        return (
            rules
            + goal_block
            + nav_ctx
            + f"APP_STATE:\n{json.dumps(app_state or {}, ensure_ascii=False)}\n\n"
            + f"APP_CONTEXT:\n{json.dumps(app_context, ensure_ascii=False)}\n\n"
            + "RECENT_STEP_SUMMARY:\n"
            + summary
            + "\n\nRECENT_ACTIONS_JSON:\n"
            + json.dumps(hist, ensure_ascii=False)
            + "\n\n"
            + f"CLEAN_SCREEN_ELEMENTS:\n{json.dumps(elements, ensure_ascii=False)}\n"
        )
    base = (
        nav_shell
        + "You are an Android UI agent. Fields: "
        "action_type(tap|input|back|wait), target_resource_id, target_content_desc, x, y, text, reason, "
        "submit_search (optional bool).\n"
        "For input/search: use one step with the full string in text (whole phrase, not per-letter). "
        "Include target_resource_id/content_desc or x,y on that same JSON object to focus the field before typing.\n"
        "Repeated input without clearing duplicates text — runner clears before replace when focusing by default.\n"
        "submit_search:true triggers submit keyevents after text (adb input text does not use the soft keyboard; "
        "search-like fields default to Enter then TAB+Enter unless CONTEXTDROID_LLM_INPUT_SUBMIT_KEYSEQUENCE is set).\n"
        "If a resource_id from a prior screen is gone, use the visible search/query field or coordinates — avoid repeat-tapping missing ids.\n"
        "Stay inside the app under test; do not open browsers or external apps.\n"
        "Priority: use resource_id/content_desc first, coordinates only if necessary.\n"
        "When stuck without goal-plan mode, prefer BACK once or a visibly different control.\n"
        "Do not repeat failing actions.\n"
        + stagnation
        + "\n\n"
        + nav_ctx
        + f"APP_STATE:\n{json.dumps(app_state or {}, ensure_ascii=False)}\n\n"
        + f"APP_CONTEXT:\n{json.dumps(app_context, ensure_ascii=False)}\n\n"
        + "RECENT_STEP_SUMMARY:\n"
        + summary
        + "\n\nRECENT_ACTIONS_JSON:\n"
        + json.dumps(hist, ensure_ascii=False)
        + "\n\n"
        + f"CLEAN_SCREEN_ELEMENTS:\n{json.dumps(elements, ensure_ascii=False)}\n"
    )
    return base

def _build_primary_ux_prompt(
    app_context: dict[str, Any],
    elements: list[dict[str, str]],
    recent_actions: list[dict[str, Any]],
    *,
    primary_mission: str,
    stagnant: int,
    navigation_digest_text: str,
    batch_limit: int,
    app_state: dict[str, Any] | None = None,
    primary_micro_intent: dict[str, Any] | None = None,
) -> str:
    hist = recent_actions[-_ACTION_HIST_WIN:]
    summary = _recent_steps_summary(recent_actions, max_steps=_ACTION_HIST_WIN)
    stagnation = _stagnation_prompt_fragment(stagnant, goal_plan=False)
    batch_instr = (
        f"Return JSON ONLY: {{\"actions\":[{{...}}, ...]}} with 1–{batch_limit} actions per response "
        "(executed in order).\n"
    )
    return (
        "PHASE=PRIMARY_APP_UX (remaining session time). Checklist goals are paused or finished — you already explored "
        "the app shell; now mimic typical sustained use (scroll/browse, revisit main tabs, short tasks).\n"
        + batch_instr
        + "PRIMARY_UX_MISSION (follow this closely):\n"
        + primary_mission
        + "\n\n"
        + "PRIMARY_MICRO_INTENT (this turn's concrete user-like intent):\n"
        + json.dumps(primary_micro_intent or {}, ensure_ascii=False)
        + "\n\n"
        "Actions: action_type one of tap|input|back|wait|swipe. Prefer swipe for scrolling feeds/lists.\n"
        "swipe fields: x1,y1,x2,y2 pixel coordinates (portrait phone). Vertical browse: same x, y1 below y2 "
        "(e.g. swipe up to see older content: start lower on screen, end higher). Optional duration_ms (50–450) "
        "for slower drag.\n"
        "Follow PRIMARY_MICRO_INTENT for this turn. If stuck on a dialog or wrong screen, back once then tap toward the main tab/feed.\n"
        "Avoid advance_goal — there is no goal index here. Avoid idle wait loops when the UI is unchanged — swipe "
        "or tap instead.\n"
        + stagnation
        + "\n\nDISCOVERED_SCREENS:\n"
        + navigation_digest_text
        + "\n\nAPP_CONTEXT:\n"
        + json.dumps(app_context, ensure_ascii=False)
        + "\n\nAPP_STATE:\n"
        + json.dumps(app_state or {}, ensure_ascii=False)
        + "\n\nRECENT_STEP_SUMMARY:\n"
        + summary
        + "\n\nRECENT_ACTIONS_JSON:\n"
        + json.dumps(hist, ensure_ascii=False)
        + "\n\nCLEAN_SCREEN_ELEMENTS:\n"
        + json.dumps(elements, ensure_ascii=False)
        + "\n"
    )
