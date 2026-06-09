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

from .dialogs import _element_is_permission_dialog_widget, _hierarchy_shows_permission_dialog, _package_is_permission_dialog_surface
from .goals import _goal_hint_for_repair, _goal_opens_search_ui, _screen_map_anchors
from .action_model import _action_signature_for_candidate
from .navigation import _action_is_back_like, _action_is_search_like
from .screen import (
    _allowed_resource_ids_from_elements,
    _bounds_center,
    _element_matches_tap_target,
    _hierarchy_max_bottom_y,
    _resource_id_belongs_to_target_app,
    _resource_id_owner_package,
    _visible_content_descs_from_elements,
)
from .config import (
    _INPUT_CLEAR_BEFORE_TEXT,
    _INPUT_CLEAR_DEL_COUNT,
    _INPUT_FOCUS_PAUSE_SEC,
    _INPUT_POST_TEXT_SUBMIT_PAUSE_SEC,
    _INPUT_SUBMIT_RESPECT_MODEL_FALSE_ON_SEARCH,
    _INPUT_SUBMIT_SEARCH_INFER,
    _SEARCH_UI_HINT_RE,
)

def _action_xy(action: dict[str, Any]) -> tuple[int, int] | None:
    if action.get("x") is None or action.get("y") is None:
        return None
    try:
        return int(action["x"]), int(action["y"])
    except (TypeError, ValueError):
        return None

def _point_inside_bounds(x: int, y: int, bounds: str) -> bool:
    m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds or "")
    if not m:
        return False
    x1, y1, x2, y2 = (int(v) for v in m.groups())
    return x1 <= x <= x2 and y1 <= y <= y2

def _coordinate_targets_visible_text_field(action: dict[str, Any], elements: list[dict[str, str]]) -> bool:
    xy = _action_xy(action)
    if xy is None:
        return False
    x, y = xy
    for e in elements:
        cn = (e.get("class_name") or "").lower()
        if "edittext" not in cn and "autocomplete" not in cn:
            continue
        if _point_inside_bounds(x, y, e.get("bounds", "")):
            return True
    return False

def _structured_execute_target_rejection(
    action: dict[str, Any],
    elements: list[dict[str, str]],
) -> str:
    """Reject non-visible structured-goal targets before coordinate fallback can fire."""
    prop_type = str(action.get("action_type") or "")
    if prop_type not in ("tap", "input"):
        return ""
    rid = str(action.get("target_resource_id") or "").strip()
    cd = str(action.get("target_content_desc") or "").strip()
    has_xy = action.get("x") is not None and action.get("y") is not None
    allowed_ids = _allowed_resource_ids_from_elements(elements)
    visible_descs = _visible_content_descs_from_elements(elements)
    if rid and rid not in allowed_ids:
        return "target_resource_id_not_visible"
    if cd and cd not in visible_descs:
        return "target_content_desc_not_visible"
    if not rid and not cd and has_xy:
        if prop_type == "input" and _coordinate_targets_visible_text_field(action, elements):
            return ""
        return "coordinate_only_target_disallowed"
    if not rid and not cd and prop_type == "tap":
        return "tap_missing_visible_target"
    return ""

def _guard_planner_action(
    action: dict[str, Any],
    elements: list[dict[str, str]],
    target_pkg: str,
    *,
    strict_visible_tap: bool,
) -> dict[str, Any]:
    """Execute/primary-UX: reject foreign-package RIDs and invisible tap targets."""
    at = str(action.get("action_type") or "wait")
    if at in ("advance_goal", "back", "wait"):
        return action
    if at == "input":
        rid = str(action.get("target_resource_id") or "").strip()
        if rid and not _resource_id_belongs_to_target_app(rid, target_pkg):
            return {"action_type": "wait", "reason": "guard_foreign_rid"}
        return action
    if at == "tap":
        rid = str(action.get("target_resource_id") or "").strip()
        if rid and not _resource_id_belongs_to_target_app(rid, target_pkg):
            pref = _resource_id_owner_package(rid)
            if (
                _package_is_permission_dialog_surface(pref)
                and _element_matches_tap_target(action, elements) is not None
            ):
                pass  # visible system permission sheet control
            else:
                return {"action_type": "wait", "reason": "guard_foreign_rid"}
        if strict_visible_tap:
            has_rid_or_cd = bool(rid or str(action.get("target_content_desc") or "").strip())
            if has_rid_or_cd and _element_matches_tap_target(action, elements) is None:
                return {"action_type": "wait", "reason": "guard_invisible_tap_target"}
            if not has_rid_or_cd:
                try:
                    xi = int(action.get("x", 0))
                    yi = int(action.get("y", 0))
                except (TypeError, ValueError):
                    return {"action_type": "wait", "reason": "guard_no_tap_target"}
                if xi <= 0 and yi <= 0:
                    return {"action_type": "wait", "reason": "guard_no_tap_target"}
        return action
    return action

def _primary_ux_scroll_coords(elements: list[dict[str, str]]) -> dict[str, int]:
    bottom = _hierarchy_max_bottom_y(elements)
    max_x = 0
    for e in elements:
        center = _bounds_center(e.get("bounds", ""))
        if center:
            max_x = max(max_x, center[0])
    cx = max(360, max_x // 2) if max_x > 400 else 540
    y1 = int(bottom * 0.72) if bottom > 400 else 1580
    y2 = int(bottom * 0.32) if bottom > 400 else 620
    return {"x1": cx, "y1": y1, "x2": cx, "y2": y2, "duration_ms": 280}

def _primary_ux_visible_tap_candidates(
    elements: list[dict[str, str]], target_pkg: str
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for e in elements:
        rid = str(e.get("resource_id") or "").strip()
        if not rid or not _resource_id_belongs_to_target_app(rid, target_pkg):
            continue
        cd = str(e.get("content_desc") or "").strip()
        probe = {"target_resource_id": rid, "target_content_desc": cd}
        if _action_is_search_like(probe) or _action_is_back_like(probe):
            continue
        cn = (e.get("class_name") or "").lower()
        if "edittext" in cn or "autocomplete" in cn:
            continue
        center = _bounds_center(e.get("bounds", ""))
        if center is None:
            continue
        out.append(
            {
                "action_type": "tap",
                "target_resource_id": rid,
                "target_content_desc": cd,
                "x": int(center[0]),
                "y": int(center[1]),
                "reason": "primary_ux_visible_tap",
            }
        )
    return out

def _pick_primary_ux_visible_tap(
    elements: list[dict[str, str]], target_pkg: str, *, rotate_offset: int = 0
) -> dict[str, Any] | None:
    cands = _primary_ux_visible_tap_candidates(elements, target_pkg)
    if not cands:
        return None
    return dict(cands[rotate_offset % len(cands)])

def _normalize_primary_ux_swipe(action: dict[str, Any], elements: list[dict[str, str]]) -> dict[str, Any]:
    out = dict(action)
    coords = _primary_ux_scroll_coords(elements)
    try:
        y1 = int(out.get("y1", coords["y1"]))
        y2 = int(out.get("y2", coords["y2"]))
    except (TypeError, ValueError):
        y1, y2 = coords["y1"], coords["y2"]
    if y1 <= y2:
        out.update(coords)
    else:
        out.setdefault("x1", coords["x1"])
        out.setdefault("x2", coords["x2"])
        out.setdefault("duration_ms", coords["duration_ms"])
    out["reason"] = str(out.get("reason") or "primary_ux_scroll")
    return out

def _sanitize_primary_ux_action(
    action: dict[str, Any],
    elements: list[dict[str, str]],
    target_pkg: str,
    *,
    stagnant: int,
    tap_rotate: int = 0,
) -> tuple[dict[str, Any], int]:
    action = _guard_planner_action(action, elements, target_pkg, strict_visible_tap=True)
    at = str(action.get("action_type") or "wait")
    reason = str(action.get("reason") or "")
    if at == "tap" and reason.startswith("guard_"):
        pick = _pick_primary_ux_visible_tap(elements, target_pkg, rotate_offset=tap_rotate)
        if pick:
            return pick, tap_rotate + 1
        swipe = {"action_type": "swipe", "reason": "primary_ux_fallback_swipe"}
        swipe.update(_primary_ux_scroll_coords(elements))
        return swipe, tap_rotate
    if at == "swipe":
        return _normalize_primary_ux_swipe(action, elements), tap_rotate
    if at == "wait" and stagnant >= 2:
        swipe = {"action_type": "swipe", "reason": "primary_ux_stagnation_swipe"}
        swipe.update(_primary_ux_scroll_coords(elements))
        return swipe, tap_rotate
    return action, tap_rotate

def _primary_ux_controller_action(
    micro_intent: dict[str, Any],
    elements: list[dict[str, str]],
    target_pkg: str,
    *,
    tap_rotate: int,
) -> tuple[dict[str, Any], int]:
    preferred = [str(x) for x in (micro_intent.get("preferred_actions") or [])]
    intent = str(micro_intent.get("intent") or "primary_micro_intent")
    if "back" in preferred and intent in ("resolve_blocking_dialog", "wait_for_content_or_recover"):
        return {"action_type": "back", "reason": f"engine_primary_{intent}"}, tap_rotate
    if "tap" in preferred:
        pick = _pick_primary_ux_visible_tap(elements, target_pkg, rotate_offset=tap_rotate)
        if pick:
            pick["reason"] = f"engine_primary_{intent}_tap"
            return pick, tap_rotate + 1
    swipe = {"action_type": "swipe", "reason": f"engine_primary_{intent}_swipe"}
    swipe.update(_primary_ux_scroll_coords(elements))
    return swipe, tap_rotate

def _escape_adb_input_text(text: str) -> str:
    """Spaces for `adb shell input text` (see Android `input text` semantics)."""
    flat = " ".join(text.splitlines()).strip()
    if not flat:
        return ""
    return flat.replace(" ", "%s")

def _input_targets_search_like_widget(action: dict[str, Any], elements: list[dict[str, str]]) -> bool:
    """Heuristic: focused widget from action matches search/query entry patterns."""
    rid_a = str(action.get("target_resource_id", "")).strip()
    cd_a = str(action.get("target_content_desc", "")).strip()
    blob_action = f"{rid_a} {cd_a}"
    if _SEARCH_UI_HINT_RE.search(blob_action):
        return True
    if rid_a:
        for e in elements:
            if e.get("resource_id") != rid_a:
                continue
            eb = " ".join(
                [
                    str(e.get("resource_id") or ""),
                    str(e.get("content_desc") or ""),
                    str(e.get("text") or ""),
                    str(e.get("class_name") or ""),
                ]
            )
            if _SEARCH_UI_HINT_RE.search(eb):
                return True
            break
    return False

def _effective_submit_search(
    action: dict[str, Any], elements: list[dict[str, str]]
) -> tuple[bool, bool]:
    """Whether to fire IME-style submit keyevents after adb input text; second flag = heuristic vs explicit true."""
    ss = action.get("submit_search")
    sb = action.get("submit")
    explicit_true = ss is True or sb is True
    explicit_false = ss is False or sb is False

    search_like = bool(_INPUT_SUBMIT_SEARCH_INFER and _input_targets_search_like_widget(action, elements))

    # Search-box typing must submit or results never refresh; local LLMs often emit submit_search:false anyway.
    if search_like:
        if explicit_false and _INPUT_SUBMIT_RESPECT_MODEL_FALSE_ON_SEARCH:
            return False, False
        return True, not explicit_true

    if explicit_true:
        return True, False
    if explicit_false:
        return False, False
    return False, False

def _adb_clear_focused_field_before_replace(adb_bin: str) -> None:
    """Clear typical single-line fields: cursor to end, then backward-delete."""
    if not _INPUT_CLEAR_BEFORE_TEXT or _INPUT_CLEAR_DEL_COUNT <= 0:
        return
    # KEYCODE_MOVE_END = 123, KEYCODE_DEL = 67
    subprocess.run([adb_bin, "shell", "input", "keyevent", "123"], check=False)
    chunk = 48
    remaining = _INPUT_CLEAR_DEL_COUNT
    while remaining > 0:
        n = min(chunk, remaining)
        subprocess.run([adb_bin, "shell", "input", "keyevent"] + ["67"] * n, check=False)
        remaining -= n
    time.sleep(0.06)

def _fallback_probe_query_for_input() -> str:
    q = os.environ.get("CONTEXTDROID_LLM_INPUT_FALLBACK_QUERY", "demo").strip()
    return q or "demo"

def _fill_tap_coords_from_element(
    action: dict[str, Any], elements: list[dict[str, str]]
) -> dict[str, Any]:
    match = _element_matches_tap_target(action, elements)
    if match is None:
        return action
    center = _bounds_center(match.get("bounds", ""))
    if center is None:
        return action
    out = dict(action)
    out["x"] = int(center[0])
    out["y"] = int(center[1])
    return out

def _score_element_for_tap_repair(
    e: dict[str, str],
    *,
    goal_hint: str,
    action_blob: str,
    digest_anchors: frozenset[str],
) -> int:
    rid = str(e.get("resource_id") or "").strip()
    cd = str(e.get("content_desc") or "").strip()
    txt = str(e.get("text") or "").strip()
    cn = (e.get("class_name") or "").lower()
    blob = f"{rid} {cd} {txt}".lower()
    score = 0
    if "edittext" in cn or "autocomplete" in cn:
        score += 3
    if any(k in blob for k in ("fab_search", "search")):
        score += 8
    if any(k in blob for k in ("categories", "latest", "nearby", "updates", "settings")):
        score += 6
    for anchor in digest_anchors:
        if anchor in blob:
            score += 4
    if goal_hint:
        for tok in re.findall(r"[a-z][a-z0-9_]{2,}", goal_hint):
            if tok in ("tap", "open", "press", "click", "select", "input", "type", "the", "and"):
                continue
            if tok in blob:
                score += 7
    if action_blob:
        for tok in re.findall(r"[a-z][a-z0-9_]{2,}", action_blob):
            if tok in blob:
                score += 5
    return score

def _pick_permission_dialog_tap(
    elements: list[dict[str, str]], target_pkg: str, *, prefer_deny: bool
) -> dict[str, Any] | None:
    allow_priority = (
        "permission_allow_foreground_only",
        "permission_allow_one_time",
        "permission_allow_always",
        "permission_allow",
        "allow_button",
        "button1",
    )
    deny_markers = ("permission_deny", "deny_button", "button2")
    scored: list[tuple[tuple[int, str], dict[str, Any]]] = []
    for e in elements:
        if not _element_is_permission_dialog_widget(e, target_pkg):
            continue
        center = _bounds_center(e.get("bounds", ""))
        if center is None:
            continue
        rid = str(e.get("resource_id") or "").strip()
        cd = str(e.get("content_desc") or "").strip()
        text = str(e.get("text") or "").strip()
        blob = f"{rid} {cd} {text}".lower()
        if prefer_deny:
            if any(m in blob for m in deny_markers) or "don't allow" in blob or "dont allow" in blob:
                pri = 0
            elif any(w in blob for w in ("allow", "ok", "continue", "accept")):
                pri = 80
            else:
                pri = 40
        else:
            pri = 40
            for i, pat in enumerate(allow_priority):
                if pat in blob:
                    pri = i
                    break
            else:
                if any(m in blob for m in deny_markers):
                    pri = 60
                elif any(w in blob for w in ("allow", "ok", "continue", "accept", "while using")):
                    pri = 15
        act = {
            "action_type": "tap",
            "target_resource_id": rid,
            "target_content_desc": cd,
            "x": int(center[0]),
            "y": int(center[1]),
            "reason": "tap_repair_permission_dialog",
        }
        scored.append(((pri, _action_signature_for_candidate(act)), act))
    if not scored:
        return None
    scored.sort(key=lambda item: item[0])
    return dict(scored[0][1])

def _repair_tap_action_for_execution(
    action: dict[str, Any],
    elements: list[dict[str, str]],
    *,
    ux_goals: list[str] | None,
    ux_goal_idx: int,
    navigation_digest_text: str | None,
    target_pkg: str,
) -> dict[str, Any]:
    """Retarget missing tap RIDs to visible controls (search FAB, tabs, permission buttons)."""
    if str(action.get("action_type") or "") != "tap":
        return action
    if _element_matches_tap_target(action, elements) is not None:
        return _fill_tap_coords_from_element(action, elements)

    goal_hint = _goal_hint_for_repair(ux_goals, ux_goal_idx)
    action_blob = " ".join(
        (
            str(action.get("target_resource_id") or ""),
            str(action.get("target_content_desc") or ""),
            str(action.get("reason") or ""),
        )
    ).lower()
    digest_anchors = (
        _screen_map_anchors(navigation_digest_text)
        if navigation_digest_text
        else frozenset()
    )

    wants_deny = any(k in goal_hint for k in ("deny", "reject", "don't allow", "do not allow"))
    wants_allow = any(k in goal_hint for k in ("allow", "grant", "accept", "ok"))
    if (wants_deny or wants_allow) and _hierarchy_shows_permission_dialog(elements, target_pkg):
        pick = _pick_permission_dialog_tap(elements, target_pkg, prefer_deny=wants_deny and not wants_allow)
        if pick:
            logging.info(
                "Retargeted permission tap (goal=%r) to visible dialog control %s.",
                ux_goals[ux_goal_idx] if ux_goals else "?",
                pick.get("target_resource_id"),
            )
            return pick

    if _goal_opens_search_ui(goal_hint):
        search_scored: list[tuple[int, dict[str, str]]] = []
        for e in elements:
            if _resource_id_owner_package(str(e.get("resource_id") or "")) not in ("", target_pkg):
                continue
            cn = (e.get("class_name") or "").lower()
            if "edittext" in cn:
                continue
            blob = f'{e.get("resource_id") or ""} {e.get("content_desc") or ""}'.lower()
            score = 0
            if "fab_search" in blob:
                score += 20
            if "scanbutton" in blob:
                score += 18
            if "search" in blob and "button" in blob:
                score += 14
            if e.get("content_desc", "").strip().lower() == "search":
                score += 12
            if score > 0:
                search_scored.append((score, e))
        search_scored.sort(key=lambda x: -x[0])
        if search_scored:
            e = search_scored[0][1]
            center = _bounds_center(e.get("bounds", ""))
            if center:
                logging.info(
                    "Retargeted search-open tap to visible control %s.",
                    e.get("resource_id"),
                )
                return {
                    "action_type": "tap",
                    "target_resource_id": str(e.get("resource_id") or "").strip(),
                    "target_content_desc": str(e.get("content_desc") or "").strip(),
                    "x": int(center[0]),
                    "y": int(center[1]),
                    "reason": "tap_repair_search_open",
                }

    scored_elems: list[tuple[int, dict[str, str]]] = []
    for e in elements:
        pref = _resource_id_owner_package(str(e.get("resource_id") or ""))
        if pref and pref != target_pkg and not _package_is_permission_dialog_surface(pref):
            continue
        center = _bounds_center(e.get("bounds", ""))
        if center is None:
            continue
        cn = (e.get("class_name") or "").lower()
        clickable = str(e.get("clickable") or "").lower() in ("true", "1")
        if not clickable and "button" not in cn and "tab" not in cn:
            continue
        score = _score_element_for_tap_repair(
            e, goal_hint=goal_hint, action_blob=action_blob, digest_anchors=digest_anchors
        )
        if score > 0:
            scored_elems.append((score, e))
    scored_elems.sort(key=lambda x: -x[0])
    if scored_elems:
        e = scored_elems[0][1]
        center = _bounds_center(e.get("bounds", ""))
        if center:
            logging.info(
                "Retargeted tap from absent rid=%s to visible %s (score=%d).",
                action.get("target_resource_id") or "(none)",
                e.get("resource_id"),
                scored_elems[0][0],
            )
            return {
                "action_type": "tap",
                "target_resource_id": str(e.get("resource_id") or "").strip(),
                "target_content_desc": str(e.get("content_desc") or "").strip(),
                "x": int(center[0]),
                "y": int(center[1]),
                "reason": "tap_repair_visible_match",
            }
    return action

def _repair_input_action_for_execution(
    action: dict[str, Any],
    elements: list[dict[str, str]],
    *,
    ux_goals: list[str] | None,
    ux_goal_idx: int,
) -> dict[str, Any]:
    """Fill empty LLM `input` text and retarget missing resource_ids to visible query fields."""
    if str(action.get("action_type")) != "input":
        return action
    out = dict(action)

    txt = out.get("text")
    needs_fill = txt is None or not str(txt).strip()
    goal_hint = ""
    if ux_goals and 0 <= ux_goal_idx < len(ux_goals):
        goal_hint = ux_goals[ux_goal_idx].lower()
    typing_goal = any(
        k in goal_hint for k in ("enter", "type", "input", "search", "query", "package", "find", "filter")
    )
    if needs_fill and typing_goal:
        out["text"] = _fallback_probe_query_for_input()
        logging.info(
            "Repaired empty input text for UX goal (%s); using CONTEXTDROID_LLM_INPUT_FALLBACK_QUERY.",
            ux_goals[ux_goal_idx] if ux_goals else "?",
        )

    rid = str(out.get("target_resource_id", "")).strip()
    rid_present = bool(rid) and any(e.get("resource_id") == rid for e in elements)
    if rid_present or not elements:
        return out

    scored: list[tuple[int, dict[str, str]]] = []
    for e in elements:
        cn = (e.get("class_name") or "").lower()
        blob = f'{e.get("resource_id") or ""} {e.get("content_desc") or ""}'
        score = 0
        if "edittext" in cn or "autocomplete" in cn:
            score += 20
        elif "fab_search" in blob.lower():
            score = 0
        elif _SEARCH_UI_HINT_RE.search(blob):
            score += 3
        if score > 0:
            scored.append((score, e))
    scored.sort(key=lambda x: -x[0])
    if scored:
        pick_rid = str(scored[0][1].get("resource_id") or "").strip()
        if pick_rid:
            logging.info(
                "Retargeted input action from absent rid=%s to visible field %s.",
                rid or "(none)",
                pick_rid,
            )
            out["target_resource_id"] = pick_rid
    return out

def _adb_submit_after_input(adb_bin: str, *, search_like: bool) -> str:
    """Best-effort submit after injected text.

    `adb shell input text` does not press soft-keyboard keys; it fills the focused field directly.
    The IME \"Search\" chip is often IME_ACTION_SEARCH — plain ENTER (66) may not route there on some
    keyboards; TAB (61) + ENTER (66) commonly activates the IME action bar first (see SO #28366720).
    """
    time.sleep(max(0.0, _INPUT_POST_TEXT_SUBMIT_PAUSE_SEC))
    raw = os.environ.get("CONTEXTDROID_LLM_INPUT_SUBMIT_KEYSEQUENCE", "").strip().lower()
    if raw in _SUBMIT_SEQ_ALLOWED:
        seq = raw
    elif raw == "":
        # Try plain ENTER then IME action (TAB+ENTER); closer to tapping keyboard Search on many OEM IMEs.
        seq = "enter_then_tab_enter" if search_like else "enter"
    else:
        seq = "enter"

    def _keyevent(code: str) -> None:
        subprocess.run([adb_bin, "shell", "input", "keyevent", code], check=False)

    if seq == "enter":
        _keyevent("66")
        return "keyevent_enter"
    if seq == "tab_enter":
        _keyevent("61")
        time.sleep(0.06)
        _keyevent("66")
        return "keyevent_tab_enter"
    if seq == "enter_then_tab_enter":
        _keyevent("66")
        time.sleep(0.14)
        _keyevent("61")
        time.sleep(0.06)
        _keyevent("66")
        return "keyevent_enter_then_tab_enter"
    _keyevent("84")
    return "keyevent_search"

def _tap_xy_if_present(adb_bin: str, action: dict[str, Any]) -> tuple[bool, str] | None:
    if action.get("x") is None or action.get("y") is None:
        return None
    try:
        x = int(action["x"])
        y = int(action["y"])
    except (TypeError, ValueError):
        return None
    rc = subprocess.run([adb_bin, "shell", "input", "tap", str(x), str(y)], check=False).returncode
    if rc == 0:
        return True, f"tap_xy:{x},{y}"
    return False, "tap_xy_failed"

def _tap_from_action(adb_bin: str, action: dict[str, Any], elements: list[dict[str, str]]) -> tuple[bool, str]:
    rid = str(action.get("target_resource_id", "")).strip()
    cdesc = str(action.get("target_content_desc", "")).strip()
    if rid or cdesc:
        for e in elements:
            if rid and e.get("resource_id") == rid:
                center = _bounds_center(e.get("bounds", ""))
                if center:
                    rc = subprocess.run(
                        [adb_bin, "shell", "input", "tap", str(center[0]), str(center[1])], check=False
                    ).returncode
                    return rc == 0, f"tap_rid:{rid}"
            if cdesc and e.get("content_desc") == cdesc:
                center = _bounds_center(e.get("bounds", ""))
                if center:
                    rc = subprocess.run(
                        [adb_bin, "shell", "input", "tap", str(center[0]), str(center[1])], check=False
                    ).returncode
                    return rc == 0, f"tap_desc:{cdesc}"
        # Widget absent after transitions (e.g. FAB hidden when search overlay opens): use coordinates.
        xy = _tap_xy_if_present(adb_bin, action)
        if xy is not None:
            ok, note = xy
            if ok:
                return True, f"{note}_fallback_rid_missing"
            return False, "target_not_found_xy_failed"
        return False, "target_not_found"
    xy_only = _tap_xy_if_present(adb_bin, action)
    if xy_only is not None:
        ok, note = xy_only
        return ok, note
    return False, "no_tap_target"

def _execute_action(adb_bin: str, action: dict[str, Any], elements: list[dict[str, str]]) -> tuple[bool, str]:
    a_type = str(action.get("action_type", "wait"))
    if a_type == "advance_goal":
        return True, "advance_goal"
    if a_type == "back":
        rc = subprocess.run([adb_bin, "shell", "input", "keyevent", "4"], check=False).returncode
        return rc == 0, "back"
    if a_type == "input":
        raw_txt = action.get("text")
        if raw_txt is None:
            return False, "missing_text"
        text = str(raw_txt)
        if not text.strip():
            return False, "missing_text"
        wants_focus = bool(
            str(action.get("target_resource_id", "")).strip()
            or str(action.get("target_content_desc", "")).strip()
            or (action.get("x") is not None and action.get("y") is not None)
        )
        tap_ok = False
        tap_note = "no_tap_target"
        if wants_focus:
            tap_ok, tap_note = _tap_from_action(adb_bin, action, elements)
            if tap_ok:
                time.sleep(max(0.05, _INPUT_FOCUS_PAUSE_SEC))
            elif tap_note == "target_not_found":
                logging.info("Input focus tap missed (%s); typing anyway.", tap_note)
                time.sleep(0.12)
        if wants_focus:
            _adb_clear_focused_field_before_replace(adb_bin)
        escaped = _escape_adb_input_text(text)
        if not escaped:
            return False, "missing_text"
        rc = subprocess.run([adb_bin, "shell", "input", "text", escaped], check=False).returncode
        typed = rc == 0
        outcome_bits = [tap_note if wants_focus else "focus_skip", f"text:{text[:120]}"]
        submit, submit_inferred = _effective_submit_search(action, elements)
        search_like_target = _input_targets_search_like_widget(action, elements)
        if typed and submit:
            submit_note = _adb_submit_after_input(adb_bin, search_like=search_like_target)
            outcome_bits.append(submit_note + ("_inferred" if submit_inferred else ""))
        return typed, ";".join(outcome_bits)

    if a_type == "tap":
        ok, outcome = _tap_from_action(adb_bin, action, elements)
        return ok, outcome
    if a_type == "swipe":
        try:
            x1 = int(action.get("x1", action.get("x", 540)))
            y1 = int(action.get("y1", 1650))
            x2 = int(action.get("x2", action.get("x", 540)))
            y2 = int(action.get("y2", 750))
        except (TypeError, ValueError):
            return False, "swipe_bad_coords"
        dur = action.get("duration_ms")
        cmd = [adb_bin, "shell", "input", "swipe", str(x1), str(y1), str(x2), str(y2)]
        if dur is not None:
            try:
                cmd.append(str(max(1, int(dur))))
            except (TypeError, ValueError):
                cmd.append("220")
        rc = subprocess.run(cmd, check=False).returncode
        note = f"swipe:{x1},{y1}->{x2},{y2}"
        if dur is not None:
            note += f";{dur}"
        return rc == 0, note
    time.sleep(0.5)
    return True, "wait"
