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
from .device import (
    _foreground_package,
    _hierarchy_dominant_foreign_package,
    _restart_target_root,
    _should_recover_from_foreign_app,
    _start_target_root_activity,
)
from .dialogs import _hierarchy_shows_permission_dialog
from .screen import (
    _dump_filtered_screen,
    _filter_widgets_for_target,
    _resource_id_owner_package,
    _screen_digest_hint,
    _screen_hash,
    _screen_root_signature,
    _target_app_widget_count,
    dump_clean_screen,
)
from .config import (
    _HANDOFF_EXPLORE_SETTLED_MIN_LANDMARK,
    _HANDOFF_EXPLORE_SETTLED_MIN_VISITS,
    _ROOT_CAPTURE_DEADLINE_SEC,
    _ROOT_HANDOFF_ATTEMPTS,
    _ROOT_HANDOFF_BACK_STEPS,
    _ROOT_HANDOFF_CLEAR_TASK,
    _ROOT_HANDOFF_RELAUNCH,
    _env_int,
)

def _screen_root_landmark_score(elements: list[dict[str, str]], target_pkg: str) -> int:
    """Generic root/home-ish score from visible app-owned navigation landmarks."""
    score = 0
    seen: set[str] = set()
    nav_tokens = (
        "home",
        "main",
        "feed",
        "browse",
        "search",
        "settings",
        "profile",
        "account",
        "categories",
        "category",
        "latest",
        "updates",
        "nearby",
        "favorites",
        "library",
        "tab",
        "bottom",
        "navigation",
        "backup",
        "install",
        "installer",
        "menu",
        "toggle",
        "passive",
        "active",
        "inspector",
        "button",
    )
    for e in elements:
        rid = str(e.get("resource_id") or "").strip()
        node_pkg = str(e.get("package") or "").strip()
        pref = _resource_id_owner_package(rid)
        if node_pkg and node_pkg != target_pkg and pref != target_pkg:
            continue
        blob = " ".join(
            (
                rid,
                str(e.get("content_desc") or ""),
                str(e.get("text") or ""),
                str(e.get("class_name") or ""),
            )
        ).lower()
        for token in nav_tokens:
            if token in blob and token not in seen:
                seen.add(token)
                score += 1
    return score

def _screen_is_valid_execute_root(
    elements: list[dict[str, str]],
    *,
    raw_xml: str,
    target_pkg: str,
) -> tuple[bool, str]:
    if not elements:
        return False, "empty_hierarchy"
    hier_pkg = _hierarchy_dominant_foreign_package(raw_xml, target_pkg)
    if hier_pkg and hier_pkg != target_pkg:
        return False, f"foreign_hierarchy:{hier_pkg}"
    if _hierarchy_shows_permission_dialog(elements, target_pkg):
        return False, "permission_dialog"
    if _target_app_widget_count(elements, target_pkg) <= 0:
        return False, "no_target_widgets"
    return True, "ok"

def _evaluate_execute_root_candidate(
    elements: list[dict[str, str]],
    *,
    raw_xml: str,
    target_pkg: str,
    expected_root_hash: str,
    expected_root_signature: str = "",
) -> tuple[bool, str, str]:
    valid, reason = _screen_is_valid_execute_root(
        elements, raw_xml=raw_xml, target_pkg=target_pkg
    )
    if not valid:
        return False, reason, "invalid"
    screen_hash = _screen_hash(elements)
    if expected_root_hash and screen_hash == expected_root_hash:
        return True, "root_handoff_ok_exact", "exact"
    screen_signature = _screen_root_signature(elements, target_pkg)
    if expected_root_signature and screen_signature == expected_root_signature:
        return True, "root_handoff_ok_signature", "signature"
    if expected_root_hash or expected_root_signature:
        return False, "not_original_root_home", "valid_non_root"
    landmark_score = _screen_root_landmark_score(elements, target_pkg)
    if landmark_score >= 2:
        return True, f"root_handoff_ok_landmarks:{landmark_score}", "landmarks"
    return True, "root_handoff_ok_valid_no_reference", "valid_no_reference"

def _capture_execute_root_reference(adb_bin: str, package_name: str) -> dict[str, Any]:
    """Start the launcher/root activity and capture the screen navigation begins from."""
    deadline = time.monotonic() + _ROOT_CAPTURE_DEADLINE_SEC
    try:
        if _ROOT_HANDOFF_RELAUNCH:
            if time.monotonic() >= deadline:
                return {"ok": False, "reason": "root_reference_capture_timeout"}
            _restart_target_root(adb_bin, package_name)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {"ok": False, "reason": "root_reference_capture_timeout"}
        elements, screen_hash, raw_xml = _dump_filtered_screen(
            adb_bin,
            package_name,
            timeout_sec=max(1.0, remaining),
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"ok": False, "reason": f"root_reference_capture_error:{type(exc).__name__}"}
    if time.monotonic() >= deadline:
        return {"ok": False, "reason": "root_reference_capture_timeout"}
    ok, reason = _screen_is_valid_execute_root(elements, raw_xml=raw_xml, target_pkg=package_name)
    if not ok:
        return {
            "ok": False,
            "reason": reason,
            "screen_hash": screen_hash,
            "interactive_count": len(elements),
        }
    return {
        "ok": True,
        "reason": "root_reference_captured",
        "elements": elements,
        "screen_hash": screen_hash,
        "root_signature": _screen_root_signature(elements, package_name),
        "root_hint": _screen_digest_hint(elements),
        "interactive_count": len(elements),
    }

def _root_handoff_recovery_actions(
    nav_transitions: list[dict[str, Any]],
    *,
    expected_root_hash: str,
    target_pkg: str,
    max_n: int = 4,
) -> list[dict[str, Any]]:
    """Learn app-owned actions that returned exploration to the canonical root screen."""
    if not expected_root_hash:
        return []
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    nav_tokens = (
        "home",
        "latest",
        "categories",
        "updates",
        "settings",
        "nearby",
        "browse",
        "main",
        "backup",
        "install",
        "installer",
        "menu",
        "toggle",
        "passive",
        "active",
        "inspector",
        "button",
    )
    for tr in nav_transitions:
        if not tr.get("ok") or tr.get("to") != expected_root_hash:
            continue
        action = tr.get("action") or {}
        if str(action.get("action_type") or "") != "tap":
            continue
        rid = str(action.get("target_resource_id") or "").strip()
        cd = str(action.get("target_content_desc") or "").strip()
        if not rid and not cd:
            continue
        owner_pkg = _resource_id_owner_package(rid)
        if owner_pkg and owner_pkg != target_pkg:
            continue
        blob = f"{rid} {cd}".lower()
        if not any(tok in blob for tok in nav_tokens):
            continue
        key = (rid, cd)
        if key in seen:
            continue
        seen.add(key)
        recovered = {
            "action_type": "tap",
            "target_resource_id": rid,
            "target_content_desc": cd,
            "x": action.get("x"),
            "y": action.get("y"),
            "reason": f"root_handoff_recovery:{action.get('reason') or 'learned_transition'}",
        }
        out.append(recovered)
        if len(out) >= max_n:
            break
    return out

def _try_explore_settled_handoff(
    adb_bin: str,
    package_name: str,
    *,
    nav_visited_counts: dict[str, int] | None,
    attempts: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Accept a well-explored hub when launch-time hash no longer matches after BFS (utility/installer apps)."""
    if not nav_visited_counts or not attempts:
        return None
    last_hash = str(attempts[-1].get("screen_hash") or "")
    last_visits = int(nav_visited_counts.get(last_hash) or 0)
    if not last_hash or last_visits < _HANDOFF_EXPLORE_SETTLED_MIN_VISITS:
        return None
    elements, screen_hash, raw_xml = _dump_filtered_screen(adb_bin, package_name)
    valid, valid_reason = _screen_is_valid_execute_root(
        elements, raw_xml=raw_xml, target_pkg=package_name
    )
    if not valid:
        return None
    landmark = _screen_root_landmark_score(elements, package_name)
    if landmark < _HANDOFF_EXPLORE_SETTLED_MIN_LANDMARK:
        return None
    logging.info(
        "Root handoff explore-settled accept (hash=%s visits=%d landmark=%d).",
        screen_hash[:16],
        last_visits,
        landmark,
    )
    return {
        "ok": True,
        "reason": f"root_handoff_ok_explore_settled:{last_visits}:{landmark}",
        "elements": elements,
        "screen_hash": screen_hash,
        "raw_xml": raw_xml,
        "attempts": attempts,
        "match_kind": "explore_settled",
    }

def _restore_execute_root_screen(
    adb_bin: str,
    package_name: str,
    *,
    expected_root_hash: str = "",
    expected_root_signature: str = "",
    root_recovery_actions: list[dict[str, Any]] | None = None,
    nav_visited_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Actively restore the target root/home screen before execute."""
    attempts: list[dict[str, Any]] = []
    strategies: list[tuple[str, bool, bool]] = []
    learned_recovery_actions = root_recovery_actions or []
    if _ROOT_HANDOFF_RELAUNCH:
        strategies.append(("start_root_activity", False, False))
        # Soft relaunch preserves the activity stack; clear_task resets to launcher root.
        strategies.append(("start_root_activity_clear_task", True, False))
    strategies.extend(("back_toward_root", False, True) for _ in range(_ROOT_HANDOFF_BACK_STEPS))
    if _ROOT_HANDOFF_CLEAR_TASK:
        strategies.append(("start_root_activity_clear_task_repeat", True, False))
    if not strategies:
        strategies.append(("validate_current", False, False))

    max_attempts = max(_ROOT_HANDOFF_ATTEMPTS, len(strategies))
    for i in range(max_attempts):
        strategy, clear_task, send_back = strategies[min(i, len(strategies) - 1)]
        if send_back:
            subprocess.run(
                [adb_bin, "shell", "input", "keyevent", "4"],
                check=False,
                capture_output=True,
                timeout=8,
            )
            time.sleep(0.8)
        elif strategy.startswith("start_root_activity"):
            _start_target_root_activity(adb_bin, package_name, clear_task=clear_task)
            time.sleep(1.0 if clear_task else 0.8)
        elif i > 0:
            time.sleep(0.8)
        fg = _foreground_package(adb_bin)
        if fg and fg != package_name and _should_recover_from_foreign_app(package_name, fg):
            _start_target_root_activity(adb_bin, package_name, clear_task=clear_task)
            time.sleep(0.8)
        elements, screen_hash, raw_xml = _dump_filtered_screen(adb_bin, package_name)
        ok, reason, match_kind = _evaluate_execute_root_candidate(
            elements,
            raw_xml=raw_xml,
            target_pkg=package_name,
            expected_root_hash=expected_root_hash,
            expected_root_signature=expected_root_signature,
        )
        screen_signature = _screen_root_signature(elements, package_name)
        attempts.append(
            {
                "attempt": i + 1,
                "strategy": strategy,
                "clear_task": clear_task,
                "foreground_package": fg,
                "screen_hash": screen_hash,
                "interactive_count": len(elements),
                "valid": ok,
                "reason": reason,
                "match_kind": match_kind,
                "root_hash_match": match_kind == "exact",
                "root_signature_match": match_kind == "signature",
                "screen_root_signature": screen_signature,
                "root_landmark_score": _screen_root_landmark_score(elements, package_name),
            }
        )
        if ok:
            return {
                "ok": True,
                "reason": reason,
                "elements": elements,
                "screen_hash": screen_hash,
                "raw_xml": raw_xml,
                "attempts": attempts,
                "match_kind": match_kind,
            }
        if match_kind == "valid_non_root" and learned_recovery_actions:
            for recovery_action in learned_recovery_actions:
                action_ok, action_outcome = _execute_action(adb_bin, recovery_action, elements)
                time.sleep(0.8)
                rec_elements, rec_screen_hash, rec_raw_xml = _dump_filtered_screen(adb_bin, package_name)
                rec_ok, rec_reason, rec_match_kind = _evaluate_execute_root_candidate(
                    rec_elements,
                    raw_xml=rec_raw_xml,
                    target_pkg=package_name,
                    expected_root_hash=expected_root_hash,
                    expected_root_signature=expected_root_signature,
                )
                rec_screen_signature = _screen_root_signature(rec_elements, package_name)
                attempts.append(
                    {
                        "attempt": i + 1,
                        "strategy": "learned_root_recovery_action",
                        "parent_strategy": strategy,
                        "clear_task": clear_task,
                        "foreground_package": _foreground_package(adb_bin),
                        "recovery_action": recovery_action,
                        "recovery_action_ok": action_ok,
                        "recovery_action_outcome": action_outcome,
                        "screen_hash": rec_screen_hash,
                        "interactive_count": len(rec_elements),
                        "valid": rec_ok,
                        "reason": rec_reason,
                        "match_kind": rec_match_kind,
                        "root_hash_match": rec_match_kind == "exact",
                        "root_signature_match": rec_match_kind == "signature",
                        "screen_root_signature": rec_screen_signature,
                        "root_landmark_score": _screen_root_landmark_score(rec_elements, package_name),
                    }
                )
                if rec_ok:
                    return {
                        "ok": True,
                        "reason": rec_reason,
                        "elements": rec_elements,
                        "screen_hash": rec_screen_hash,
                        "raw_xml": rec_raw_xml,
                        "attempts": attempts,
                        "match_kind": rec_match_kind,
                    }
    if (expected_root_hash or expected_root_signature) and attempts:
        best_landmark = 0
        for att in attempts:
            if att.get("match_kind") != "valid_non_root":
                continue
            best_landmark = max(best_landmark, int(att.get("root_landmark_score") or 0))
        pragmatic_min = _env_int("CONTEXTDROID_LLM_HANDOFF_PRAGMATIC_LANDMARK_MIN", 4, minimum=2)
        if best_landmark >= pragmatic_min:
            _start_target_root_activity(adb_bin, package_name, clear_task=False)
            time.sleep(1.0)
            elements, screen_hash, raw_xml = _dump_filtered_screen(adb_bin, package_name)
            valid, valid_reason = _screen_is_valid_execute_root(
                elements, raw_xml=raw_xml, target_pkg=package_name
            )
            landmark = _screen_root_landmark_score(elements, package_name)
            if valid and landmark >= pragmatic_min:
                logging.info(
                    "Root handoff pragmatic accept (landmark=%d, min=%d) after failed exact recovery.",
                    landmark,
                    pragmatic_min,
                )
                return {
                    "ok": True,
                    "reason": f"root_handoff_ok_pragmatic_landmarks:{landmark}",
                    "elements": elements,
                    "screen_hash": screen_hash,
                    "raw_xml": raw_xml,
                    "attempts": attempts,
                    "match_kind": "pragmatic_landmarks",
                }
    settled = _try_explore_settled_handoff(
        adb_bin,
        package_name,
        nav_visited_counts=nav_visited_counts,
        attempts=attempts,
    )
    if settled is not None:
        return settled
    return {
        "ok": False,
        "reason": attempts[-1]["reason"] if attempts else "no_attempts",
        "elements": [],
        "screen_hash": "",
        "raw_xml": "",
        "attempts": attempts,
    }

def _recover_empty_execute_screen(
    adb_bin: str,
    package_name: str,
    *,
    attempts_used: int,
) -> dict[str, Any]:
    """Observation recovery for empty/unknown execute screens; no blind swipes."""
    if attempts_used == 0:
        time.sleep(0.8)
        reason = "empty_execute_wait_redump"
    elif attempts_used == 1:
        subprocess.run(
            [adb_bin, "shell", "input", "keyevent", "4"],
            check=False,
            capture_output=True,
            timeout=8,
        )
        time.sleep(0.8)
        reason = "empty_execute_back_once"
    else:
        _restart_target_root(adb_bin, package_name)
        time.sleep(0.8)
        reason = "empty_execute_relaunch_root"
    elements, _, raw_xml = dump_clean_screen(adb_bin)
    elements = _filter_widgets_for_target(elements, package_name)
    screen_hash = _screen_hash(elements)
    ok, screen_reason = _screen_is_valid_execute_root(
        elements, raw_xml=raw_xml, target_pkg=package_name
    )
    if ok and not elements:
        ok = False
        screen_reason = "empty_hierarchy_after_validation"
    return {
        "ok": ok,
        "reason": reason,
        "screen_reason": screen_reason,
        "elements": elements,
        "screen_hash": screen_hash,
        "raw_xml": raw_xml,
    }
