"""Explore-phase candidate instrumentation (logging only; no selection behavior)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .action_model import _nav_target_key
from .screen import _bounds_center

EXPLORE_RECOVERY_REASONS = frozenset({"bfs_return_to_hub", "bfs_avoid_back_loop"})

_LOW_SIGNAL_FRIDA_CATEGORIES = frozenset({"reflection", "lifecycle", "unknown"})
_FRAMEWORK_FRIDA_APIS = frozenset({"hook_loaded", "Method.invoke"})

# Tier indices aligned with remediation_plan.md Step 5 table.
_TIER_BY_REASON: dict[str, int] = {
    "bfs_system_dialog_dismiss": 0,
    "dialog_policy_recover_to_target": 0,
    "bfs_expand_after_tab_switch": 1,
    "bfs_graph_uncovered_tab": 2,
    "bfs_graph_uncovered_nav": 2,
    "bfs_tab_frontier": 3,
    "bfs_nav_frontier": 4,
    "bfs_nav_visible_fallback": 5,
    "bfs_expand_frontier": 6,
    "bfs_leave_permission_overlay": 7,
    "bfs_expand_layer_depth": 8,
    "bfs_nav_cycle_after_exhaust": 9,
    "bfs_search_after_frontier": 9,
    "bfs_text_entry_probe": 9,
    "bfs_return_to_hub": 10,
    "bfs_avoid_back_loop": 10,
}

# Recovery-step element snapshots only; non-recovery explore steps log counts.
_RECOVERY_SNAPSHOT_MAX_ELEMENTS = 48


def explore_tier_index_for_reason(reason: str) -> int | None:
    rr = str(reason or "").strip()
    if not rr:
        return None
    if rr in _TIER_BY_REASON:
        return _TIER_BY_REASON[rr]
    if rr.startswith("bfs_expand_"):
        return 8
    return None


def _element_tap_key(element: dict[str, str]) -> str | None:
    center = _bounds_center(element.get("bounds", ""))
    if center is None:
        return None
    return _nav_target_key(
        {
            "action_type": "tap",
            "target_resource_id": str(element.get("resource_id") or "").strip(),
            "target_content_desc": str(element.get("content_desc") or "").strip(),
            "x": int(center[0]),
            "y": int(center[1]),
        }
    )


def _candidate_keys(candidates: list[dict[str, Any]]) -> set[str]:
    return {_nav_target_key(c) for c in candidates}


def _effective_clickable(element: dict[str, str]) -> bool:
    """Elements in the instrumentation list already passed _is_visible_and_interactive."""
    clickable_raw = str(element.get("clickable") or "").lower()
    if clickable_raw in ("true", "1"):
        return True
    if clickable_raw in ("false", "0"):
        return False
    return True


def _trim_snapshot_element(element: dict[str, str], bucket: str) -> dict[str, Any]:
    return {
        "class": str(element.get("class_name") or ""),
        "bounds": str(element.get("bounds") or ""),
        "clickable": _effective_clickable(element),
        "has_rid": bool(str(element.get("resource_id") or "").strip()),
        "has_cd": bool(str(element.get("content_desc") or "").strip()),
        "has_text": bool(str(element.get("text") or "").strip()),
        "bucket": bucket,
    }


def build_explore_candidate_instrumentation(
    elements: list[dict[str, str]],
    nav_cands: list[dict[str, Any]],
    other_cands: list[dict[str, Any]],
    expand_cands: list[dict[str, Any]],
    tab_cands: list[dict[str, Any]],
    *,
    screen_hash: str,
    recovery_step: bool = False,
) -> dict[str, Any]:
    """Summarize in-memory candidate buckets for JSONL logging.

    ``elements`` is the same post-filter list used for ``interactive_element_count``
    (visible + interactive hierarchy nodes). ``skipped_interactive`` counts members of
    that list that map to no nav/tab/expand/other candidate bucket.
    """
    tab_keys = _candidate_keys(tab_cands)
    nav_keys = _candidate_keys(nav_cands)
    expand_keys = _candidate_keys(expand_cands)
    other_keys = _candidate_keys(other_cands)

    snapshot_elements: list[dict[str, Any]] = []
    skipped_interactive = 0
    max_snapshot_elements = _RECOVERY_SNAPSHOT_MAX_ELEMENTS if recovery_step else 0

    for element in elements:
        key = _element_tap_key(element)
        if key is None:
            skipped_interactive += 1
            if len(snapshot_elements) < max_snapshot_elements:
                snapshot_elements.append(_trim_snapshot_element(element, "none"))
            continue
        if key in tab_keys:
            bucket = "tab"
        elif key in nav_keys:
            bucket = "nav"
        elif key in expand_keys:
            bucket = "expand"
        elif key in other_keys:
            bucket = "other"
        else:
            bucket = "none"
            skipped_interactive += 1
        if len(snapshot_elements) < max_snapshot_elements:
            snapshot_elements.append(_trim_snapshot_element(element, bucket))

    out: dict[str, Any] = {
        "explore_candidate_counts": {
            "nav_cands": len(nav_cands),
            "other_cands": len(other_cands),
            "expand_cands": len(expand_cands),
            "tab_cands": len(tab_cands),
            "skipped_interactive": skipped_interactive,
        },
    }
    if recovery_step:
        out["element_snapshot"] = {
            "screen_hash": screen_hash,
            "elements": snapshot_elements,
            "truncated": len(elements) > len(snapshot_elements),
        }
    return out


def is_explore_recovery_action(action: dict[str, Any] | None) -> bool:
    if not action:
        return False
    reason = str(action.get("reason") or "")
    return reason in EXPLORE_RECOVERY_REASONS


def _is_meaningful_frida_event(category: str, api: str) -> bool:
    if category in _LOW_SIGNAL_FRIDA_CATEGORIES:
        return False
    if api in _FRAMEWORK_FRIDA_APIS:
        return False
    return True


def frida_log_byte_offset(frida_log_path: Path) -> int:
    if not frida_log_path.is_file():
        return 0
    return frida_log_path.stat().st_size


def frida_meaningful_in_log_slice(
    text: str,
    *,
    window_start_ms: int,
    window_end_ms: int,
) -> bool:
    """True if any meaningful Frida event in text falls within [window_start_ms, window_end_ms]."""
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type", "event") != "event":
            continue
        ts = obj.get("timestamp")
        if ts is None:
            continue
        ts_i = int(ts)
        if ts_i < window_start_ms or ts_i > window_end_ms:
            continue
        cat = str(obj.get("category") or "")
        api = str(obj.get("api") or "")
        if _is_meaningful_frida_event(cat, api):
            return True
    return False


def read_frida_log_slice(frida_log_path: Path, byte_offset: int) -> str:
    if not frida_log_path.is_file():
        return ""
    with frida_log_path.open("rb") as handle:
        handle.seek(byte_offset)
        return handle.read().decode("utf-8", errors="ignore")


def explore_input_effective_after_action(
    *,
    action_success: bool,
    screen_hash: str,
    screen_hash_after: str,
    frida_log_path: Path,
    frida_pre_offset: int,
    action_start_ms: int,
    window_ms: int = 5000,
) -> bool:
    """Input counts as effective when it changed the screen or triggered meaningful Frida."""
    if not action_success:
        return False
    if screen_hash and screen_hash_after and screen_hash != screen_hash_after:
        return True
    if not frida_log_path.is_file():
        return False
    chunk = read_frida_log_slice(frida_log_path, frida_pre_offset)
    return frida_meaningful_in_log_slice(
        chunk,
        window_start_ms=action_start_ms,
        window_end_ms=action_start_ms + window_ms,
    )
