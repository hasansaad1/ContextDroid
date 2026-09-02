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

from .goals import (
    _goal_needs_text_entry_field,
    _goal_opens_search_ui,
    _goal_requests_back_navigation,
    _nav_goal_recently_satisfied,
    _screen_looks_like_search_entry_overlay,
    _search_launch_ids_on_screen,
    _search_open_goal_recently_satisfied,
    _typing_goal_recently_satisfied,
)
from .navigation import _build_text_entry_input_action
from .device import _foreground_acceptable, _should_recover_from_foreign_app
from .config import _BACK_GOAL_STUCK_LIMIT
from .screen import (
    _bounds_center,
    _resource_id_owner_package,
    _screen_has_edittext_for_typing,
    _screen_has_search_launch_affordance,
)
def _route_tap_from_nav_targets(
    goal_route: dict[str, Any],
    nav_graph: dict[str, Any],
    elements: list[dict[str, str]],
    target_pkg: str,
    *,
    reason: str = "engine_route_tap_goal_nav",
) -> dict[str, Any] | None:
    """Tap a goal-route target recorded in the semantic nav graph during explore."""
    target_keys = {str(k) for k in (goal_route.get("target_keys") or [])}
    targets = nav_graph.get("targets") or {}
    wanted: list[dict[str, Any]] = []
    for key in target_keys:
        rec = targets.get(key)
        if isinstance(rec, dict):
            wanted.append(rec)
    for rec in wanted:
        rid = str(rec.get("target_resource_id") or "").strip()
        cd = str(rec.get("target_content_desc") or "").strip()
        for e in elements:
            if rid and e.get("resource_id") != rid:
                continue
            if cd and str(e.get("content_desc") or "") != cd:
                continue
            pref = _resource_id_owner_package(str(e.get("resource_id") or ""))
            if pref and pref != target_pkg:
                continue
            center = _bounds_center(e.get("bounds", ""))
            if center is None:
                continue
            return {
                "action_type": "tap",
                "target_resource_id": rid,
                "target_content_desc": cd,
                "x": int(center[0]),
                "y": int(center[1]),
                "reason": reason,
            }
    return None

def _route_tap_search_launch(
    elements: list[dict[str, str]],
    target_pkg: str,
    *,
    goal_route: dict[str, Any] | None = None,
    nav_graph: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Tap visible search FAB/button for open-search goals (not a bottom-nav token)."""
    if goal_route and nav_graph:
        tap = _route_tap_from_nav_targets(
            goal_route,
            nav_graph,
            elements,
            target_pkg,
            reason="engine_route_tap_search_launch",
        )
        if tap is not None:
            return tap
    for rid in _search_launch_ids_on_screen(elements):
        for e in elements:
            if e.get("resource_id") != rid:
                continue
            pref = _resource_id_owner_package(str(e.get("resource_id") or ""))
            if pref and pref != target_pkg:
                continue
            center = _bounds_center(e.get("bounds", ""))
            if center is None:
                continue
            return {
                "action_type": "tap",
                "target_resource_id": rid,
                "target_content_desc": str(e.get("content_desc") or ""),
                "x": int(center[0]),
                "y": int(center[1]),
                "reason": "engine_route_tap_search_launch",
            }
    return None

def _route_navigate_to_search_surface(
    nav_graph: dict[str, Any],
    elements: list[dict[str, str]],
    target_pkg: str,
) -> dict[str, Any] | None:
    """Switch to a main tab where explore recorded the search FAB (FAB absent on e.g. Updates)."""
    prefer_tokens = ("latest", "categories", "nearby", "updates")
    targets = nav_graph.get("targets") or {}
    candidates: list[dict[str, Any]] = []
    for key, rec_any in targets.items():
        if not isinstance(rec_any, dict):
            continue
        rec = rec_any
        token = str(rec.get("semantic_token") or "")
        if token not in prefer_tokens:
            continue
        rid = str(rec.get("target_resource_id") or "").strip()
        if not rid:
            continue
        candidates.append(
            {
                "semantic_token": token,
                "target_resource_id": rid,
                "target_content_desc": str(rec.get("target_content_desc") or ""),
                "order": prefer_tokens.index(token),
            }
        )
    candidates.sort(key=lambda x: int(x["order"]))
    for rec in candidates:
        rid = str(rec["target_resource_id"])
        cd = str(rec["target_content_desc"])
        for e in elements:
            if e.get("resource_id") != rid:
                continue
            if cd and str(e.get("content_desc") or "") != cd:
                continue
            pref = _resource_id_owner_package(str(e.get("resource_id") or ""))
            if pref and pref != target_pkg:
                continue
            center = _bounds_center(e.get("bounds", ""))
            if center is None:
                continue
            return {
                "action_type": "tap",
                "target_resource_id": rid,
                "target_content_desc": cd,
                "x": int(center[0]),
                "y": int(center[1]),
                "reason": "engine_route_nav_to_search_surface",
            }
    for suffix in prefer_tokens:
        rid = f"{target_pkg}:id/{suffix}"
        for e in elements:
            if e.get("resource_id") != rid:
                continue
            center = _bounds_center(e.get("bounds", ""))
            if center is None:
                continue
            return {
                "action_type": "tap",
                "target_resource_id": rid,
                "target_content_desc": str(e.get("content_desc") or suffix.title()),
                "x": int(center[0]),
                "y": int(center[1]),
                "reason": "engine_route_nav_to_search_surface",
            }
    return None

def _route_tap_nav_token_fallback(
    nav_token: str,
    elements: list[dict[str, str]],
    target_pkg: str,
    *,
    reason: str = "engine_route_tap_nav_fallback",
) -> dict[str, Any] | None:
    """Tap bottom-nav by semantic token when nav-graph keys are not visible on this screen."""
    token = (nav_token or "").strip().lower()
    if not token or token == "search":
        return None
    rid = f"{target_pkg}:id/{token}"
    for e in elements:
        if e.get("resource_id") != rid:
            continue
        center = _bounds_center(e.get("bounds", ""))
        if center is None:
            continue
        return {
            "action_type": "tap",
            "target_resource_id": rid,
            "target_content_desc": str(e.get("content_desc") or token.title()),
            "x": int(center[0]),
            "y": int(center[1]),
            "reason": reason,
        }
    return None

def _repeated_tap_without_screen_delta(
    recent_actions: list[dict[str, Any]] | None,
    *,
    target_resource_id: str = "",
    reason_prefix: str = "",
    min_repeats: int = 2,
) -> bool:
    if not recent_actions:
        return False
    rid = (target_resource_id or "").strip()
    prefix = (reason_prefix or "").strip()
    repeats = 0
    for ev in reversed(recent_actions[-8:]):
        pa = ev.get("parsed_action") or {}
        if str(pa.get("action_type") or "") != "tap" or not ev.get("action_success"):
            continue
        if rid and str(pa.get("target_resource_id") or "").strip() != rid:
            continue
        if prefix and not str(pa.get("reason") or "").startswith(prefix):
            continue
        if ev.get("screen_hash") and ev.get("screen_hash") == ev.get("screen_hash_after"):
            repeats += 1
        else:
            break
        if repeats >= min_repeats:
            return True
    return False

def _goal_label_needles(goal: str) -> list[str]:
    """Extract searchable label tokens from a tap/input goal string."""
    g = (goal or "").strip().casefold()
    if g.startswith("tap "):
        label = g[4:].strip()
    elif g.startswith("input "):
        label = g[6:].strip()
    else:
        label = g
    needles: list[str] = []
    if label:
        needles.append(label)
    for token in re.findall(r"[a-z0-9]+", label.replace("_", " ")):
        if len(token) >= 3:
            needles.append(token)
    out: list[str] = []
    seen: set[str] = set()
    for n in needles:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _route_tap_goal_label_fallback(
    goal: str,
    elements: list[dict[str, str]],
    target_pkg: str,
) -> dict[str, Any] | None:
    """Tap a visible control whose label/resource tail overlaps the active goal text."""
    needles = _goal_label_needles(goal)
    if not needles:
        return None
    best: dict[str, Any] | None = None
    best_score = 0
    for e in elements:
        rid = str(e.get("resource_id") or "").strip()
        pref = _resource_id_owner_package(rid)
        if pref and pref != target_pkg:
            continue
        rid_tail = rid.split("/")[-1].replace("_", " ") if ":id/" in rid else ""
        blob = " ".join(
            [
                str(e.get("text") or ""),
                str(e.get("content_desc") or ""),
                rid_tail,
            ]
        ).casefold()
        score = sum(1 for n in needles if n in blob)
        if score <= best_score:
            continue
        center = _bounds_center(e.get("bounds", ""))
        if center is None:
            continue
        best_score = score
        best = {
            "action_type": "tap",
            "target_resource_id": rid,
            "target_content_desc": str(e.get("content_desc") or ""),
            "x": int(center[0]),
            "y": int(center[1]),
            "reason": "engine_fallback_tap_goal_label",
        }
    return best


def _execute_engine_fallback_action(
    goal_route: dict[str, Any] | None,
    goal: str,
    nav_graph: dict[str, Any],
    app_state: dict[str, Any] | None,
    elements: list[dict[str, str]],
    target_pkg: str,
    *,
    goal_status: str = "feasible",
    goal_blocked_turns: int = 0,
    recent_actions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Deterministic execute step when nav routing cannot map the active goal."""
    route = _route_controller_action_for_goal(
        goal_route,
        nav_graph,
        app_state,
        elements,
        target_pkg,
        recent_actions=recent_actions,
    )
    if route is not None:
        return route
    if goal_status == "satisfied":
        return {"action_type": "advance_goal", "reason": "engine_fallback_goal_satisfied"}
    if _goal_opens_search_ui(goal) or _goal_needs_text_entry_field(goal):
        launch = _route_tap_search_launch(
            elements,
            target_pkg,
            goal_route=goal_route,
            nav_graph=nav_graph,
        )
        if launch is not None:
            return launch
        if _goal_needs_text_entry_field(goal) and _screen_has_edittext_for_typing(elements):
            typed = _build_text_entry_input_action(
                elements,
                target_pkg=target_pkg,
                reason="engine_fallback_text_entry",
            )
            if typed is not None:
                return typed
    tap = _route_tap_goal_label_fallback(goal, elements, target_pkg)
    if tap is not None:
        return tap
    if goal_status == "blocked" or goal_blocked_turns >= 1:
        return {"action_type": "advance_goal", "reason": "engine_fallback_skip_blocked"}
    return {"action_type": "advance_goal", "reason": "engine_fallback_skip_unroutable"}


def _repeated_back_without_screen_delta(
    recent_actions: list[dict[str, Any]] | None,
    *,
    min_repeats: int = _BACK_GOAL_STUCK_LIMIT,
) -> bool:
    if not recent_actions:
        return False
    repeats = 0
    for ev in reversed(recent_actions[-12:]):
        pa = ev.get("parsed_action") or {}
        if str(pa.get("action_type") or "") != "back":
            continue
        reason = str(pa.get("reason") or "")
        if reason.startswith("engine_route_exit"):
            continue
        if not ev.get("action_success"):
            continue
        if ev.get("screen_hash") and ev.get("screen_hash") == ev.get("screen_hash_after"):
            repeats += 1
        else:
            break
        if repeats >= min_repeats:
            return True
    return False

def _route_controller_action_for_goal(
    goal_route: dict[str, Any] | None,
    nav_graph: dict[str, Any],
    app_state: dict[str, Any] | None,
    elements: list[dict[str, str]],
    target_pkg: str,
    *,
    recent_actions: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    if not goal_route:
        return None
    goal = str(goal_route.get("goal") or "")
    nav_token = str(goal_route.get("nav_token") or "")
    state = app_state or {}
    if state.get("search_open"):
        return {"action_type": "back", "reason": "engine_route_exit_search_overlay"}
    if _goal_opens_search_ui(goal):
        if _search_open_goal_recently_satisfied(recent_actions):
            return {"action_type": "advance_goal", "reason": "engine_search_open_recently_satisfied"}
        if bool(state.get("text_entry_visible")) and (
            bool(state.get("search_launch_visible"))
            or not _screen_has_search_launch_affordance(elements)
        ):
            return {"action_type": "advance_goal", "reason": "engine_goal_status_satisfied"}
        if _screen_looks_like_search_entry_overlay(elements):
            return {"action_type": "advance_goal", "reason": "engine_search_scanner_overlay_open"}
        launch = _route_tap_search_launch(
            elements,
            target_pkg,
            goal_route=goal_route,
            nav_graph=nav_graph,
        )
        if launch is not None:
            launch_rid = str(launch.get("target_resource_id") or "")
            if _repeated_tap_without_screen_delta(
                recent_actions,
                target_resource_id=launch_rid,
                reason_prefix="engine_route_tap_search",
            ):
                return {
                    "action_type": "advance_goal",
                    "reason": "engine_search_launch_stuck",
                }
            return launch
        if not bool(state.get("search_launch_visible")):
            nav_surface = _route_navigate_to_search_surface(nav_graph, elements, target_pkg)
            if nav_surface is not None:
                return nav_surface
            for rid in _search_launch_ids_on_screen(elements):
                for e in elements:
                    if e.get("resource_id") != rid:
                        continue
                    center = _bounds_center(e.get("bounds", ""))
                    if center is None:
                        continue
                    return {
                        "action_type": "tap",
                        "target_resource_id": rid,
                        "target_content_desc": str(e.get("content_desc") or ""),
                        "x": int(center[0]),
                        "y": int(center[1]),
                        "reason": "engine_route_tap_search_visible_entry",
                    }
        return None
    if _goal_needs_text_entry_field(goal):
        if state.get("search_open"):
            return {"action_type": "back", "reason": "engine_route_exit_search_overlay"}
        if _typing_goal_recently_satisfied(recent_actions):
            return {"action_type": "advance_goal", "reason": "engine_text_entry_recently_satisfied"}
        if _screen_looks_like_search_entry_overlay(elements):
            return {"action_type": "advance_goal", "reason": "engine_search_scanner_overlay_open"}
        if _screen_has_edittext_for_typing(elements) and not bool(state.get("search_launch_visible")):
            typed = _build_text_entry_input_action(
                elements,
                target_pkg=target_pkg,
                reason="engine_route_text_entry",
            )
            if typed is not None:
                return typed
        if not _screen_has_edittext_for_typing(elements) or bool(state.get("search_launch_visible")):
            launch = _route_tap_search_launch(
                elements,
                target_pkg,
                goal_route=goal_route,
                nav_graph=nav_graph,
            )
            if launch is not None:
                return launch
            if not bool(state.get("search_launch_visible")):
                nav_surface = _route_navigate_to_search_surface(nav_graph, elements, target_pkg)
                if nav_surface is not None:
                    return nav_surface
        return None
    if _goal_requests_back_navigation(goal):
        fg = str(state.get("foreground_package") or "")
        if fg and _should_recover_from_foreign_app(target_pkg, fg):
            return {"action_type": "advance_goal", "reason": "engine_back_goal_on_exit_surface"}
        if fg and not _foreground_acceptable(target_pkg, fg):
            return {"action_type": "advance_goal", "reason": "engine_back_goal_app_not_foreground"}
        if _repeated_back_without_screen_delta(recent_actions):
            return {"action_type": "advance_goal", "reason": "engine_back_goal_stuck"}
        visible_nav = set(state.get("visible_nav_tokens") or [])
        if len(visible_nav) >= 3 and not bool(state.get("search_open")):
            return {"action_type": "advance_goal", "reason": "engine_back_goal_at_hub"}
        return {"action_type": "back", "reason": "engine_route_back_goal"}
    if not nav_token:
        return None
    if str(state.get("active_nav_token") or "") == nav_token:
        return {"action_type": "advance_goal", "reason": "engine_goal_status_satisfied"}
    if _nav_goal_recently_satisfied(nav_token, recent_actions):
        return {"action_type": "advance_goal", "reason": "engine_nav_goal_recently_satisfied"}
    tap = _route_tap_from_nav_targets(goal_route, nav_graph, elements, target_pkg)
    if tap is not None:
        return tap
    return _route_tap_nav_token_fallback(nav_token, elements, target_pkg)
