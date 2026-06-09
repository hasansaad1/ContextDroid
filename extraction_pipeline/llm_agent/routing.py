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
    _goal_opens_search_ui,
    _nav_goal_recently_satisfied,
    _screen_looks_like_search_entry_overlay,
    _search_launch_ids_on_screen,
    _search_open_goal_recently_satisfied,
)
from .screen import _bounds_center, _resource_id_owner_package, _screen_has_search_launch_affordance
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
