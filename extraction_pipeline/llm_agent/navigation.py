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

from .action_model import _action_signature_for_candidate, _nav_target_key
from .goals import (
    _action_nav_token,
    _finalize_post_explore_goals,
    _goal_nav_token,
    _goal_opens_search_ui,
    _goals_have_minimum_actionability,
    _NAV_TOKEN_ORDER,
)
from .planner import _ollama_generate_with_retries, _parse_ux_goals_from_plan
from .screen import _bounds_center, _bounds_vertical_center_fraction, _hierarchy_max_bottom_y
from .config import (
    _NAV_DIGEST_MAX_SCREENS,
    _POST_EXPLORE_GOALS_MAX,
    _POST_EXPLORE_GOALS_MIN_KEEP,
)

def _element_suggests_navigation_chrome(e: dict[str, str]) -> bool:
    cn = (e.get("class_name") or "").lower()
    rid = (e.get("resource_id") or "").lower()
    cd = (e.get("content_desc") or "").lower()
    txt = (e.get("text") or "").lower()
    blob = f"{rid} {cd} {txt}"
    class_hits = (
        "bottomnavigation",
        "navigationbar",
        "navigationrail",
        "tablayout",
        "tabwidget",
        "slidingtablayout",
        "drawerlayout",
        "navigationview",
        "viewpager",
        "pager",
        "actionmenu",
        "action_bar",
        "toolbar",
        "chipnavigation",
        "navhost",
    )
    if any(h in cn for h in class_hits):
        return True
    token_hits = (
        "bottom_nav",
        "navigation_bar",
        "navbar",
        "nav_bar",
        "navigation_menu",
        "sliding_tabs",
        "pager_tab",
        "tab_strip",
        "drawer",
        "nav_drawer",
        "open_drawer",
        "menu_drawer",
        "toolbar",
        "action_bar",
        ":id/nav",
        "_nav_",
        "tablayout",
        "bottomnavigation",
        "chip_group_nav",
        "viewpager",
    )
    if any(h in rid or h in cd for h in token_hits):
        return True
    # Short labeled strips often mirror tab titles (still navigation-like).
    if txt and txt in ("apps", "categories", "latest", "nearby", "updates", "settings", "explore") and rid:
        return True
    return False

def _navigation_explore_targets_summary(elements: list[dict[str, str]]) -> tuple[str, bool]:
    """Human-readable bullet list for explore-phase prompts; bool True if nav-like widgets detected."""
    screen_bot = _hierarchy_max_bottom_y(elements)
    rows: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    for e in elements:
        cn_full = e.get("class_name") or ""
        cn_l = cn_full.lower()
        rid = str(e.get("resource_id") or "").strip()
        cd = str(e.get("content_desc") or "").strip()
        txt = str(e.get("text") or "").strip()
        bounds = e.get("bounds", "") or ""
        frac = _bounds_vertical_center_fraction(bounds, screen_bot)
        bottom_strip = frac is not None and frac >= 0.74
        keyword_nav = _element_suggests_navigation_chrome(e)
        toolbar_strip = frac is not None and frac <= 0.22 and keyword_nav
        if not (keyword_nav or bottom_strip or toolbar_strip):
            continue
        # Bottom-strip-only: skip huge generic containers without identity.
        if bottom_strip and not (rid or cd or txt) and "framelayout" in cn_l:
            continue
        key = (rid, cd, txt)
        if key in seen:
            continue
        seen.add(key)
        tail = rid.split("/")[-1][:52] if rid else ""
        cn_tail = cn_full.split(".")[-1][:28]
        bits = [x for x in (tail, cd[:52], txt[:36], cn_tail) if x]
        if not bits:
            continue
        tag = []
        if keyword_nav:
            tag.append("nav-chrome")
        if bottom_strip:
            tag.append("bottom-strip")
        if toolbar_strip:
            tag.append("top-strip")
        suffix = f" [{' '.join(tag)}]" if tag else ""
        rows.append(" · ".join(bits) + suffix)
        if len(rows) >= 32:
            break
    detected = bool(rows)
    if not rows:
        msg = (
            "(No nav widgets matched strict heuristics — still prioritize horizontal tab/tablayout rows, "
            "bottom-edge labeled destinations, drawer/menu icons, and toolbar tabs visible in CLEAN_SCREEN_ELEMENTS.)"
        )
        return msg, False
    bullets = "\n".join(f"- {r}" for r in rows)
    return bullets, detected

def _action_is_search_like(action: dict[str, Any]) -> bool:
    rid = str(action.get("target_resource_id") or "").lower()
    cd = str(action.get("target_content_desc") or "").lower()
    return any(k in f"{rid} {cd}" for k in ("search", "fab_search", "query", "find"))

def _action_is_back_like(action: dict[str, Any]) -> bool:
    rid = str(action.get("target_resource_id") or "").lower()
    cd = str(action.get("target_content_desc") or "").lower()
    tail = rid.split("/")[-1].strip()
    cd_norm = cd.strip()
    return (
        "back" in tail
        or "back" in cd_norm
        or "navigate_up" in tail
        or "navigate up" in cd_norm
        or tail in ("up", "button_up")
        or cd_norm in ("up", "navigate up")
    )

def _is_likely_nav_candidate(e: dict[str, str], *, screen_bottom: int) -> bool:
    if _element_suggests_navigation_chrome(e):
        return True
    frac = _bounds_vertical_center_fraction(e.get("bounds", ""), screen_bottom)
    if frac is None:
        return False
    label = " ".join(
        [
            str(e.get("text") or ""),
            str(e.get("content_desc") or ""),
            str(e.get("resource_id") or ""),
        ]
    ).strip()
    # Bottom-located labeled controls are often nav tabs.
    return bool(label) and frac >= 0.72

def _build_bfs_candidates(elements: list[dict[str, str]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (nav_candidates, other_candidates) as tap actions with deterministic order."""
    bottom = _hierarchy_max_bottom_y(elements)
    nav: list[dict[str, Any]] = []
    other: list[dict[str, Any]] = []
    for e in elements:
        center = _bounds_center(e.get("bounds", ""))
        if center is None:
            continue
        text = str(e.get("text") or "").strip()
        cd = str(e.get("content_desc") or "").strip()
        rid = str(e.get("resource_id") or "").strip()
        cls = str(e.get("class_name") or "").lower()
        clickable = str(e.get("clickable") or "").lower() in ("true", "1")
        if not clickable and "button" not in cls and "tab" not in cls:
            continue
        act = {
            "action_type": "tap",
            "target_resource_id": rid,
            "target_content_desc": cd,
            "x": int(center[0]),
            "y": int(center[1]),
            "reason": "bfs_navigation",
        }
        if _is_likely_nav_candidate(e, screen_bottom=bottom):
            nav.append(act)
        else:
            # Prefer labeled controls and visible list/detail entries.
            if text or cd or rid:
                other.append(act)
    def _nav_priority(a: dict[str, Any]) -> tuple[int, str]:
        rid = str(a.get("target_resource_id") or "").lower()
        cd = str(a.get("target_content_desc") or "").lower()
        blob = f"{rid} {cd}"
        # Prefer tab/bottom-nav entries; de-prioritize search FAB during BFS nav breadth.
        if any(k in blob for k in ("categories", "latest", "nearby", "updates", "settings", "tab", "bottom_nav")):
            pri = 0
        elif any(k in blob for k in ("fab_search", "search")):
            pri = 3
        else:
            pri = 1
        return (pri, _action_signature_for_candidate(a))

    # Deterministic order with nav-aware priority.
    nav.sort(key=_nav_priority)
    other.sort(key=_action_signature_for_candidate)
    return nav, other

def _build_tab_targets(elements: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Extract likely tab-strip destinations independent of generic clickable scoring."""
    screen_bottom = _hierarchy_max_bottom_y(elements)
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for e in elements:
        center = _bounds_center(e.get("bounds", ""))
        if center is None:
            continue
        rid = str(e.get("resource_id") or "").strip()
        txt = str(e.get("text") or "").strip()
        cd = str(e.get("content_desc") or "").strip()
        cls = str(e.get("class_name") or "").lower()
        frac = _bounds_vertical_center_fraction(e.get("bounds", ""), screen_bottom)
        rid_tail = rid.split("/")[-1].lower() if rid else ""
        label = (txt or cd).strip()
        ll = label.lower() if label else ""
        # Some tabs expose only resource_id (no visible text/content_desc).
        rid_tab_hint = any(k in rid_tail for k in ("categories", "latest", "nearby", "updates", "settings", "explore", "home"))
        if not label and not rid_tab_hint:
            continue
        if any(k in ll for k in ("search", "find", "query")):
            continue
        if ll in ("back", "up", "navigate up") or "navigate up" in ll:
            continue
        # Tab-like signals: near bottom strip, tab-ish classes/ids, or known nav labels.
        tab_like = (
            (frac is not None and frac >= 0.66)
            or ("tab" in cls or "framelayout" in cls)
            or any(k in rid.lower() for k in ("tab", "navigation", "bottom"))
            or ll in ("categories", "latest", "nearby", "updates", "settings", "explore", "home")
            or rid_tab_hint
        )
        if not tab_like:
            continue
        act = {
            "action_type": "tap",
            "target_resource_id": rid,
            "target_content_desc": cd,
            "x": int(center[0]),
            "y": int(center[1]),
            "reason": "bfs_tab_frontier",
        }
        k = _nav_target_key(act)
        if k in seen:
            continue
        seen.add(k)
        out.append(act)
    out.sort(key=_action_signature_for_candidate)
    return out

def _nav_graph_target_key(action: dict[str, Any], *, candidate_kind: str) -> str:
    token = _action_nav_token(action)
    if token:
        return f"{candidate_kind}:{token}"
    return f"{candidate_kind}:{_nav_target_key(action)}"

def _nav_graph_register_candidates(
    nav_graph: dict[str, Any],
    screen_hash: str,
    candidates: list[dict[str, Any]],
    *,
    candidate_kind: str,
    target_pkg: str,
) -> None:
    from .dialogs import _action_is_foreign_dialog_widget

    targets = nav_graph.setdefault("targets", {})
    for c in candidates:
        if _action_is_foreign_dialog_widget(c, target_pkg):
            continue
        key = _nav_graph_target_key(c, candidate_kind=candidate_kind)
        rec = targets.setdefault(
            key,
            {
                "kind": candidate_kind,
                "semantic_token": _action_nav_token(c),
                "target_resource_id": str(c.get("target_resource_id") or ""),
                "target_content_desc": str(c.get("target_content_desc") or ""),
                "visible_on": [],
                "attempts": 0,
                "successes": 0,
                "last_from": "",
                "last_to": "",
            },
        )
        if screen_hash and screen_hash not in rec["visible_on"]:
            rec["visible_on"].append(screen_hash)

def _nav_graph_pick_uncovered_visible(
    nav_graph: dict[str, Any],
    candidates: list[dict[str, Any]],
    *,
    candidate_kind: str,
    target_pkg: str,
) -> dict[str, Any] | None:
    from .dialogs import _action_is_foreign_dialog_widget

    targets = nav_graph.setdefault("targets", {})
    scored: list[tuple[tuple[int, int, int, str], dict[str, Any]]] = []
    for c in candidates:
        if _action_is_foreign_dialog_widget(c, target_pkg):
            continue
        if _action_is_search_like(c) or _action_is_back_like(c):
            continue
        key = _nav_graph_target_key(c, candidate_kind=candidate_kind)
        rec = targets.get(key, {})
        successes = int(rec.get("successes") or 0)
        attempts = int(rec.get("attempts") or 0)
        if successes == 0 and attempts >= 2:
            continue
        token = _action_nav_token(c)
        token_rank = _NAV_TOKEN_ORDER.index(token) if token in _NAV_TOKEN_ORDER else len(_NAV_TOKEN_ORDER)
        scored.append(((successes, attempts, token_rank, key), c))
    if not scored:
        return None
    scored.sort(key=lambda item: item[0])
    if scored[0][0][0] > 0:
        return None
    out = dict(scored[0][1])
    out["reason"] = f"bfs_graph_uncovered_{candidate_kind}"
    return out

def _nav_graph_record_transition(
    nav_graph: dict[str, Any],
    *,
    from_hash: str,
    to_hash: str,
    action: dict[str, Any],
    ok: bool,
    candidate_kind: str,
) -> str:
    key = _nav_graph_target_key(action, candidate_kind=candidate_kind)
    targets = nav_graph.setdefault("targets", {})
    rec = targets.setdefault(
        key,
        {
            "kind": candidate_kind,
            "semantic_token": _action_nav_token(action),
            "target_resource_id": str(action.get("target_resource_id") or ""),
            "target_content_desc": str(action.get("target_content_desc") or ""),
            "visible_on": [],
            "attempts": 0,
            "successes": 0,
            "last_from": "",
            "last_to": "",
        },
    )
    rec["attempts"] = int(rec.get("attempts") or 0) + 1
    if ok:
        rec["successes"] = int(rec.get("successes") or 0) + 1
    rec["last_from"] = from_hash
    rec["last_to"] = to_hash
    nav_graph.setdefault("edges", []).append(
        {
            "from": from_hash,
            "to": to_hash,
            "target_key": key,
            "ok": bool(ok),
            "action_type": str(action.get("action_type") or ""),
            "reason": str(action.get("reason") or ""),
        }
    )
    return key

def _build_navigation_artifact(
    *,
    pkg: str,
    discovered: dict[str, str],
    transitions: list[dict[str, Any]],
    visited_counts: dict[str, int],
    nav_graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    screens = [
        {"screen_hash": h, "hint": discovered[h], "visit_count": int(visited_counts.get(h, 0))}
        for h in sorted(discovered.keys())
    ]
    return {
        "schema": "contextdroid_nav_semantic_graph_v1",
        "package_name": pkg,
        "screen_count": len(screens),
        "screens": screens,
        "transitions": transitions,
        "semantic_graph": nav_graph or {"targets": {}, "edges": []},
    }

def _build_route_aware_goals(
    goals: list[str],
    nav_graph: dict[str, Any],
    discovered: dict[str, str],
) -> list[dict[str, Any]]:
    targets = nav_graph.get("targets") or {}
    out: list[dict[str, Any]] = []
    for idx, goal in enumerate(goals):
        nav_token = _goal_nav_token(goal)
        matching: list[dict[str, Any]] = []
        for key, rec_any in targets.items():
            if not isinstance(rec_any, dict):
                continue
            rec = rec_any
            if nav_token and rec.get("semantic_token") != nav_token:
                continue
            if not nav_token and not any(
                str(rec.get(k) or "").lower() and str(rec.get(k) or "").lower() in goal.lower()
                for k in ("target_resource_id", "target_content_desc")
            ):
                continue
            matching.append({"target_key": key, **rec})
        observed_hashes: list[str] = []
        for rec in matching:
            for h in list(rec.get("visible_on") or []) + [str(rec.get("last_to") or "")]:
                if h and h not in observed_hashes:
                    observed_hashes.append(h)
        route_hint = ""
        if nav_token and matching:
            route_hint = f"Use visible {nav_token} navigation target before executing this goal if not already there."
        elif nav_token:
            route_hint = f"Navigate toward the {nav_token} surface using visible app navigation controls."
        elif _goal_opens_search_ui(goal):
            nav_token = nav_token or "search"
            route_hint = "Open the observed search affordance before typing into a query field."
        elif "search" in goal.lower():
            route_hint = "Open the observed search affordance before typing into a query field."
        else:
            route_hint = "Use the current screen if feasible; otherwise navigate via observed app controls."
        out.append(
            {
                "index": idx,
                "goal": goal,
                "nav_token": nav_token,
                "target_keys": [str(x.get("target_key") or "") for x in matching[:5]],
                "observed_screen_hashes": observed_hashes[:5],
                "observed_screen_hints": [
                    discovered[h] for h in observed_hashes[:3] if h in discovered
                ],
                "route_hint": route_hint,
            }
        )
    return out

def _format_navigation_digest(digest: dict[str, str]) -> str:
    if not digest:
        return "(no screens recorded yet)"
    lines = [f"{h[:16]}… | {digest[h]}" for h in sorted(digest.keys())]
    return "\n".join(lines[-min(len(lines), _NAV_DIGEST_MAX_SCREENS) :])

def _plan_execution_goals_from_digest(
    app_context: dict[str, Any], screen_map_text: str, model: str, endpoint: str
) -> list[str]:
    prompt = (
        "Black-box Android QA planner. A runner already NAVIGATED and collected distinct screens.\n"
        "Below is a compact SCREEN MAP (hash prefix → UI hints). The app is in the foreground.\n"
        "The device may be OFFLINE — do not require network-dependent outcomes; only navigation you can drive from "
        "visible controls.\n"
        "Reply with JSON ONLY (no markdown fences, no commentary): {\"goals\":[\"...\", ...]} "
        f"with {max(4, min(6, _POST_EXPLORE_GOALS_MAX))}–{_POST_EXPLORE_GOALS_MAX} imperative TEST GOALS in sensible ORDER "
        "(tap, input text, back, wait only).\n"
        "HARD RULES:\n"
        "- Every goal MUST name a concrete control or area that appears in SCREEN_MAP (e.g. Categories, Latest, "
        "Nearby, Updates, Settings, Search, Apps menu, QR, permission dialog).\n"
        "- FORBIDDEN: software-engineering or meta tasks (architecture, metadata integration, hybrid apps, "
        "investigations, optimizing UX in the abstract, analyzing logs, refining integrations).\n"
        "- DIVERSIFY flows suggested by the map; avoid repeating the same widget. Next steps EXECUTE goals "
        "one-by-one.\n"
        "- OBSERVED UI DEPENDENCY: if SCREEN_MAP shows search launch (e.g. fab_search / Search button) on some "
        "screens and EditText search fields on others, list TAP/OPEN search goals BEFORE any INPUT/TYPE search "
        "query goals — the text field is not available until search is opened.\n\n"
        f"SCREEN_MAP:\n{screen_map_text}\n\nAPP_CONTEXT:\n{json.dumps(app_context, ensure_ascii=False)}\n"
    )
    try:
        raw = _ollama_generate_with_retries(prompt, model, endpoint)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        logging.warning("Post-explore goal planning failed; using digest-only goals.")
        return _finalize_post_explore_goals([], screen_map_text)
    goals = _parse_ux_goals_from_plan(raw)
    if not goals:
        # Recovery pass: ask the model to transform its own non-JSON response into strict JSON.
        repair_prompt = (
            "Convert the following planner output into STRICT JSON only.\n"
            "Return exactly: {\"goals\":[\"...\", ...]} with 6-12 concise imperative goals.\n"
            "Do not include markdown fences, explanations, or extra keys.\n\n"
            f"PLANNER_OUTPUT_TO_REPAIR:\n{raw}\n"
        )
        try:
            repaired_raw = _ollama_generate_with_retries(repair_prompt, model, endpoint)
            repaired_goals = _parse_ux_goals_from_plan(repaired_raw)
            if repaired_goals:
                goals = repaired_goals
                logging.info(
                    "Recovered post-explore goals via JSON-repair pass; parsed %d goals.",
                    len(goals),
                )
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            pass
    # If repair succeeded syntactically but produced abstract/non-actionable goals, do one stricter retry.
    if goals and not _goals_have_minimum_actionability(goals, minimum=4):
        strict_repair_prompt = (
            "Rewrite the following goals into CONCRETE ANDROID UI ACTIONS.\n"
            "Return STRICT JSON only: {\"goals\":[\"...\", ...]} with 6-10 items.\n"
            "Rules:\n"
            "- Each goal MUST start with one of: Tap/Open/Press/Select/Input/Type/Search/Back/Swipe/Scroll/Wait\n"
            "- Each goal MUST reference a specific UI target that literally appears in SCREEN_MAP.\n"
            "- No abstract wording (improve/enhance/optimize/refine/architecture/metadata/integration/investigate).\n"
            "- No markdown, no commentary, no extra keys.\n\n"
            f"SCREEN_MAP:\n{screen_map_text}\n\n"
            f"GOALS_TO_REWRITE:\n{json.dumps(goals, ensure_ascii=False)}\n"
        )
        try:
            strict_repaired_raw = _ollama_generate_with_retries(strict_repair_prompt, model, endpoint)
            strict_repaired_goals = _parse_ux_goals_from_plan(strict_repaired_raw)
            if strict_repaired_goals and _goals_have_minimum_actionability(strict_repaired_goals, minimum=4):
                goals = strict_repaired_goals
                logging.info(
                    "Recovered post-explore goals via strict actionability-repair pass; parsed %d goals.",
                    len(goals),
                )
            else:
                logging.warning(
                    "Strict actionability-repair returned insufficiently concrete goals; keeping prior set."
                )
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            pass
    if not goals:
        logging.warning(
            "Could not parse post-explore goals; digest-only template. planner_preview=%r",
            (raw[:900] + "…") if len(raw) > 900 else raw,
        )
        return _finalize_post_explore_goals([], screen_map_text)
    finalized = _finalize_post_explore_goals(goals, screen_map_text)
    if len(finalized) < _POST_EXPLORE_GOALS_MIN_KEEP and goals:
        # Spend one extra planner turn to recover concrete UI-tied goals if strict gate dropped too much.
        extra_strict_prompt = (
            "Rewrite these goals into STRICT UI-ONLY goals for this exact SCREEN_MAP.\n"
            f"Return JSON ONLY: {{\"goals\":[\"...\", ...]}} with {_POST_EXPLORE_GOALS_MIN_KEEP}-{_POST_EXPLORE_GOALS_MAX} items.\n"
            "Every item MUST start with Tap/Open/Press/Select/Input/Type/Search/Back/Swipe/Scroll/Wait "
            "and MUST map to a visible control/area in SCREEN_MAP.\n"
            "FORBIDDEN: architecture, metadata, integration, analysis, correlation, expected permissions, "
            "user-feedback, generic improvements.\n\n"
            f"SCREEN_MAP:\n{screen_map_text}\n\n"
            f"GOALS_TO_REWRITE:\n{json.dumps(goals, ensure_ascii=False)}\n"
        )
        try:
            extra_raw = _ollama_generate_with_retries(extra_strict_prompt, model, endpoint)
            extra_goals = _parse_ux_goals_from_plan(extra_raw)
            if extra_goals:
                extra_final = _finalize_post_explore_goals(extra_goals, screen_map_text)
                if len(extra_final) >= len(finalized):
                    finalized = extra_final
                    logging.info(
                        "Recovered post-explore goals via extra strict pass; keeping %d goals.",
                        len(finalized),
                    )
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            pass
    logging.info("Parsed %d post-explore execution goals from planner.", len(finalized))
    return finalized
