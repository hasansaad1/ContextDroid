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

from .dialogs import _derive_dialog_state, _hierarchy_shows_permission_dialog
from .planner import _ollama_generate_with_retries, _parse_ux_goals_from_plan
from .screen import (
    _allowed_resource_ids_from_elements,
    _bounds_center,
    _bounds_vertical_center_fraction,
    _hierarchy_max_bottom_y,
    _is_definite_search_launch_widget,
    _is_false_positive_search_launch_widget,
    _resource_id_owner_package,
    _screen_has_edittext_for_typing,
    _screen_has_search_entry_widget,
    _screen_has_search_launch_affordance,
    _screen_is_empty_state,
)
from .config import (
    _ABSTRACT_PLANNER_GOAL_RE,
    _BAD_UX_GOAL_RE,
    _DEFAULT_UX_GOALS,
    _POST_EXPLORE_GOALS_MAX,
    _POST_EXPLORE_GOALS_MIN_KEEP,
    _POST_EXPLORE_STRICT_DIGEST,
)


_COMMON_BOTTOM_NAV_TOKENS = ("categories", "latest", "nearby", "updates", "settings")
_NAV_TOKEN_ORDER = (
    "latest",
    "categories",
    "nearby",
    "updates",
    "settings",
    "home",
    "browse",
    "apps",
    "explore",
)


def _screen_map_for_goal_grounding(screen_map_text: str) -> tuple[str, frozenset[str]]:
    """SCREEN_MAP body only — exclude the TRANSITIONS appendix used for nav metadata."""
    raw = screen_map_text or ""
    body = raw.split("\n\nTRANSITIONS:\n", 1)[0]
    return body.lower(), _screen_map_anchors(body)


def _sanitize_ux_goal_strings(goals: list[str]) -> list[str]:
    # Drop planner goals that are syntactically valid but not actionable UX intents.
    bad_phrases = (
        "wait for ",
        "input text in categories",
        "input text in latest",
        "input text in nearby",
        "input text in settings",
        "input text in updates",
        "input text in tab",
        "frame layout",
    )
    kept: list[str] = []
    for g in goals:
        if not g or _BAD_UX_GOAL_RE.search(g):
            continue
        if _is_degenerate_transitions_goal(g):
            continue
        gl = g.strip().lower()
        if any(p in gl for p in bad_phrases):
            continue
        kept.append(g)
    return kept if kept else list(_DEFAULT_UX_GOALS)

def _strip_unusable_ux_goal_strings(goals: list[str]) -> list[str]:
    """Like _sanitize_ux_goal_strings but returns [] when everything is dropped (no default injection)."""
    bad_phrases = (
        "wait for ",
        "input text in categories",
        "input text in latest",
        "input text in nearby",
        "input text in settings",
        "input text in updates",
        "input text in tab",
        "frame layout",
    )
    kept: list[str] = []
    for g in goals:
        if not g or _BAD_UX_GOAL_RE.search(g):
            continue
        if _is_degenerate_transitions_goal(g):
            continue
        gl = g.strip().lower()
        if any(p in gl for p in bad_phrases):
            continue
        kept.append(g)
    return kept

def _screen_map_has_search_surface(screen_map_text: str) -> bool:
    """True only when digest shows real search chrome (FAB / launch button), not backup_search widgets."""
    if not screen_map_text:
        return False
    any_launch = False
    for line in screen_map_text.splitlines():
        hint_blob = line.split("|", 1)[1] if "|" in line else line
        _can_type, can_launch = _digest_line_search_observation(hint_blob)
        if can_launch:
            any_launch = True
            break
    return any_launch

def _digest_fragment_search_observation(fragment: str) -> tuple[bool, bool]:
    """Per-widget digest fragment: (can_type_in_field, can_launch_search_chrome)."""
    low = (fragment or "").lower()
    has_edittext = "edittext" in low or "autocomplete" in low
    has_fab = "fab_search" in low
    has_search_button = "search_button" in low or (
        "search" in low and "button" in low and not has_edittext
    )
    can_type = has_edittext and any(k in low for k in ("search", "query", "apps"))
    if has_edittext and not can_type:
        can_type = True
    can_launch = has_fab or has_search_button
    if can_type:
        can_launch = can_launch or has_fab
    return can_type, can_launch


def _digest_line_search_observation(hint_blob: str) -> tuple[bool, bool]:
    """From one SCREEN_MAP hint line: (can_type_in_field, can_launch_search_chrome).

    Hint lines join multiple widgets with ' · '; evaluate each fragment separately so a
    payment sendInput on the same line does not suppress search_button launch detection.
    """
    blob = (hint_blob or "").strip()
    if not blob:
        return False, False
    fragments = [blob] if " · " not in blob else [f.strip() for f in blob.split(" · ") if f.strip()]
    can_type = False
    can_launch = False
    for frag in fragments:
        t, l = _digest_fragment_search_observation(frag)
        can_type = can_type or t
        can_launch = can_launch or l
    return can_type, can_launch

def _digest_requires_open_search_before_type(screen_map_text: str) -> bool:
    """True when observation shows search typing happens on a different surface than launch (FAB/button)."""
    if not _screen_map_has_search_surface(screen_map_text):
        return False
    any_type_surface = False
    any_launch_only_surface = False
    for line in (screen_map_text or "").splitlines():
        if "|" in line:
            hint_blob = line.split("|", 1)[1]
        else:
            hint_blob = line
        can_type, can_launch = _digest_line_search_observation(hint_blob)
        if can_type:
            any_type_surface = True
        if can_launch and not can_type:
            any_launch_only_surface = True
    if any_launch_only_surface:
        return True
    return False

_TEXT_ENTRY_VERBS = ("input", "type", "enter", "write", "fill")


def _goal_has_text_entry_verbs(goal: str) -> bool:
    g = (goal or "").strip().lower()
    if not g:
        return False
    if g.startswith(tuple(f"{v} " for v in _TEXT_ENTRY_VERBS)):
        return True
    if "input text" in g:
        return True
    return any(re.search(rf"\b{v}\b", g) for v in _TEXT_ENTRY_VERBS)


def _is_degenerate_transitions_goal(goal: str) -> bool:
    """Reject planner goals that treat the TRANSITIONS digest section as a tap target."""
    g = (goal or "").strip().casefold()
    if not g:
        return False
    return g.startswith("tap transitions:") or "tap transitions:" in g


def _goal_needs_text_entry_field(
    goal: str,
    *,
    elements: list[dict[str, str]] | None = None,
) -> bool:
    """True when the goal requires typing into a visible text-entry field."""
    g = (goal or "").strip().lower()
    if not g:
        return False
    if _is_degenerate_transitions_goal(goal):
        return False
    if _goal_has_text_entry_verbs(g):
        return True
    if any(k in g for k in ("search", "query")) and any(
        v in g for v in _TEXT_ENTRY_VERBS
    ):
        return True
    if elements and _screen_has_edittext_for_typing(elements):
        if g.startswith(("tap ", "open ", "press ", "select ")):
            tokens = [
                t
                for t in re.findall(r"[a-z][a-z0-9_]{2,}", g)
                if t not in {"tap", "open", "press", "select", "the", "field"}
            ]
            for e in elements:
                cn = (e.get("class_name") or "").lower()
                if "edittext" not in cn and "autocomplete" not in cn:
                    continue
                blob = " ".join(
                    (
                        str(e.get("text") or ""),
                        str(e.get("content_desc") or ""),
                        str(e.get("resource_id") or ""),
                    )
                ).lower()
                if any(t in blob for t in tokens[:4]):
                    return True
    return False


def _element_looks_like_search_field(e: dict[str, str]) -> bool:
    blob = " ".join(
        (
            str(e.get("resource_id") or ""),
            str(e.get("content_desc") or ""),
            str(e.get("text") or ""),
        )
    ).lower()
    return any(k in blob for k in ("search", "query", "find", "filter"))


def _screen_is_search_typing_surface(elements: list[dict[str, str]]) -> bool:
    """True when visible EditText is search/query chrome — not a generic form field."""
    if not _screen_has_edittext_for_typing(elements):
        return False
    for e in elements:
        cn = (e.get("class_name") or "").lower()
        if "edittext" not in cn and "autocomplete" not in cn:
            continue
        if _element_looks_like_search_field(e):
            return True
    if _screen_has_search_launch_affordance(elements):
        return True
    return False


def _typing_goal_recently_satisfied(
    recent_actions: list[dict[str, Any]] | None,
) -> bool:
    """True after a successful input action with non-empty text."""
    if not recent_actions:
        return False
    for ev in reversed(recent_actions[-10:]):
        pa = ev.get("parsed_action") or {}
        if str(pa.get("action_type") or "") != "input" or not ev.get("action_success"):
            continue
        if str(pa.get("text") or "").strip():
            return True
    return False


def _single_typing_goal_substantiated(
    goal: str,
    actions: list[dict[str, Any]],
) -> bool:
    if not _goal_needs_text_entry_field(goal):
        return True
    return _typing_goal_recently_satisfied(actions)

def _goal_opens_search_ui(goal: str) -> bool:
    """True for concrete 'open search chrome' goals — not narrative 'search for a package' flows."""
    g = (goal or "").strip().lower()
    if not any(v in g for v in ("tap", "open", "press", "click", "touch")):
        return False
    if not any(k in g for k in ("search", "fab")):
        return False
    if any(
        k in g
        for k in (
            "package",
            "detail page",
            "detail view",
            "results page",
            "browse apps",
            "navigate through",
            "open its",
            "open a package",
        )
    ):
        return False
    return True

def _reorder_goals_by_observed_ui_dependencies(
    goals: list[str], *, screen_map_text: str
) -> list[str]:
    """Put 'open search' before 'type in search field' when digest shows two-phase search UX."""
    if not goals or not _digest_requires_open_search_before_type(screen_map_text):
        return list(goals)
    launch: list[str] = []
    typing: list[str] = []
    rest: list[str] = []
    for g in goals:
        if _goal_needs_text_entry_field(g):
            typing.append(g)
        elif _goal_opens_search_ui(g):
            launch.append(g)
        else:
            rest.append(g)
    if not launch and typing:
        launch = ["Tap Search"]
    out: list[str] = []
    seen: set[str] = set()
    for bucket in (launch, rest, typing):
        for g in bucket:
            key = g.strip().casefold()
            if key in seen:
                continue
            seen.add(key)
            out.append(g.strip())
    logging.info(
        "Reordered post-explore goals by observed search UI dependencies (open before type)."
    )
    return out[:_POST_EXPLORE_GOALS_MAX]

def _ensure_search_flow_goals(goals: list[str], *, screen_map_text: str) -> list[str]:
    """Guarantee at least one open-search and one type-search goal when search UI exists."""
    if not goals or not _screen_map_has_search_surface(screen_map_text):
        return goals
    has_open = any(_goal_opens_search_ui(g) for g in goals)
    has_type = any(_goal_needs_text_entry_field(g) for g in goals)
    out = list(goals)
    if not has_open:
        out.insert(0, "Tap Search")
    if not has_type:
        insert_at = 1 if out and _goal_opens_search_ui(out[0]) else 0
        out.insert(insert_at, "Input search query")
    out = _reorder_goals_by_observed_ui_dependencies(out, screen_map_text=screen_map_text)
    return out[:_POST_EXPLORE_GOALS_MAX]

_DIGEST_WIDGET_CLASSES = frozenset(
    {
        "Button",
        "EditText",
        "TextView",
        "ImageButton",
        "FrameLayout",
        "View",
        "Spinner",
        "RadioButton",
        "LinearLayout",
        "LinearLayoutCompat",
        "CardView",
    }
)

_SKIP_DIGEST_LABELS = frozenset(
    {
        "view",
        "none",
        "touch_outside",
        "skip to main content",
        "more options",
    }
)

_SKIP_DIGEST_RID_TAILS = frozenset(
    {
        "touch_outside",
        "view",
        "nav_view",
    }
)


def _looks_like_resource_id_tail(token: str) -> bool:
    t = (token or "").strip()
    if not t or " " in t:
        return False
    if t[0].isupper() and t.endswith("Layout"):
        return False
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", t))


def _parse_digest_widget_fragment(fragment: str) -> dict[str, str] | None:
    """Parse one ' · '-separated widget blob from a SCREEN_MAP hint line."""
    frag = (fragment or "").strip()
    if not frag:
        return None
    parts = frag.split()
    if not parts:
        return None
    class_name = ""
    if parts[-1] in _DIGEST_WIDGET_CLASSES or parts[-1].endswith(("Layout", "LayoutCompat")):
        class_name = parts[-1]
        parts = parts[:-1]
    rid_tail = ""
    if parts and _looks_like_resource_id_tail(parts[-1]):
        rid_tail = parts[-1]
        parts = parts[:-1]
    label = " ".join(parts).strip()
    if not label and rid_tail:
        label = rid_tail.replace("_", " ")
    label_low = label.casefold()
    rid_low = rid_tail.casefold()
    if not label and not rid_tail:
        return None
    if rid_low in _SKIP_DIGEST_RID_TAILS:
        return None
    if label_low in _SKIP_DIGEST_LABELS and not rid_tail:
        return None
    if label_low in _SKIP_DIGEST_LABELS and rid_low in _SKIP_DIGEST_RID_TAILS:
        return None
    return {
        "label": label,
        "rid_tail": rid_tail,
        "class_name": class_name,
    }


def _parse_digest_controls(screen_map_text: str) -> list[dict[str, str]]:
    """Distinct tappable controls inferred from SCREEN_MAP digest hint lines."""
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []
    for line in (screen_map_text or "").splitlines():
        hint_blob = line.split("|", 1)[1].strip() if "|" in line else line.strip()
        if not hint_blob or hint_blob.startswith("("):
            continue
        if hint_blob.casefold().startswith("transitions:"):
            continue
        fragments = [hint_blob] if " · " not in hint_blob else [f.strip() for f in hint_blob.split(" · ")]
        for frag in fragments:
            parsed = _parse_digest_widget_fragment(frag)
            if parsed is None:
                continue
            key = (parsed["label"].casefold(), parsed["rid_tail"].casefold())
            if key in seen:
                continue
            seen.add(key)
            out.append(parsed)
    return out


def _dynamic_anchors_from_digest(screen_map_text: str) -> frozenset[str]:
    """App-agnostic anchors from parsed digest controls (supplements F-Droid needles)."""
    found: set[str] = set()
    low = (screen_map_text or "").lower()
    for c in _parse_digest_controls(screen_map_text):
        label = c.get("label", "").casefold()
        rid = c.get("rid_tail", "").casefold()
        blob = f"{label} {rid}"
        if any(k in blob for k in ("search", "action_search", "fab_search", "query")):
            found.add("search")
        if "settings" in blob or "navigation_settings" in rid:
            found.add("settings")
        if "categor" in blob:
            found.add("categories")
        if "latest" in blob:
            found.add("latest")
        if "nearby" in blob:
            found.add("nearby")
        if "updates" in blob or "update" in label:
            found.add("updates")
        if rid.startswith("nav_") or rid.startswith("navigation_"):
            for token in _NAV_TOKEN_ORDER:
                if token in rid or token in label:
                    found.add(token)
            if "explore" in rid:
                found.add("explore")
            if "login" in rid or "sign_in" in rid or "sign in" in label:
                found.add("login")
        if "sign_up" in rid or "sign up" in label or "create an account" in label:
            found.add("signup")
        if "permission" in blob:
            found.add("permission")
        if "wifi" in blob or "wi-fi" in label:
            found.add("wifi")
    if "edittext" in low and any(k in low for k in ("search", "query")):
        found.add("search")
    return frozenset(found)


def _screen_map_anchors(screen_map_text: str) -> frozenset[str]:
    """Coarse UI anchors inferred from navigation digest lines (hash | hints)."""
    low = (screen_map_text or "").lower()
    found: set[str] = set()
    pairs = (
        ("categories", "categories"),
        ("latest", "latest"),
        ("nearby", "nearby"),
        ("updates", "updates"),
        ("settings", "settings"),
        ("fab_search", "search"),
        ("search_button", "search"),
        ("action_search", "search"),
        ("btn_apps", "apps"),
        ("btn_scan_qr", "qr"),
        ("btn_send_fdroid", "send"),
        ("turn_on_wifi", "wifi"),
        ("permission_deny", "permission"),
        ("permission_allow", "permission"),
        ("find_people", "nearby"),
    )
    for needle, tag in pairs:
        if needle in low:
            found.add(tag)
    found.update(_dynamic_anchors_from_digest(screen_map_text))
    return frozenset(found)

def _goal_requests_back_navigation(goal: str) -> bool:
    g = (goal or "").strip().casefold()
    return g.startswith(("back ", "press back"))


def _goal_is_vague_back_navigation(goal: str) -> bool:
    """Drop planner-invented hub goals that have no routable nav_token or digest anchor."""
    g = (goal or "").strip().casefold()
    if not _goal_requests_back_navigation(g):
        return False
    if any(k in g for k in ("main app", "main list", "app list", "previous screen", "home screen")):
        return False
    return any(k in g for k in ("hub", "home", "main screen", "landing"))


def _strip_vague_back_goals(goals: list[str]) -> list[str]:
    return [g for g in goals if not _goal_is_vague_back_navigation(g)]


def _goal_is_forward(goal: str) -> bool:
    """True for concrete tap/input/swipe goals (not back/wait)."""
    if not _goal_looks_concrete_actionable(goal):
        return False
    g = (goal or "").strip().casefold()
    if g.startswith("wait "):
        return False
    if _goal_requests_back_navigation(goal):
        return False
    return True


def _goal_matches_digest_controls(goal: str, screen_map_text: str) -> bool:
    """Token overlap between goal text and parsed digest controls."""
    g = (goal or "").strip().casefold()
    if not g:
        return False
    stop = frozenset(
        {
            "tap",
            "open",
            "press",
            "click",
            "select",
            "input",
            "type",
            "the",
            "for",
            "and",
            "from",
            "into",
            "with",
            "text",
            "field",
        }
    )
    goal_words = {
        w
        for w in re.findall(r"[a-z0-9]+", g)
        if len(w) >= 3 and w not in stop
    }
    for c in _parse_digest_controls(screen_map_text):
        label = c.get("label", "").casefold()
        rid = c.get("rid_tail", "").casefold().replace("_", " ")
        hay_words = {
            w
            for w in re.findall(r"[a-z0-9]+", f"{label} {rid}")
            if len(w) >= 3 and w not in stop
        }
        if goal_words & hay_words:
            return True
        if label and len(label) >= 4 and label in g:
            return True
        if rid and len(rid) >= 4 and rid in g:
            return True
    sm = screen_map_text.casefold()
    if "search" in g and any(
        k in sm for k in ("action_search", "fab_search", "search_button", " search ", "search button")
    ):
        return True
    if "sign in" in g and "sign_in" in sm:
        return True
    if "account" in g and "sign_up" in sm:
        return True
    return False


def _goal_references_screen_map(goal: str, anchors: frozenset[str], screen_map_lower: str) -> bool:
    """True if goal text can be tied to something visible in the digest (or generic back/wait)."""
    g = (goal or "").strip().casefold()
    if not g:
        return False
    if g.startswith("wait "):
        return True
    if _goal_requests_back_navigation(g):
        return not _goal_is_vague_back_navigation(goal)
    blob = f"{g} {screen_map_lower}"
    if "search" in anchors or any(
        k in screen_map_lower for k in ("fab_search", "search_button", "edittext")
    ):
        if _goal_opens_search_ui(goal) or _goal_needs_text_entry_field(goal):
            return True
        if _goal_has_text_entry_verbs(g) and "edittext" in screen_map_lower:
            return True
        if any(k in g for k in ("search", "query")) and not any(
            k in g
            for k in (
                "package",
                "detail page",
                "detail view",
                "results page",
                "browse apps",
                "navigate through",
                "open its",
                "open a package",
            )
        ):
            return True
    if "categories" in anchors and "categor" in g:
        return True
    if "latest" in anchors and "latest" in g:
        return True
    if "nearby" in anchors and "nearby" in g:
        return True
    if "updates" in anchors and "update" in g:
        return True
    if "settings" in anchors and "setting" in g:
        return True
    if "apps" in anchors and "app" in g:
        return True
    if "qr" in anchors and "qr" in g:
        return True
    if "send" in anchors and "send" in g:
        return True
    if "wifi" in anchors and ("wi-fi" in g or "wifi" in g):
        return True
    if "permission" in anchors and "permission" in g:
        return True
    if "checkbox" in screen_map_lower and "checkbox" in g:
        return True
    if _goal_matches_digest_controls(goal, screen_map_lower):
        return True
    return False


def _digest_control_priority(control: dict[str, str]) -> tuple[int, str]:
    rid = control.get("rid_tail", "").casefold()
    label = control.get("label", "").casefold()
    cls = control.get("class_name", "").casefold()
    if rid.startswith("nav_") or rid.startswith("navigation_"):
        return (0, rid)
    if any(k in rid for k in ("sign_in", "sign_up", "nextbutton", "next")):
        return (1, rid or label)
    if "search" in rid or label == "search":
        return (2, rid or label)
    if "settings" in rid or "settings" in label:
        return (3, rid or label)
    if "button" in cls and label and label not in _SKIP_DIGEST_LABELS:
        return (4, label)
    if "edittext" in cls:
        return (5, rid or label)
    if label and label not in _SKIP_DIGEST_LABELS:
        return (6, label)
    return (9, rid or label)


def _goal_text_for_digest_control(control: dict[str, str]) -> str | None:
    rid = control.get("rid_tail", "")
    label = control.get("label", "")
    cls = control.get("class_name", "")
    cls_low = cls.casefold()
    # Digest hints clip visible text at ~28 chars; prefer stable resource-id tails when clipped.
    if label and len(label) >= 27 and rid:
        label = ""
    elif label and len(label) >= 27 and not rid:
        return None
    if "edittext" in cls_low:
        if label and label.casefold() not in ("input", "view", "edittext"):
            return f"Input text in {label}"
        if rid:
            return f"Input text in {rid.replace('_', ' ')}"
        return "Input text in field"
    if rid.startswith("nav_"):
        token = rid[4:].replace("_", " ").strip()
        if token:
            return f"Tap {token.title()}"
    if rid.startswith("navigation_"):
        token = rid[len("navigation_") :].replace("_", " ").strip()
        if token:
            return f"Tap {token.title()}"
    if label and label.casefold() not in _SKIP_DIGEST_LABELS:
        return f"Tap {label}"
    if rid:
        return f"Tap {rid.replace('_', ' ')}"
    return None


def _synthesize_tap_goals_from_digest(screen_map_text: str, *, max_n: int) -> list[str]:
    """Build forward tap/input goals from digest widget hints (offline-safe)."""
    controls = sorted(_parse_digest_controls(screen_map_text), key=_digest_control_priority)
    out: list[str] = []
    seen: set[str] = set()
    for c in controls:
        goal = _goal_text_for_digest_control(c)
        if not goal or _is_degenerate_transitions_goal(goal):
            continue
        key = goal.casefold()
        if key in seen:
            continue
        if not _goal_looks_concrete_actionable(goal):
            continue
        seen.add(key)
        out.append(goal)
        if len(out) >= max_n:
            break
    return out


def _append_back_and_wait_if_deep_enough(out: list[str], *, max_n: int) -> list[str]:
    """Only add generic back/wait when at least two forward goals exist."""
    forward = [g for g in out if _goal_is_forward(g)]
    if len(forward) < 2:
        return out[:max_n]
    if not any(_goal_requests_back_navigation(g) for g in out):
        out.append("Press Back to return to the main app list")
    if not any(str(g).casefold().startswith("wait ") for g in out):
        out.append("Wait for UI to settle")
    return out[:max_n]


def _merge_unique_goals(primary: list[str], extra: list[str], *, max_n: int) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for g in primary + extra:
        key = g.strip().casefold()
        if not key or key in seen:
            continue
        seen.add(key)
        merged.append(g.strip())
        if len(merged) >= max_n:
            break
    return merged


def _ensure_minimum_forward_goals(goals: list[str], screen_map_text: str) -> list[str]:
    """Guarantee at least _POST_EXPLORE_GOALS_MIN_KEEP forward goals; never back-only."""
    forward_count = sum(1 for g in goals if _goal_is_forward(g))
    if forward_count >= _POST_EXPLORE_GOALS_MIN_KEEP:
        return goals[:_POST_EXPLORE_GOALS_MAX]
    synthesized = _synthesize_tap_goals_from_digest(
        screen_map_text, max_n=_POST_EXPLORE_GOALS_MAX
    )
    merged = _merge_unique_goals(goals, synthesized, max_n=_POST_EXPLORE_GOALS_MAX)
    merged = _append_back_and_wait_if_deep_enough(merged, max_n=_POST_EXPLORE_GOALS_MAX)
    forward_after = sum(1 for g in merged if _goal_is_forward(g))
    if forward_after < _POST_EXPLORE_GOALS_MIN_KEEP:
        logging.warning(
            "Post-explore goals: digest synthesis yielded only %d forward goals (wanted %d).",
            forward_after,
            _POST_EXPLORE_GOALS_MIN_KEEP,
        )
    return merged[:_POST_EXPLORE_GOALS_MAX]


def _deterministic_goals_from_screen_map(screen_map_text: str, *, max_n: int) -> list[str]:
    """Fallback goals derived from digest anchors and parsed widget hints (offline-safe)."""
    anchors = _screen_map_anchors(screen_map_text)
    out: list[str] = []

    def push(s: str) -> None:
        if s not in out and len(out) < max_n:
            out.append(s)

    if "search" in anchors and _digest_requires_open_search_before_type(screen_map_text):
        push("Tap Search")
        push("Input search query")
    elif "search" in anchors:
        push("Input search query")
    if "categories" in anchors:
        push("Tap Categories")
    if "latest" in anchors:
        push("Tap Latest")
    if "nearby" in anchors:
        push("Tap Nearby")
    if "updates" in anchors:
        push("Tap Updates")
    if "settings" in anchors:
        push("Tap Settings")
    if "apps" in anchors:
        push("Tap Apps menu button")
    if "qr" in anchors:
        push("Open QR code scanner from Apps menu")
    if "send" in anchors:
        push("Open Send F-Droid from Apps menu")
    if "wifi" in anchors:
        push("Dismiss or acknowledge Wi-Fi hint if shown")
    if "permission" in anchors:
        push("Tap Deny on system permission dialog if shown")
    digest_goals = _synthesize_tap_goals_from_digest(screen_map_text, max_n=max_n)
    out = _merge_unique_goals(out, digest_goals, max_n=max_n)
    return _append_back_and_wait_if_deep_enough(out, max_n=max_n)

def _finalize_post_explore_goals(
    goals: list[str],
    screen_map_text: str,
    *,
    supplemental_goals: list[str] | None = None,
) -> list[str]:
    """Drop abstract / non-grounded goals; cap count; fall back to digest templates if too little remains."""
    if supplemental_goals:
        goals = _merge_unique_goals(goals, supplemental_goals, max_n=_POST_EXPLORE_GOALS_MAX)
    sm_low, anchors = _screen_map_for_goal_grounding(screen_map_text)
    filtered: list[str] = []
    for g in goals:
        if not g or not str(g).strip():
            continue
        if _is_degenerate_transitions_goal(g):
            continue
        if _BAD_UX_GOAL_RE.search(g):
            continue
        if _ABSTRACT_PLANNER_GOAL_RE.search(g):
            continue
        if not _goal_looks_concrete_actionable(g):
            continue
        if _POST_EXPLORE_STRICT_DIGEST and not _goal_references_screen_map(g, anchors, sm_low):
            continue
        filtered.append(g.strip())
    dedup: list[str] = []
    seen_g: set[str] = set()
    for g in filtered:
        k = g.casefold()
        if k in seen_g:
            continue
        seen_g.add(k)
        dedup.append(g)
    capped = _strip_unusable_ux_goal_strings(dedup[:_POST_EXPLORE_GOALS_MAX])
    enforced = _ensure_search_flow_goals(capped if capped else [], screen_map_text=screen_map_text)
    enforced = _strip_vague_back_goals(enforced)
    enforced = enforced[:_POST_EXPLORE_GOALS_MAX]
    if len(enforced) < _POST_EXPLORE_GOALS_MIN_KEEP or not _goals_have_minimum_actionability(
        enforced, minimum=min(4, _POST_EXPLORE_GOALS_MIN_KEEP)
    ):
        fb = _deterministic_goals_from_screen_map(screen_map_text, max_n=_POST_EXPLORE_GOALS_MAX)
        merged: list[str] = []
        seen: set[str] = set()
        for g in enforced + fb:
            k = g.strip().casefold()
            if k in seen:
                continue
            seen.add(k)
            merged.append(g)
            if len(merged) >= _POST_EXPLORE_GOALS_MAX:
                break
        enforced = merged[:_POST_EXPLORE_GOALS_MAX]
        logging.info(
            "Post-explore goals: merged planner output with digest template (%d goals).",
            len(enforced),
        )

    # Hard final gate: never emit abstract/non-actionable/non-digest goals.
    strict_final: list[str] = []
    for g in enforced:
        if _is_degenerate_transitions_goal(g):
            continue
        if _ABSTRACT_PLANNER_GOAL_RE.search(g):
            continue
        if not _goal_looks_concrete_actionable(g):
            continue
        if _POST_EXPLORE_STRICT_DIGEST and not _goal_references_screen_map(g, anchors, sm_low):
            continue
        strict_final.append(g)
    if strict_final:
        enforced = strict_final[:_POST_EXPLORE_GOALS_MAX]
    else:
        enforced = _deterministic_goals_from_screen_map(screen_map_text, max_n=_POST_EXPLORE_GOALS_MAX)
        logging.warning("Post-explore goals strict gate dropped all planner goals; using digest-only goals.")
    enforced = _reorder_goals_by_observed_ui_dependencies(
        enforced, screen_map_text=screen_map_text
    )
    enforced = _ensure_minimum_forward_goals(enforced, screen_map_text.split("\n\nTRANSITIONS:\n", 1)[0])
    enforced = [g for g in enforced if not _is_degenerate_transitions_goal(g)]
    return enforced[:_POST_EXPLORE_GOALS_MAX]

def _goal_looks_concrete_actionable(goal: str) -> bool:
    g = goal.strip().lower()
    if not g:
        return False
    if _ABSTRACT_PLANNER_GOAL_RE.search(g):
        return False
    abstract_terms = (
        "improve ",
        "enhance ",
        "optimize ",
        "refine ",
        "increase ",
        "reduce ",
        "accuracy",
        "user interface",
        "user experience",
        "context switching",
        "behavioral notes",
        "investigate",
        "architecture",
        "metadata",
    )
    if any(t in g for t in abstract_terms):
        return False
    # Require a concrete UI action verb.
    concrete_verbs = (
        "tap",
        "open",
        "press",
        "click",
        "select",
        "input",
        "type",
        "search",
        "back",
        "swipe",
        "scroll",
        "wait",
    )
    return any(g.startswith(v + " ") for v in concrete_verbs)

def _goals_have_minimum_actionability(goals: list[str], *, minimum: int = 4) -> bool:
    return sum(1 for g in goals if _goal_looks_concrete_actionable(g)) >= minimum

def _goal_implies_launch_search_surface(goal: str) -> bool:
    """True when the stated goal is about opening search chrome (FAB/toolbar), not typing a query."""
    g = goal.lower()
    if "search" not in g and "find" not in g:
        return False
    if any(k in g for k in ("enter", "type", "input", "fill", "select from", "choose from")):
        return False
    return any(k in g for k in ("tap", "open", "press", "touch", "click", "fab", "button", "icon"))

def _nav_token_from_blob(blob: str) -> str:
    low = (blob or "").lower()
    if "categor" in low:
        return "categories"
    for token in _NAV_TOKEN_ORDER:
        if token in low:
            return token
    return ""

def _goal_nav_token(goal: str) -> str:
    return _nav_token_from_blob(goal or "")

def _action_nav_token(action: dict[str, Any]) -> str:
    if str(action.get("action_type") or "") != "tap":
        return ""
    blob = " ".join(
        [
            str(action.get("target_resource_id") or ""),
            str(action.get("target_content_desc") or ""),
            str(action.get("target_text") or ""),
        ]
    )
    token = _nav_token_from_blob(blob)
    if token == "apps" and "fab_search" in blob.lower():
        return ""
    return token

def _visible_bottom_nav_tokens(elements: list[dict[str, str]]) -> list[str]:
    """Visible bottom/tab navigation labels; interior buttons with similar text are ignored."""
    bottom = _hierarchy_max_bottom_y(elements)
    out: list[str] = []
    for e in elements:
        rid = str(e.get("resource_id") or "")
        cd = str(e.get("content_desc") or "")
        txt = str(e.get("text") or "")
        cls = str(e.get("class_name") or "").lower()
        blob = f"{rid} {cd} {txt}"
        token = _nav_token_from_blob(blob)
        if not token:
            continue
        frac = _bounds_vertical_center_fraction(e.get("bounds", ""), bottom)
        nav_like = (
            frac is not None
            and frac >= 0.66
            or "tab" in cls
            or "framelayout" in cls
            or "navigation" in rid.lower()
            or "bottom" in rid.lower()
        )
        if nav_like and token not in out:
            out.append(token)
    return out

def _infer_active_nav_token(
    visible_nav_tokens: list[str],
    previous_nav_token: str = "",
) -> tuple[str, str]:
    visible = set(visible_nav_tokens)
    prev = (previous_nav_token or "").strip().lower()
    if prev and prev in _NAV_TOKEN_ORDER and prev not in visible and visible:
        return prev, "previous_successful_nav_tap"
    common_visible = visible & set(_COMMON_BOTTOM_NAV_TOKENS)
    if len(common_visible) >= 3:
        missing = [tok for tok in _COMMON_BOTTOM_NAV_TOKENS if tok not in common_visible]
        if len(missing) == 1:
            return missing[0], "inferred_missing_selected_tab"
    return "", ""

def _derive_app_screen_state(
    elements: list[dict[str, str]],
    target_pkg: str,
    *,
    foreground_pkg: str | None = None,
    previous_nav_token: str = "",
) -> dict[str, Any]:
    """Small semantic state snapshot shared by goal evaluation, prompts, and logs."""
    visible_nav = _visible_bottom_nav_tokens(elements)
    active_nav, active_nav_source = _infer_active_nav_token(visible_nav, previous_nav_token)
    search_open = _screen_is_search_typing_surface(elements)
    dialog_state = _derive_dialog_state(foreground_pkg, elements, target_pkg)
    dialog_visible = bool(dialog_state.get("visible"))
    if dialog_state.get("kind") == "permission":
        screen_role = "permission_dialog"
    elif dialog_visible and dialog_state.get("kind") not in ("none", "transient"):
        screen_role = "system_dialog"
    elif search_open:
        screen_role = "search"
    elif _screen_has_edittext_for_typing(elements):
        screen_role = "text_entry"
    elif active_nav or visible_nav:
        screen_role = "tab_surface"
    elif _screen_is_empty_state(elements):
        screen_role = "empty_state"
    elif elements:
        screen_role = "content"
    else:
        screen_role = "empty_hierarchy"
    return {
        "screen_role": screen_role,
        "foreground_package": foreground_pkg or "",
        "active_nav_token": active_nav,
        "active_nav_source": active_nav_source,
        "visible_nav_tokens": visible_nav,
        "search_open": search_open,
        "search_launch_visible": _screen_has_search_launch_affordance(elements),
        "text_entry_visible": _screen_has_edittext_for_typing(elements),
        "permission_dialog_visible": dialog_state.get("kind") == "permission",
        "dialog_visible": dialog_visible,
        "dialog_kind": dialog_state.get("kind") or "none",
        "dialog_policy": dialog_state.get("policy") or "",
        "dialog_token": dialog_state.get("token") or "",
    }

def _pick_search_launch_tap_from_elements(
    elements: list[dict[str, str]], target_pkg: str
) -> dict[str, Any] | None:
    for e in elements:
        rid = str(e.get("resource_id") or "").strip()
        pref = _resource_id_owner_package(rid)
        if pref and pref != target_pkg:
            continue
        cn = (e.get("class_name") or "").lower()
        cd = str(e.get("content_desc") or "").strip()
        blob = f"{rid} {cd}".lower()
        if "fab_search" in blob or (cd.lower() == "search" and "imagebutton" in cn):
            center = _bounds_center(e.get("bounds", ""))
            if center is None:
                continue
            return {
                "action_type": "tap",
                "target_resource_id": rid,
                "target_content_desc": cd,
                "x": int(center[0]),
                "y": int(center[1]),
                "reason": "engine_open_search_before_input",
            }
    return None

def _coerce_search_input_to_open_when_needed(
    action: dict[str, Any],
    elements: list[dict[str, str]],
    *,
    ux_goals: list[str] | None,
    ux_goal_idx: int,
    target_pkg: str,
) -> dict[str, Any]:
    """If the active goal needs a text field but only launch chrome is visible, tap open-search first."""
    if str(action.get("action_type") or "") != "input":
        return action
    if ux_goals and 0 <= ux_goal_idx < len(ux_goals):
        if not _goal_needs_text_entry_field(ux_goals[ux_goal_idx]):
            return action
    elif not _goal_needs_text_entry_field(str(action.get("reason") or "")):
        return action
    if _screen_has_edittext_for_typing(elements):
        return action
    launch = _pick_search_launch_tap_from_elements(elements, target_pkg)
    if launch:
        logging.info(
            "No EditText on screen for input goal; opening search affordance first (%s).",
            launch.get("target_resource_id") or launch.get("target_content_desc"),
        )
        return launch
    return action

def _goal_feasible_on_elements(goal: str, elements: list[dict[str, str]]) -> bool:
    """Heuristic feasibility check: can current UI plausibly satisfy the goal now?"""
    g = (goal or "").strip().lower()
    if not g:
        return True
    if any(k in g for k in ("back", "return", "go back", "previous")):
        return True
    if _goal_needs_text_entry_field(g):
        return _screen_has_edittext_for_typing(elements)
    if _goal_opens_search_ui(g):
        # Opening search means FAB/toolbar — not an already-open query field (see _goal_execute_status).
        return _screen_has_search_launch_affordance(elements)
    if any(k in g for k in ("search", "query", "filter")):
        return _screen_has_search_entry_widget(elements)
    nav_token = _goal_nav_token(goal)
    if nav_token:
        return nav_token in _visible_bottom_nav_tokens(elements)

    blobs = [
        " ".join(
            (
                str(e.get("text") or ""),
                str(e.get("content_desc") or ""),
                str(e.get("resource_id") or ""),
                str(e.get("class_name") or ""),
            )
        ).lower()
        for e in elements
    ]
    # Pull simple noun-ish tokens from the goal and see if UI currently contains them.
    tokens = [t for t in re.findall(r"[a-z][a-z0-9_]{2,}", g) if t not in {"tap", "open", "press", "click", "view"}]
    if not tokens:
        return bool(elements)
    joined = "\n".join(blobs)
    hits = sum(1 for t in tokens[:4] if t in joined)
    return hits >= 1

def _visible_content_nav_control(nav_token: str, elements: list[dict[str, str]]) -> bool:
    """Non-bottom-nav controls (e.g. Settings LinearLayout) visible by label."""
    token = (nav_token or "").strip().casefold()
    if not token:
        return False
    for e in elements:
        cd = str(e.get("content_desc") or "").strip().casefold()
        txt = str(e.get("text") or "").strip().casefold()
        if token not in (cd, txt) and token not in cd and token not in txt:
            continue
        if _bounds_center(e.get("bounds", "")) is not None:
            return True
    return False

def _nav_goal_recently_satisfied(
    nav_token: str,
    recent_actions: list[dict[str, Any]] | None,
) -> bool:
    """True after a successful nav tap that changed the screen (home-row Settings, etc.)."""
    token = (nav_token or "").strip().casefold()
    if not token or not recent_actions:
        return False
    for ev in reversed(recent_actions[-6:]):
        pa = ev.get("parsed_action") or {}
        if str(pa.get("action_type") or "") != "tap" or not ev.get("action_success"):
            continue
        blob = " ".join(
            [
                str(pa.get("target_content_desc") or ""),
                str(pa.get("target_resource_id") or ""),
                str(pa.get("reason") or ""),
            ]
        ).casefold()
        if token not in blob and f":id/{token}" not in blob:
            continue
        sh_before = ev.get("screen_hash")
        sh_after = ev.get("screen_hash_after")
        if sh_before and sh_after and sh_before != sh_after:
            return True
    return False

def _resource_id_looks_like_search_launch(rid: str) -> bool:
    """Heuristic on resource_id alone (planner/engine action logs lack class_name)."""
    rid_low = (rid or "").strip().lower()
    if not rid_low:
        return False
    stub = {"resource_id": rid, "class_name": "Button", "content_desc": "", "text": ""}
    if _is_false_positive_search_launch_widget(stub):
        return False
    if any(tok in rid_low for tok in ("fab_search", "search_button", "scanbutton")):
        return True
    if "search" in rid_low and "fab" in rid_low:
        return True
    return False

def _action_tapped_search_launch(action: dict[str, Any]) -> bool:
    reason = str(action.get("reason") or "")
    if reason.startswith("engine_route_tap_search"):
        return True
    return _resource_id_looks_like_search_launch(str(action.get("target_resource_id") or ""))

def _search_open_goal_recently_satisfied(
    recent_actions: list[dict[str, Any]] | None,
) -> bool:
    """True after a successful search-launch tap that opened search/scanner chrome."""
    if not recent_actions:
        return False
    for ev in reversed(recent_actions[-6:]):
        pa = ev.get("parsed_action") or {}
        if str(pa.get("action_type") or "") != "tap" or not ev.get("action_success"):
            continue
        if not _action_tapped_search_launch(pa):
            continue
        sh_before = ev.get("screen_hash")
        sh_after = ev.get("screen_hash_after")
        if sh_before and sh_after and sh_before != sh_after:
            return True
        reason = str(pa.get("reason") or "")
        if not sh_after and reason.startswith("engine_route_tap_search"):
            return True
    return False

def _screen_looks_like_search_entry_overlay(elements: list[dict[str, str]]) -> bool:
    """Post-open scanner/camera surfaces — no FAB or EditText but search goal is done."""
    for e in elements:
        rid = (e.get("resource_id") or "").lower()
        if any(
            tok in rid
            for tok in (
                "scannerpaste",
                "scannergallery",
                "scannerinstruction",
                "qrscanner",
                "barcodescanner",
                "barcode_scanner",
            )
        ):
            return True
    return False

def _goal_execute_status(
    goal: str,
    elements: list[dict[str, str]],
    recent_actions: list[dict[str, Any]] | None = None,
    app_state: dict[str, Any] | None = None,
    *,
    target_pkg: str = "",
) -> str:
    """Observation-based goal state for execute prompts: satisfied | feasible | blocked."""
    g = (goal or "").strip().lower()
    if not g:
        return "feasible"
    if g.startswith("wait "):
        return "satisfied"
    if _goal_requests_back_navigation(goal):
        visible_nav = set((app_state or {}).get("visible_nav_tokens") or [])
        if len(visible_nav) >= 3 and not bool((app_state or {}).get("search_open")):
            return "satisfied"
        return "feasible"
    if "permission" in g and ("deny" in g or "allow" in g):
        if not (app_state or {}).get("permission_dialog_visible"):
            if not _hierarchy_shows_permission_dialog(elements, target_pkg):
                return "satisfied"
    nav_token = _goal_nav_token(goal)
    if nav_token and nav_token != "apps":
        active_nav = str((app_state or {}).get("active_nav_token") or "")
        visible_nav = set((app_state or {}).get("visible_nav_tokens") or [])
        if active_nav == nav_token:
            return "satisfied"
        if _nav_goal_recently_satisfied(nav_token, recent_actions):
            return "satisfied"
        if nav_token in visible_nav:
            return "feasible"
        if _visible_content_nav_control(nav_token, elements):
            return "feasible"
        return "blocked"
    if _goal_opens_search_ui(goal):
        if _search_open_goal_recently_satisfied(recent_actions):
            return "satisfied"
        has_launch = bool((app_state or {}).get("search_launch_visible")) or _screen_has_search_launch_affordance(
            elements
        )
        has_type = bool((app_state or {}).get("text_entry_visible")) or _screen_has_edittext_for_typing(elements)
        if has_type:
            return "satisfied"
        if has_launch:
            return "feasible"
        if bool((app_state or {}).get("search_open")):
            return "satisfied"
        if _screen_looks_like_search_entry_overlay(elements):
            return "satisfied"
        return "blocked"
    if _goal_needs_text_entry_field(goal):
        if _typing_goal_recently_satisfied(recent_actions):
            return "satisfied"
        return "feasible" if _screen_has_edittext_for_typing(elements) else "blocked"
    if not _goal_feasible_on_elements(goal, elements):
        return "blocked"
    if recent_actions and not _goal_has_text_entry_verbs(goal):
        tail = recent_actions[-3:]
        taps = [
            ev
            for ev in tail
            if str((ev.get("parsed_action") or {}).get("action_type")) == "tap"
            and ev.get("action_success")
        ]
        if len(taps) >= 2:
            unchanged = sum(
                1
                for ev in taps
                if ev.get("screen_hash")
                and ev.get("screen_hash") == ev.get("screen_hash_after")
            )
            if unchanged >= 2:
                return "satisfied"
    return "feasible"

def _search_launch_ids_on_screen(elements: list[dict[str, str]]) -> list[str]:
    out: list[str] = []
    for e in elements:
        if not _is_definite_search_launch_widget(e):
            continue
        rid = str(e.get("resource_id") or "").strip()
        if rid and rid not in out:
            out.append(rid)
    return out[:6]

def _edittext_ids_on_screen(elements: list[dict[str, str]]) -> list[str]:
    out: list[str] = []
    for e in elements:
        cn = (e.get("class_name") or "").lower()
        if "edittext" in cn or "autocomplete" in cn:
            rid = str(e.get("resource_id") or "").strip()
            if rid:
                out.append(rid)
    return out[:6]

def _goal_action_hint(
    goal: str,
    status: str,
    elements: list[dict[str, str]],
    app_state: dict[str, Any] | None = None,
    recent_actions: list[dict[str, Any]] | None = None,
) -> str:
    """Concrete next-step guidance derived from goal text + current hierarchy."""
    if status == "satisfied":
        nav_token = _goal_nav_token(goal)
        if nav_token:
            return (
                f"The {nav_token} navigation destination is already active according to APP_STATE. "
                "Return {\"action_type\":\"advance_goal\",\"reason\":\"active_navigation_destination\"}."
            )
        if _goal_opens_search_ui(goal):
            return (
                "Search/scanner entry is already open. "
                "Return {\"action_type\":\"advance_goal\",\"reason\":\"search_ui_open\"} — do NOT tap Search again."
            )
        return (
            "This goal looks complete on the current screen. "
            "Return {\"action_type\":\"advance_goal\",\"reason\":\"goal_satisfied_on_screen\"}."
        )
    if status == "blocked":
        if _goal_opens_search_ui(goal):
            if _search_open_goal_recently_satisfied(recent_actions):
                return (
                    "Search/scanner was opened on the previous step. "
                    "Return {\"action_type\":\"advance_goal\",\"reason\":\"search_ui_opened\"} — do NOT tap scanner controls."
                )
            if _screen_looks_like_search_entry_overlay(elements):
                return (
                    "Scanner/search entry overlay is already open. "
                    "Return {\"action_type\":\"advance_goal\",\"reason\":\"search_scanner_open\"} — do NOT tap paste/gallery controls."
                )
            visible_ids = _allowed_resource_ids_from_elements(elements)
            if not visible_ids:
                return (
                    "No app controls are visible. Do not invent resource_ids; return wait or advance_goal. "
                    "The runner may restore the app root if the hierarchy remains empty."
                )
            tab_ids = [
                rid
                for rid in visible_ids
                if any(
                    token in rid.lower()
                    for token in ("categor", "latest", "nearby", "updates", "settings", "home")
                )
            ]
            if tab_ids:
                return (
                    "No search-launch control is visible. Tap one exact visible navigation id: "
                    + ", ".join(tab_ids[:8])
                    + ". Do not invent alternative ids."
                )
            return (
                "No search-launch control is visible. Use only exact ids from ALLOWED_TARGET_RESOURCE_IDS, "
                "or return advance_goal if none matches. Do not invent ids."
            )
        if _goal_needs_text_entry_field(goal):
            launch = _search_launch_ids_on_screen(elements)
            if launch:
                return (
                    "No query field visible yet. Tap a search-launch control first: "
                    + ", ".join(launch)
                    + " — then the next goal will be typing."
                )
            return (
                "No query field is visible. Use only exact visible ids to open search, or advance_goal."
            )
        nav_token = _goal_nav_token(goal)
        visible_nav = set((app_state or {}).get("visible_nav_tokens") or [])
        if nav_token and visible_nav:
            return (
                "Goal navigation target is not active. Visible navigation destinations are: "
                + ", ".join(sorted(visible_nav))
                + ". Tap the matching exact id from ALLOWED_TARGET_RESOURCE_IDS, or advance_goal if already done."
            )
        return (
            "Goal control not visible now. Pick an exact id from ALLOWED_TARGET_RESOURCE_IDS that matches "
            "the goal, or advance_goal."
        )
    # feasible
    if _goal_needs_text_entry_field(goal):
        fields = _edittext_ids_on_screen(elements)
        if fields:
            return (
                "Use action_type=input with a non-empty text string (full query) on: "
                + ", ".join(fields)
                + ". Omit submit_search or set true so the runner submits."
            )
    if _goal_opens_search_ui(goal):
        launch = _search_launch_ids_on_screen(elements)
        if launch:
            return "Tap exactly one search-launch id from: " + ", ".join(launch)
        return "Tap the visible Search FAB/button listed in ALLOWED_TARGET_RESOURCE_IDS."
    g = goal.lower()
    if "categor" in g:
        return "Tap the Categories bottom-nav control (resource_id containing categories) from ALLOWED list."
    for tab in ("updates", "latest", "nearby", "settings"):
        if tab in g:
            return f"Tap the {tab.title()} bottom-nav control from ALLOWED_TARGET_RESOURCE_IDS."
    return "Use action_type tap on a control from ALLOWED_TARGET_RESOURCE_IDS that matches the goal."

def _digest_search_recovery_tab_tokens(
    exploration_digest: dict[str, str], *, prefer_type_surface: bool
) -> list[str]:
    """Bottom-nav tab labels on digest screens that showed search launch or query fields."""
    priority = ("categories", "latest", "updates", "settings", "explore", "home")
    found: list[str] = []
    seen: set[str] = set()
    for hint in exploration_digest.values():
        can_type, can_launch = _digest_line_search_observation(hint)
        low = hint.lower()
        if prefer_type_surface:
            if not can_type:
                continue
        elif not (can_launch or can_type):
            continue
        if not any(k in low for k in ("fab_search", "edittext", "search")):
            continue
        if "find_people" in low and "fab_search" not in low:
            continue
        for tab in priority:
            if tab in low and tab not in seen:
                seen.add(tab)
                found.append(tab)
    return found

def _goal_recovery_tab_tokens(goal: str, exploration_digest: dict[str, str]) -> list[str]:
    g = (goal or "").strip().lower()
    if _goal_opens_search_ui(goal) or _goal_needs_text_entry_field(goal):
        return _digest_search_recovery_tab_tokens(
            exploration_digest, prefer_type_surface=_goal_needs_text_entry_field(goal)
        )
    tokens: list[str] = []
    if "categor" in g:
        tokens.append("categories")
    for tab in ("latest", "nearby", "updates", "settings", "apps", "explore", "home"):
        if tab in g:
            tokens.append(tab)
    return tokens

def _pick_execute_nav_recovery_for_blocked_goal(
    goal: str,
    elements: list[dict[str, str]],
    *,
    exploration_digest: dict[str, str],
    target_pkg: str,
    attempt_index: int,
) -> dict[str, Any] | None:
    """One-shot nav toward a digest screen where the blocked goal can run (tab, then back)."""
    if attempt_index >= 2:
        return None
    if attempt_index == 1:
        return {"action_type": "back", "reason": "engine_nav_recovery_back"}
    tab_tokens = _goal_recovery_tab_tokens(goal, exploration_digest)
    if not tab_tokens:
        return None
    from .navigation import _build_tab_targets

    tab_targets = _build_tab_targets(elements)
    for tab_token in tab_tokens:
        for act in tab_targets:
            pref = _resource_id_owner_package(str(act.get("target_resource_id") or ""))
            if pref and pref != target_pkg:
                continue
            rid_tail = str(act.get("target_resource_id") or "").split("/")[-1].lower()
            blob = " ".join(
                (
                    str(act.get("target_resource_id") or ""),
                    str(act.get("target_content_desc") or ""),
                    rid_tail,
                )
            ).lower()
            if tab_token == "categories":
                matched = "categor" in blob
            elif tab_token == "apps":
                matched = "apps" in blob or "btn_apps" in blob
            else:
                matched = tab_token in blob
            if not matched:
                continue
            out = dict(act)
            out["reason"] = "engine_nav_recovery_toward_goal"
            return out
    return None

def _plan_ux_goals(app_context: dict[str, Any], model: str, endpoint: str) -> list[str]:
    prompt = (
        "You plan black-box UX exploration for Android QA.\n"
        "The target app is ALREADY RUNNING in the foreground — do NOT include goals about "
        "launching, installing, opening, or starting the app.\n"
        "Output JSON ONLY: {\"goals\":[\"...\", ...]} with 4-7 short imperative goals "
        "(distinct in-app user intents). Achievable using tap, input text, back, wait only.\n"
        "Goals MUST diversify navigation across the app: mix browsing lists or categories, opening one detail "
        "view, visiting preferences/settings once, using search/query when sensible, and main navigation "
        "(tabs, drawer, bottom bar). Avoid multiple goals that repeat the same single-screen tap.\n"
        "Include at least one goal about using search or query if the app type suggests it.\n\n"
        f"APP_CONTEXT:\n{json.dumps(app_context, ensure_ascii=False)}\n"
    )
    try:
        raw = _ollama_generate_with_retries(prompt, model, endpoint)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        logging.warning("UX goal planning failed; using default goals.")
        return list(_DEFAULT_UX_GOALS)
    goals = _parse_ux_goals_from_plan(raw)
    if not goals:
        logging.warning("Could not parse UX goals from planner output; using defaults.")
        return list(_DEFAULT_UX_GOALS)
    cleaned = _sanitize_ux_goal_strings(goals)
    if len(cleaned) != len(goals):
        logging.info("Dropped %d unusable UX goals (launch/install wording).", len(goals) - len(cleaned))
    return cleaned

def _goal_requires_planner_input(goal: str) -> bool:
    return _goal_needs_text_entry_field(goal) or _goal_has_text_entry_verbs(goal)

def _goal_hint_for_repair(ux_goals: list[str] | None, ux_goal_idx: int) -> str:
    if ux_goals and 0 <= ux_goal_idx < len(ux_goals):
        return ux_goals[ux_goal_idx].lower()
    return ""
