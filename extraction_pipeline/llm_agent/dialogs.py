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
from .screen import _bounds_center, _resource_id_owner_package
from .config import (
    _FOREGROUND_DIALOG_PACKAGES,
    _FOREGROUND_TRANSIENT_PACKAGES,
    _PERMISSION_DIALOG_PACKAGES,
    _SETTINGS_PACKAGES,
)

def _package_is_foreign_dialog_surface(package_prefix: str) -> bool:
    return bool(package_prefix) and package_prefix in _FOREGROUND_DIALOG_PACKAGES

def _package_is_permission_dialog_surface(package_prefix: str) -> bool:
    return bool(package_prefix) and package_prefix in _PERMISSION_DIALOG_PACKAGES

def _element_is_foreign_dialog_widget(e: dict[str, str], target_pkg: str) -> bool:
    pref = _resource_id_owner_package(str(e.get("resource_id") or ""))
    if not pref or pref == target_pkg:
        return False
    return _package_is_foreign_dialog_surface(pref)

def _action_is_foreign_dialog_widget(action: dict[str, Any], target_pkg: str) -> bool:
    pref = _resource_id_owner_package(str(action.get("target_resource_id") or ""))
    if not pref or pref == target_pkg:
        return False
    return _package_is_foreign_dialog_surface(pref)

def _nav_key_is_foreign_dialog(nav_key: str, target_pkg: str) -> bool:
    rid = nav_key.split("|", 1)[0].strip()
    pref = _resource_id_owner_package(rid)
    if not pref or pref == target_pkg:
        return False
    return _package_is_foreign_dialog_surface(pref)

def _hierarchy_shows_foreign_dialog(elements: list[dict[str, str]], target_pkg: str) -> bool:
    foreign = 0
    target = 0
    for e in elements:
        pref = _resource_id_owner_package(str(e.get("resource_id") or ""))
        if not pref:
            continue
        if pref == target_pkg:
            target += 1
        elif _package_is_foreign_dialog_surface(pref):
            foreign += 1
    return foreign >= 1 and (target == 0 or foreign >= target)

def _hierarchy_shows_permission_dialog(elements: list[dict[str, str]], target_pkg: str) -> bool:
    perm = 0
    target = 0
    for e in elements:
        pref = _resource_id_owner_package(str(e.get("resource_id") or ""))
        if not pref:
            continue
        if pref == target_pkg:
            target += 1
        elif _package_is_permission_dialog_surface(pref):
            perm += 1
    return perm >= 1 and (target == 0 or perm >= target)

def _dominant_permission_dialog_package(elements: list[dict[str, str]], target_pkg: str) -> str:
    counts: dict[str, int] = {}
    for e in elements:
        pref = _resource_id_owner_package(str(e.get("resource_id") or ""))
        if pref and pref != target_pkg and _package_is_permission_dialog_surface(pref):
            counts[pref] = counts.get(pref, 0) + 1
    if not counts:
        return ""
    return max(counts.items(), key=lambda item: item[1])[0]

def _derive_dialog_state(
    fg_now: Optional[str],
    elements: list[dict[str, str]],
    target_pkg: str,
) -> dict[str, str | bool]:
    """Central dialog/surface classification shared by app state, BFS, and scoring."""
    fg = (fg_now or "").strip()
    if fg and fg != target_pkg and _package_is_permission_dialog_surface(fg):
        return {
            "visible": True,
            "kind": "permission",
            "package": fg,
            "token": f"fg_perm:{fg}",
            "policy": "dismiss_once",
        }
    perm_pkg = _dominant_permission_dialog_package(elements, target_pkg)
    if perm_pkg and _hierarchy_shows_permission_dialog(elements, target_pkg):
        return {
            "visible": True,
            "kind": "permission",
            "package": perm_pkg,
            "token": f"hier_perm:{perm_pkg}",
            "policy": "dismiss_once",
        }
    if fg and fg != target_pkg and fg in _SETTINGS_PACKAGES:
        return {
            "visible": True,
            "kind": "settings",
            "package": fg,
            "token": f"fg_settings:{fg}",
            "policy": "recover_to_target",
        }
    if fg and fg != target_pkg and _package_is_foreign_dialog_surface(fg):
        return {
            "visible": True,
            "kind": "foreign_dialog",
            "package": fg,
            "token": f"fg_dialog:{fg}",
            "policy": "recover_to_target",
        }
    if _hierarchy_shows_foreign_dialog(elements, target_pkg):
        return {
            "visible": True,
            "kind": "foreign_dialog",
            "package": "",
            "token": "hier_dialog",
            "policy": "recover_to_target",
        }
    if fg and fg != target_pkg and fg in _FOREGROUND_TRANSIENT_PACKAGES:
        return {
            "visible": True,
            "kind": "transient",
            "package": fg,
            "token": f"fg_transient:{fg}",
            "policy": "wait",
        }
    return {"visible": False, "kind": "none", "package": "", "token": "", "policy": ""}

def _bfs_system_dialog_surface_token(
    fg_now: Optional[str],
    elements: list[dict[str, str]],
    target_pkg: str,
) -> str:
    state = _derive_dialog_state(fg_now, elements, target_pkg)
    if state.get("kind") == "permission":
        return str(state.get("token") or "")
    return ""

def _element_is_permission_dialog_widget(e: dict[str, str], target_pkg: str) -> bool:
    pref = _resource_id_owner_package(str(e.get("resource_id") or ""))
    if not pref or pref == target_pkg:
        return False
    return _package_is_permission_dialog_surface(pref)

def _pick_system_dialog_dismiss_action(
    elements: list[dict[str, str]], target_pkg: str
) -> dict[str, Any] | None:
    """One-shot dismiss for permission overlays — prefer Allow/OK over Deny."""
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
        if "don't allow" in blob or "dont allow" in blob:
            pri = 60
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
            "reason": "bfs_system_dialog_dismiss",
        }
        scored.append(((pri, _action_signature_for_candidate(act)), act))
    if not scored:
        return None
    scored.sort(key=lambda item: item[0])
    return dict(scored[0][1])

def _dialog_policy_action(
    dialog_state: dict[str, str | bool],
    elements: list[dict[str, str]],
    target_pkg: str,
    dismissed_tokens: set[str],
) -> dict[str, Any] | None:
    token = str(dialog_state.get("token") or "")
    kind = str(dialog_state.get("kind") or "none")
    policy = str(dialog_state.get("policy") or "")
    if not token or token in dismissed_tokens:
        return None
    if kind == "permission" and policy == "dismiss_once":
        return _pick_system_dialog_dismiss_action(elements, target_pkg)
    if policy == "recover_to_target":
        return {"action_type": "back", "reason": "dialog_policy_recover_to_target"}
    return None

def _first_non_foreign_bfs_candidate(
    candidates: list[dict[str, Any]], target_pkg: str
) -> dict[str, Any] | None:
    for c in candidates:
        if not _action_is_foreign_dialog_widget(c, target_pkg):
            return dict(c)
    return None


_PERMISSION_RISK_RID_RE = re.compile(
    r"(find_people|find.?people.?nearby|nearby_people|enable_nearby|turn_on_nearby)",
    re.IGNORECASE,
)


def _action_is_permission_risk(action: dict[str, Any]) -> bool:
    rid = str(action.get("target_resource_id") or "").lower()
    cd = str(action.get("target_content_desc") or "").lower()
    blob = f"{rid} {cd}"
    if _PERMISSION_RISK_RID_RE.search(blob):
        return True
    # Nearby tab flows that open the system location sheet (F-Droid and similar apps).
    if "find" in blob and "people" in blob:
        return True
    if "find" in blob and "nearby" in blob and "button" in rid:
        return True
    return False

def _bfs_mark_permission_risk_if_triggered(
    action: dict[str, Any],
    *,
    ok: bool,
    screen_hash_before: str,
    screen_hash_after: str,
    elements_after: list[dict[str, str]],
    target_pkg: str,
    attempted: set[str],
) -> None:
    if not _action_is_permission_risk(action):
        return
    dialog_visible = _hierarchy_shows_permission_dialog(elements_after, target_pkg)
    screen_changed = bool(screen_hash_after and screen_hash_after != screen_hash_before)
    if dialog_visible or (ok and screen_changed):
        attempted.add(_nav_target_key(action))

def _bfs_filter_expand_candidates(
    candidates: list[dict[str, Any]],
    target_pkg: str,
    permission_risk_keys_attempted: set[str],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for c in candidates:
        if _action_is_foreign_dialog_widget(c, target_pkg):
            continue
        k = _nav_target_key(c)
        if _action_is_permission_risk(c) and k in permission_risk_keys_attempted:
            continue
        out.append(c)
    return out
