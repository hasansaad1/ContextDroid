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
from .config import (
    _BROWSER_PACKAGES,
    _FILTER_FOREIGN_WIDGETS,
    _FOREGROUND_DIALOG_PACKAGES,
    _MAX_AGENT_XML_TOKENS,
    _UI_DUMP_TIMEOUT_SEC,
)
def _is_visible_and_interactive(node: ET.Element) -> bool:
    if node.attrib.get("enabled", "true") != "true":
        return False
    clickable = node.attrib.get("clickable", "false") == "true"
    long_clickable = node.attrib.get("long-clickable", "false") == "true"
    focusable = node.attrib.get("focusable", "false") == "true"
    cls_l = node.attrib.get("class", "").lower()
    text_entry_widget = (
        "edittext" in cls_l
        or "autocompletetextview" in cls_l
        or "multiautocompletetextview" in cls_l
        or "searchauto" in cls_l
    )
    if not (clickable or long_clickable or (focusable and text_entry_widget)):
        return False
    center = _bounds_center(node.attrib.get("bounds", ""))
    if center is None:
        return False
    return True


def _bounds_center(bounds: str) -> tuple[int, int] | None:
    m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds or "")
    if not m:
        return None
    x1, y1, x2, y2 = map(int, m.groups())
    if x2 <= x1 or y2 <= y1:
        return None
    return (x1 + x2) // 2, (y1 + y2) // 2

def _normalized_elements(xml_text: str) -> list[dict[str, str]]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    elements: list[dict[str, str]] = []
    for node in root.iter("node"):
        if not _is_visible_and_interactive(node):
            continue
        item = {
            "package": node.attrib.get("package", "").strip(),
            "resource_id": node.attrib.get("resource-id", "").strip(),
            "content_desc": node.attrib.get("content-desc", "").strip(),
            "text": node.attrib.get("text", "").strip(),
            "class_name": node.attrib.get("class", "").strip(),
            "bounds": node.attrib.get("bounds", "").strip(),
            "clickable": node.attrib.get("clickable", "false").strip(),
        }
        elements.append(item)
    elements.sort(
        key=lambda x: (
            x["package"],
            x["resource_id"],
            x["content_desc"],
            x["text"],
            x["class_name"],
            x["bounds"],
        )
    )
    return elements

def _token_trim_elements(elements: list[dict[str, str]]) -> list[dict[str, str]]:
    prioritized = sorted(
        elements,
        key=lambda e: (
            0 if e["resource_id"] else 1,
            0 if e["content_desc"] else 1,
            e["class_name"],
        ),
    )
    trimmed: list[dict[str, str]] = []
    budget = 0
    for e in prioritized:
        est = max(1, len(json.dumps(e)) // 4)
        if budget + est > _MAX_AGENT_XML_TOKENS:
            break
        trimmed.append(e)
        budget += est
    return trimmed

def _screen_hash(elements: list[dict[str, str]]) -> str:
    payload = json.dumps(elements, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def _screen_root_signature(elements: list[dict[str, str]], target_pkg: str) -> str:
    """App-owned screen signature used as a strict fallback when non-app nodes vary."""
    items: list[dict[str, str]] = []
    for e in elements:
        rid = str(e.get("resource_id") or "").strip()
        node_pkg = str(e.get("package") or "").strip()
        owner_pkg = _resource_id_owner_package(rid)
        app_owned = node_pkg == target_pkg or owner_pkg == target_pkg
        if not app_owned:
            continue
        items.append(
            {
                "package": target_pkg,
                "resource_id": rid,
                "content_desc": str(e.get("content_desc") or "").strip(),
                "text": str(e.get("text") or "").strip(),
                "class_name": str(e.get("class_name") or "").strip(),
                "bounds": str(e.get("bounds") or "").strip(),
            }
        )
    if not items:
        return ""
    items.sort(
        key=lambda x: (
            x["resource_id"],
            x["content_desc"],
            x["text"],
            x["class_name"],
            x["bounds"],
        )
    )
    payload = json.dumps(items, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def _filter_widgets_for_target(elements: list[dict[str, str]], package_name: str) -> list[dict[str, str]]:
    if not _FILTER_FOREIGN_WIDGETS:
        return elements
    kept: list[dict[str, str]] = []
    for e in elements:
        rid = (e.get("resource_id") or "").strip()
        node_pkg = (e.get("package") or "").strip()
        if node_pkg and node_pkg != package_name and node_pkg not in _FOREGROUND_DIALOG_PACKAGES:
            continue
        if not rid:
            kept.append(e)
            continue
        if rid.startswith("android:id/"):
            kept.append(e)
            continue
        if ":id/" in rid:
            prefix = rid.split(":id/", 1)[0]
            if prefix == package_name:
                kept.append(e)
                continue
            if prefix in _FOREGROUND_DIALOG_PACKAGES:
                kept.append(e)
                continue
            if prefix in _BROWSER_PACKAGES:
                continue
            continue
        kept.append(e)
    return kept

def _target_app_widget_count(elements: list[dict[str, str]], package_name: str) -> int:
    count = 0
    for e in elements:
        rid = str(e.get("resource_id") or "").strip()
        node_pkg = str(e.get("package") or "").strip()
        if node_pkg == package_name:
            count += 1
            continue
        if not rid:
            continue
        pref = _resource_id_owner_package(rid)
        if pref == package_name:
            count += 1
    return count

def _dump_filtered_screen(
    adb_bin: str,
    package_name: str,
    *,
    timeout_sec: float | None = None,
) -> tuple[list[dict[str, str]], str, str]:
    elements, _, raw_xml = dump_clean_screen(adb_bin, timeout_sec=timeout_sec)
    elements = _filter_widgets_for_target(elements, package_name)
    return elements, _screen_hash(elements), raw_xml

def dump_clean_screen(
    adb_bin: str,
    *,
    timeout_sec: float | None = None,
) -> tuple[list[dict[str, str]], str, str]:
    """Accessibility dump; returns empty on failure/timeout (does not abort the session)."""
    from subprocess_util import run_subprocess_with_timeout

    trace_path = (os.environ.get("CONTEXTDROID_SCREEN_DUMP_TRACE") or "").strip()
    if trace_path:
        try:
            with Path(trace_path).open("a", encoding="utf-8") as fh:
                fh.write(f"{time.time():.3f} dump_clean_screen\n")
        except OSError:
            pass

    device_xml = "/sdcard/window_dump.xml"
    dump_timeout = timeout_sec if timeout_sec is not None else _UI_DUMP_TIMEOUT_SEC
    try:
        run1 = run_subprocess_with_timeout(
            [adb_bin, "shell", "uiautomator", "dump", device_xml],
            timeout_sec=dump_timeout,
        )
    except OSError as exc:
        logging.warning("uiautomator dump failed: %s", exc)
        return [], "", ""
    if run1.returncode == 124:
        logging.warning(
            "uiautomator dump timed out after %.0fs; continuing session.",
            dump_timeout,
        )
        return [], "", ""
    if run1.returncode != 0:
        return [], "", ""
    cat_timeout = min(dump_timeout, 12.0)
    try:
        run2 = run_subprocess_with_timeout(
            [adb_bin, "shell", "cat", device_xml],
            timeout_sec=cat_timeout,
        )
    except OSError as exc:
        logging.warning("Reading window dump failed: %s", exc)
        return [], "", ""
    if run2.returncode == 124:
        logging.warning("Reading window dump timed out after %.0fs.", cat_timeout)
        return [], "", ""
    if run2.returncode != 0:
        return [], "", ""
    raw_xml = run2.stdout or ""
    elements = _normalized_elements(raw_xml)
    elements = _token_trim_elements(elements)
    return elements, _screen_hash(elements), raw_xml

def _screen_has_edittext_for_typing(elements: list[dict[str, str]]) -> bool:
    """True when a text-entry field (EditText) is visible — required before input goals."""
    for e in elements:
        cn = (e.get("class_name") or "").lower()
        if "edittext" in cn or "autocomplete" in cn:
            return True
    return False

# Search-launch heuristics live here (single owner). goals/routing import screen helpers.
_SEARCH_LAUNCH_FALSE_POSITIVE_RID_TOKENS = (
    "backup_search",
    "search_more",
    "menu_search",
    "ib_backup",
)
_SEARCH_LAUNCH_DEFINITE_RID_TOKENS = ("fab_search", "search_button", "scanbutton")


def _is_false_positive_search_launch_widget(e: dict[str, str]) -> bool:
    """Exclude backup/menu search icons that are not app-wide search FABs."""
    rid = (e.get("resource_id") or "").lower()
    return any(tok in rid for tok in _SEARCH_LAUNCH_FALSE_POSITIVE_RID_TOKENS)


def _is_definite_search_launch_widget(e: dict[str, str]) -> bool:
    """True for FAB / toolbar search launch controls — not inline backup-list search icons."""
    if _is_false_positive_search_launch_widget(e):
        return False
    rid = (e.get("resource_id") or "").lower()
    cd = (e.get("content_desc") or "").strip().lower()
    cn = (e.get("class_name") or "").lower()
    if any(tok in rid for tok in _SEARCH_LAUNCH_DEFINITE_RID_TOKENS):
        if "scanbutton" in rid:
            return "linearlayout" in cn or "imagebutton" in cn or "button" in cn
        if "search_button" in rid:
            return "button" in cn or "imagebutton" in cn
        return True
    if cd == "search" and "imagebutton" in cn:
        return True
    if "historybutton" in rid and "search" in cd:
        return True
    if "search" in rid and ("button" in cn or "imagebutton" in cn) and "fab" in rid:
        return True
    return False

def _screen_has_search_launch_affordance(elements: list[dict[str, str]]) -> bool:
    """True when user can open search chrome (FAB / search button) on the current screen."""
    return any(_is_definite_search_launch_widget(e) for e in elements)

def _screen_has_search_entry_widget(elements: list[dict[str, str]]) -> bool:
    """Broad search affordance (launch or type) — used for digest-level detection only."""
    return _screen_has_edittext_for_typing(elements) or _screen_has_search_launch_affordance(
        elements
    )

def _allowed_resource_ids_from_elements(
    elements: list[dict[str, str]], *, max_n: int = 48
) -> list[str]:
    seen: list[str] = []
    for e in elements:
        rid = str(e.get("resource_id") or "").strip()
        if rid and rid not in seen:
            seen.append(rid)
        if len(seen) >= max_n:
            break
    return seen

def _visible_content_descs_from_elements(
    elements: list[dict[str, str]], *, max_n: int = 48
) -> list[str]:
    seen: list[str] = []
    for e in elements:
        cd = str(e.get("content_desc") or "").strip()
        if cd and cd not in seen:
            seen.append(cd)
        if len(seen) >= max_n:
            break
    return seen

_EMPTY_STATE_PATTERNS = (
    "no categories",
    "no results",
    "nothing found",
    "no items",
    "empty",
    "no data",
    "nothing to show",
)


def _screen_is_empty_state(elements: list[dict[str, str]]) -> bool:
    """True when the current screen mostly expresses an empty-state message."""
    blobs: list[str] = []
    actionable = 0
    for e in elements:
        txt = str(e.get("text") or "").strip().lower()
        cd = str(e.get("content_desc") or "").strip().lower()
        rid = str(e.get("resource_id") or "").strip().lower()
        cn = str(e.get("class_name") or "").strip().lower()
        if txt or cd:
            blobs.append(f"{txt} {cd} {rid} {cn}".strip())
        clickable = str(e.get("clickable") or "").lower() in ("true", "1")
        if clickable or "button" in cn or "edittext" in cn:
            actionable += 1
    hay = "\n".join(blobs)
    empty_msg = any(p in hay for p in _EMPTY_STATE_PATTERNS)
    # Empty state with very low actionable controls should not keep the same goal alive.
    return empty_msg and actionable <= 2

def _bounds_vertical_center_fraction(bounds: str, screen_bottom_y: int) -> float | None:
    m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds or "")
    if not m or screen_bottom_y <= 0:
        return None
    y1, y2 = int(m.group(2)), int(m.group(4))
    cy = (y1 + y2) / 2.0
    return cy / float(screen_bottom_y)

def _hierarchy_max_bottom_y(elements: list[dict[str, str]]) -> int:
    mx = 0
    for e in elements:
        m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", e.get("bounds", "") or "")
        if m:
            mx = max(mx, int(m.group(4)))
    return mx or 2400

def _screen_digest_hint(elements: list[dict[str, str]]) -> str:
    parts: list[str] = []
    for e in elements[:30]:
        tid = (e.get("resource_id") or "").strip()
        if tid:
            tid = tid.split("/")[-1][:44]
        txt = (e.get("text") or "").strip()[:28]
        cd = (e.get("content_desc") or "").strip()[:28]
        cn = (e.get("class_name") or "").split(".")[-1][:20]
        blob = " ".join(x for x in (txt, cd, tid, cn) if x).strip()
        if blob:
            parts.append(blob)
        if len(parts) >= 10:
            break
    hint = " · ".join(parts)
    return hint[:440]

def _resource_id_owner_package(resource_id: str) -> str:
    rid = (resource_id or "").strip()
    if ":id/" in rid:
        return rid.split(":id/", 1)[0]
    return ""

def _resource_id_belongs_to_target_app(rid: str, target_pkg: str) -> bool:
    if not rid:
        return True
    if rid.startswith("android:id/"):
        return True
    pref = _resource_id_owner_package(rid)
    if not pref:
        return True
    return pref == target_pkg

def _element_matches_tap_target(action: dict[str, Any], elements: list[dict[str, str]]) -> dict[str, str] | None:
    rid = str(action.get("target_resource_id") or "").strip()
    cd = str(action.get("target_content_desc") or "").strip()
    for e in elements:
        if rid and e.get("resource_id") == rid:
            return e
        if cd and e.get("content_desc") == cd:
            return e
    return None
