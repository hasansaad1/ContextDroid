#!/usr/bin/env python3
"""Phase-aware UX metrics over existing session logs (measurement only)."""

from __future__ import annotations

import argparse
import csv
import json
import re
import statistics
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluate_faithfulness import _action_type  # noqa: E402
from evaluate_scenario_level import _load_actions  # noqa: E402
from llm_agent.audit import (  # noqa: E402
    _effective_execution_kind,
    _execution_counts_as_ux_progress,
    _human_ux_scored_events,
)
from llm_agent.screen import _normalized_elements, _screen_hash  # noqa: E402
from quality_rules import (  # noqa: E402
    DIRECT_RATIO_FLAil_THRESHOLD,
    HIGH_BACK_WAIT_THRESHOLD,
    MECHANICAL_MAJORITY_FRAC,
    MECHANICAL_TYPES,
    MIN_PURPOSEFUL_NAMED,
    _explore_metrics as _quality_explore_metrics,
    detect_flailing_interim_new,
    detect_flailing_legacy,
    detect_suspect_flailing,
)

PHASES_UX = ("explore", "execute", "primary_ux", "legacy")
DIRECT_TYPES = frozenset({"tap", "input", "back", "swipe"})
RECOVERY_REASONS = frozenset({"bfs_return_to_hub", "bfs_avoid_back_loop"})
SCROLLABLE_CLASSES = frozenset(
    {
        "ListView",
        "RecyclerView",
        "ScrollView",
        "NestedScrollView",
        "ViewPager",
        "GridView",
    }
)
RECYCLING_CONTAINER_CLASSES = frozenset({"ListView", "RecyclerView", "GridView"})
PRESENT_CHILD_CONTAINER_CLASSES = frozenset({"ScrollView", "NestedScrollView", "ViewPager"})

NAMED_FUNCTIONAL_DEFINITION = (
    "A tap/input is a named functional element interaction when parsed_action has a non-empty "
    "target_resource_id, target_content_desc, or target_text (or typed text for input actions). "
    "Bare coordinate-only taps with no identity do not count. Anonymous View nodes with no "
    "resource-id, content-desc, or text do not count."
)


def _parse_bounds(bounds: str) -> tuple[int, int, int, int] | None:
    m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds or "")
    if not m:
        return None
    x1, y1, x2, y2 = map(int, m.groups())
    if x2 <= x1 or y2 <= y1:
        return None
    return x1, y1, x2, y2


def _rect_inside(inner: tuple[int, int, int, int], outer: tuple[int, int, int, int]) -> bool:
    ix1, iy1, ix2, iy2 = inner
    ox1, oy1, ox2, oy2 = outer
    return ix1 >= ox1 and iy1 >= oy1 and ix2 <= ox2 and iy2 <= oy2


def _point_inside(x: int, y: int, rect: tuple[int, int, int, int]) -> bool:
    x1, y1, x2, y2 = rect
    return x1 <= x <= x2 and y1 <= y <= y2


def _viewport_from_xml(xml_text: str) -> tuple[int, int, int, int] | None:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    b = _parse_bounds(root.attrib.get("bounds", ""))
    if b:
        return b
    max_x = max_y = 0
    for node in root.iter("node"):
        nb = _parse_bounds(node.attrib.get("bounds", ""))
        if nb:
            max_x = max(max_x, nb[2])
            max_y = max(max_y, nb[3])
    if max_x <= 0 or max_y <= 0:
        return None
    return 0, 0, max_x, max_y


def _index_elements_by_rid(xml_text: str) -> dict[str, list[tuple[int, int, int, int]]]:
    out: dict[str, list[tuple[int, int, int, int]]] = defaultdict(list)
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    for node in root.iter("node"):
        rid = (node.attrib.get("resource-id") or "").strip()
        b = _parse_bounds(node.attrib.get("bounds", ""))
        if rid and b:
            out[rid].append(b)
    return out


def _analyze_xml_scrollability(xml_text: str) -> dict[str, Any]:
    signals: list[dict[str, str]] = []
    classes_seen: set[str] = set()
    recycling = False
    present_child = False
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {
            "scrollable": False,
            "signals": [],
            "scrollable_container_classes": [],
            "recycling_containers": [],
            "present_child_containers": [],
        }
    for node in root.iter("node"):
        cls = (node.attrib.get("class") or "").split(".")[-1]
        scrollable_attr = node.attrib.get("scrollable", "false") == "true"
        if scrollable_attr:
            signals.append({"signal": "scrollable=true", "class": cls, "resource_id": node.attrib.get("resource-id", "")})
        if cls in SCROLLABLE_CLASSES:
            classes_seen.add(cls)
            signals.append({"signal": f"class:{cls}", "class": cls, "resource_id": node.attrib.get("resource-id", "")})
            if cls in RECYCLING_CONTAINER_CLASSES:
                recycling = True
            if cls in PRESENT_CHILD_CONTAINER_CLASSES:
                present_child = True
    scrollable = bool(signals)
    return {
        "scrollable": scrollable,
        "signals": signals[:20],
        "scrollable_container_classes": sorted(classes_seen),
        "recycling_containers": sorted(c for c in classes_seen if c in RECYCLING_CONTAINER_CLASSES),
        "present_child_containers": sorted(c for c in classes_seen if c in PRESENT_CHILD_CONTAINER_CLASSES),
    }


def _hint_scrollability(hint: str) -> dict[str, Any]:
    classes = sorted(c for c in SCROLLABLE_CLASSES if c.lower() in (hint or "").lower())
    recycling = [c for c in classes if c in RECYCLING_CONTAINER_CLASSES]
    present = [c for c in classes if c in PRESENT_CHILD_CONTAINER_CLASSES]
    return {
        "scrollable": bool(classes),
        "signals": [{"signal": f"hint_class:{c}", "class": c, "resource_id": ""} for c in classes],
        "scrollable_container_classes": classes,
        "recycling_containers": recycling,
        "present_child_containers": present,
        "source": "navigation_hint_only",
    }


def _phase_events(actions: list[dict[str, Any]], phases: tuple[str, ...]) -> list[dict[str, Any]]:
    return [a for a in actions if str(a.get("pipeline_phase") or "") in phases]


def _old_direct_action_ratio(actions: list[dict[str, Any]]) -> dict[str, Any]:
    scored = _human_ux_scored_events(actions)
    direct = [ev for ev in scored if _execution_counts_as_ux_progress(ev)]
    ratio = len(direct) / max(1, len(scored))
    return {
        "scored_events": len(scored),
        "direct_actions": len(direct),
        "ratio": round(ratio, 4),
        "phases": ["execute", "primary_ux", "legacy"],
    }


def _all_phase_direct_action_ratio(actions: list[dict[str, Any]]) -> dict[str, Any]:
    scored = _phase_events(actions, PHASES_UX)
    direct = [
        ev
        for ev in scored
        if _action_type(ev) in DIRECT_TYPES and bool(ev.get("action_success"))
    ]
    ratio = len(direct) / max(1, len(scored))
    by_phase: dict[str, dict[str, int]] = {}
    for ph in PHASES_UX:
        pe = _phase_events(actions, (ph,))
        pd = [
            ev
            for ev in pe
            if _action_type(ev) in DIRECT_TYPES and bool(ev.get("action_success"))
        ]
        by_phase[ph] = {"scored": len(pe), "direct": len(pd)}
    return {
        "scored_events": len(scored),
        "direct_actions": len(direct),
        "ratio": round(ratio, 4),
        "phases": list(PHASES_UX),
        "by_phase": by_phase,
    }


def _per_phase_direct_ratios(actions: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for ph in PHASES_UX:
        pe = _phase_events(actions, (ph,))
        if not pe:
            continue
        direct = [
            ev
            for ev in pe
            if _action_type(ev) in DIRECT_TYPES and bool(ev.get("action_success"))
        ]
        out[ph] = {
            "scored_events": len(pe),
            "direct_actions": len(direct),
            "ratio": round(len(direct) / max(1, len(pe)), 4),
        }
    return out


def _explore_named_functional_tap(act: dict[str, Any]) -> bool:
    if _action_type(act) != "tap" or not act.get("action_success"):
        return False
    pa = act.get("parsed_action") or {}
    rid = str(pa.get("target_resource_id") or "").strip()
    desc = str(pa.get("target_content_desc") or "").strip()
    text = str(pa.get("target_text") or pa.get("text") or "").strip()
    return bool(rid or desc or text)


def _explore_metrics(actions: list[dict[str, Any]]) -> dict[str, Any]:
    return _quality_explore_metrics(actions)


def _empty_hierarchy_rate(actions: list[dict[str, Any]]) -> dict[str, Any]:
    explore = _phase_events(actions, ("explore",))
    if not explore:
        return {"explore_steps": 0, "empty_hierarchy_steps": 0, "empty_hierarchy_rate": 0.0}
    empty = 0
    for a in explore:
        role = str((a.get("app_state") or {}).get("screen_role") or "")
        iec = int(a.get("interactive_element_count") or 0)
        if role == "empty_hierarchy" or iec == 0:
            empty += 1
    return {
        "explore_steps": len(explore),
        "empty_hierarchy_steps": empty,
        "empty_hierarchy_rate": round(empty / len(explore), 4),
    }


def _max_consecutive_empty_recovery(actions: list[dict[str, Any]]) -> int:
    explore = _phase_events(actions, ("explore",))
    best = cur = 0
    for a in explore:
        role = str((a.get("app_state") or {}).get("screen_role") or "")
        iec = int(a.get("interactive_element_count") or 0)
        reason = str((a.get("parsed_action") or {}).get("reason") or "")
        at = _action_type(a)
        empty = role == "empty_hierarchy" or iec == 0
        recovery = at in {"back", "wait"} and reason in RECOVERY_REASONS
        if empty and recovery:
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def _scrollability_for_session(base: Path, pkg: str, actions: list[dict[str, Any]]) -> dict[str, Any]:
    screens: dict[str, dict[str, Any]] = {}
    verified = base / f"{pkg}_verified_start.xml"
    if verified.exists():
        xml = verified.read_text(encoding="utf-8", errors="replace")
        elements = _normalized_elements(xml)
        vhash = _screen_hash(elements) if elements else ""
        if vhash:
            screens[vhash] = {"source": "verified_start.xml", **_analyze_xml_scrollability(xml)}

    nav_path = base / f"{pkg}_llm_navigation_artifact.json"
    if nav_path.exists():
        nav = json.loads(nav_path.read_text(encoding="utf-8"))
        for scr in nav.get("screens") or []:
            if not isinstance(scr, dict):
                continue
            h = str(scr.get("screen_hash") or "")
            if not h or h in screens:
                continue
            hint = str(scr.get("hint") or "")
            screens[h] = _hint_scrollability(hint)

    explore_hashes = []
    for a in _phase_events(actions, ("explore",)):
        h = str(a.get("screen_hash") or "")
        if h:
            explore_hashes.append(h)
    visited_unique = list(dict.fromkeys(explore_hashes))

    per_screen: list[dict[str, Any]] = []
    scrollable_count = 0
    all_classes: set[str] = set()
    recycling: set[str] = set()
    present_child: set[str] = set()
    for h in visited_unique:
        info = screens.get(h)
        if info is None:
            per_screen.append({"screen_hash": h[:16], "scrollable": False, "source": "unknown"})
            continue
        scrollable_count += int(bool(info.get("scrollable")))
        all_classes.update(info.get("scrollable_container_classes") or [])
        recycling.update(info.get("recycling_containers") or [])
        present_child.update(info.get("present_child_containers") or [])
        per_screen.append(
            {
                "screen_hash": h[:16],
                "scrollable": bool(info.get("scrollable")),
                "source": info.get("source", "unknown"),
                "signals": info.get("signals", [])[:5],
                "recycling_containers": info.get("recycling_containers", []),
                "present_child_containers": info.get("present_child_containers", []),
            }
        )

    n = len(visited_unique)
    return {
        "visited_screens_explore": n,
        "screens_with_scrollable_content": scrollable_count,
        "screens_with_scrollable_fraction": round(scrollable_count / n, 4) if n else 0.0,
        "had_scrollable_content": scrollable_count > 0,
        "scrollable_container_classes": sorted(all_classes),
        "recycling_containers_seen": sorted(recycling),
        "present_child_containers_seen": sorted(present_child),
        "per_screen": per_screen,
        "data_note": (
            "Full hierarchy available via verified_start.xml for one screen; other visited screens "
            "use navigation-artifact digest hints (class names only, no scrollable= attribute)."
        ),
    }


def _phantom_tap_check(base: Path, pkg: str, actions: list[dict[str, Any]]) -> dict[str, Any]:
    verified = base / f"{pkg}_verified_start.xml"
    viewport = None
    rid_bounds: dict[str, list[tuple[int, int, int, int]]] = {}
    if verified.exists():
        xml = verified.read_text(encoding="utf-8", errors="replace")
        viewport = _viewport_from_xml(xml)
        rid_bounds = _index_elements_by_rid(xml)

    explore_taps = [
        a
        for a in _phase_events(actions, ("explore",))
        if _action_type(a) == "tap" and bool(a.get("action_success"))
    ]
    phantoms: list[dict[str, Any]] = []
    for a in explore_taps:
        pa = a.get("parsed_action") or {}
        x, y = pa.get("x"), pa.get("y")
        if x is None or y is None:
            continue
        xi, yi = int(x), int(y)
        reasons: list[str] = []
        if viewport and not _point_inside(xi, yi, viewport):
            reasons.append("tap_point_outside_viewport")
        rid = str(pa.get("target_resource_id") or "").strip()
        if rid and rid_bounds.get(rid):
            if not any(_point_inside(xi, yi, b) for b in rid_bounds[rid]):
                reasons.append("tap_point_outside_element_bounds")
            if viewport and any(not _rect_inside(b, viewport) for b in rid_bounds[rid]):
                reasons.append("element_bounds_outside_viewport")
        if reasons:
            phantoms.append(
                {
                    "step": a.get("step"),
                    "target_resource_id": rid,
                    "x": xi,
                    "y": yi,
                    "viewport": list(viewport) if viewport else None,
                    "element_bounds": [list(b) for b in rid_bounds.get(rid, [])][:3],
                    "reasons": reasons,
                }
            )

    unverified_rid_taps = sum(
        1
        for a in explore_taps
        if str((a.get("parsed_action") or {}).get("target_resource_id") or "").strip()
        and str((a.get("parsed_action") or {}).get("target_resource_id") or "").strip()
        not in rid_bounds
    )
    n = len(explore_taps)
    return {
        "explore_tap_count": n,
        "phantom_tap_count": len(phantoms),
        "phantom_tap_ratio": round(len(phantoms) / n, 4) if n else 0.0,
        "unverified_rid_tap_count": unverified_rid_taps,
        "examples": phantoms[:8],
        "method_note": (
            "Viewport and element bounds from verified_start.xml only; taps on screens not "
            "represented in that dump may be flagged target_rid_not_in_verified_start_xml."
        ),
    }


def _cross_tab_bucket(
    *,
    explore_back_wait_ratio: float,
    had_scrollable: bool,
    empty_hierarchy_rate: float,
) -> str:
    high_bw = explore_back_wait_ratio > HIGH_BACK_WAIT_THRESHOLD
    if not high_bw:
        return "low_back_wait"
    if empty_hierarchy_rate >= 0.75:
        return "high_back_wait_empty_hierarchy"
    if had_scrollable:
        return "high_back_wait_scrollable"
    return "high_back_wait_other"


def analyze_session(
    *,
    package: str,
    session_id: str,
    artifact_dir: Path,
    sim_status: str = "",
) -> dict[str, Any]:
    actions_path = artifact_dir / f"{package}_llm_actions.jsonl"
    actions = _load_actions(actions_path)
    report_path = artifact_dir / f"{package}_human_ux_report.json"
    report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else None
    if not sim_status:
        meta_path = artifact_dir / f"{package}_dynamic_metadata.json"
        if meta_path.exists():
            sim_status = str(json.loads(meta_path.read_text()).get("llm_simulation_status") or "")

    old_ratio = _old_direct_action_ratio(actions)
    new_ratio = _all_phase_direct_action_ratio(actions)
    explore = _explore_metrics(actions)
    empty = _empty_hierarchy_rate(actions)
    scroll = _scrollability_for_session(artifact_dir, package, actions)
    phantom = _phantom_tap_check(artifact_dir, package, actions)
    flail_old, flail_old_ev = detect_flailing_legacy(actions, sim_status=sim_status, report=report)
    flail_new, flail_new_ev = detect_flailing_interim_new(
        actions,
        sim_status=sim_status,
        all_phase_ratio=new_ratio["ratio"],
        explore_metrics=explore,
    )
    flail_merged, flail_merged_ev = detect_suspect_flailing(
        actions,
        sim_status=sim_status,
        report=report,
        all_phase_ratio=new_ratio["ratio"],
        explore_metrics=explore,
    )
    bucket = _cross_tab_bucket(
        explore_back_wait_ratio=explore["explore_back_wait_ratio"],
        had_scrollable=scroll["had_scrollable_content"],
        empty_hierarchy_rate=empty["empty_hierarchy_rate"],
    )

    return {
        "package": package,
        "session_id": session_id,
        "artifact_dir": str(artifact_dir),
        "sim_status": sim_status,
        "direct_action_ratio_old": old_ratio,
        "direct_action_ratio_all_phase": new_ratio,
        "direct_action_ratio_by_phase": _per_phase_direct_ratios(actions),
        "explore_metrics": explore,
        "empty_hierarchy": empty,
        "scrollability": scroll,
        "phantom_taps": phantom,
        "max_consecutive_empty_recovery": _max_consecutive_empty_recovery(actions),
        "flailing_old": flail_old,
        "flailing_old_evidence": flail_old_ev,
        "flailing_new": flail_new,
        "flailing_new_evidence": flail_new_ev,
        "flailing_merged": flail_merged,
        "flailing_merged_evidence": flail_merged_ev,
        "cross_tab_bucket": bucket,
    }


def _load_working_dataset(path: Path) -> list[dict[str, str]]:
    return list(csv.DictReader(path.open(encoding="utf-8")))


def _load_v6_success(index_path: Path) -> list[dict[str, str]]:
    rows = []
    for r in csv.DictReader(index_path.open(encoding="utf-8")):
        if r.get("status") != "success" or not r.get("metadata_path"):
            continue
        meta_path = Path(r["metadata_path"])
        base = meta_path.parent
        rows.append(
            {
                "package": r["package_name"],
                "session_id": r.get("session_id") or "",
                "artifact_dir": str(base),
            }
        )
    return rows


def _summarize_distribution(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"n": 0}
    vs = sorted(values)
    return {
        "n": len(vs),
        "mean": round(statistics.mean(vs), 4),
        "median": round(statistics.median(vs), 4),
        "p25": round(vs[len(vs) // 4], 4),
        "p75": round(vs[(3 * len(vs)) // 4], 4),
        "min": round(vs[0], 4),
        "max": round(vs[-1], 4),
    }


def _aggregate(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    old_ratios = [s["direct_action_ratio_old"]["ratio"] for s in sessions]
    new_ratios = [s["direct_action_ratio_all_phase"]["ratio"] for s in sessions]
    deltas = [n - o for o, n in zip(old_ratios, new_ratios)]

    flail_old_n = sum(1 for s in sessions if s["flailing_old"])
    flail_new_n = sum(1 for s in sessions if s["flailing_new"])
    flail_merged_n = sum(1 for s in sessions if s["flailing_merged"])
    newly_flailing = [
        s
        for s in sessions
        if not s["flailing_old"] and s["flailing_new"]
    ]
    cleared = [s for s in sessions if s["flailing_old"] and not s["flailing_new"]]
    restored = [s for s in sessions if s["flailing_old"] and not s["flailing_new"] and s["flailing_merged"]]
    merged_additions = [
        s for s in sessions if s["flailing_merged"] and not s["flailing_old"]
    ]

    buckets: dict[str, list[dict[str, str]]] = defaultdict(list)
    high_bw = [s for s in sessions if s["explore_metrics"]["explore_back_wait_ratio"] > HIGH_BACK_WAIT_THRESHOLD]
    for s in sessions:
        buckets[s["cross_tab_bucket"]].append({"package": s["package"], "session_id": s["session_id"]})

    phantom_sessions = [s for s in sessions if s["phantom_taps"]["phantom_tap_count"] > 0]
    phantom_ratio_vals = [s["phantom_taps"]["phantom_tap_ratio"] for s in sessions if s["phantom_taps"]["explore_tap_count"]]

    max_streaks = [s["max_consecutive_empty_recovery"] for s in sessions]

    high = high_bw
    n_high = len(high)
    scroll_n = sum(1 for s in high if s["scrollability"]["had_scrollable_content"])
    empty_n = sum(1 for s in high if s["empty_hierarchy"]["empty_hierarchy_rate"] >= 0.75)
    other_n = n_high - scroll_n - empty_n

    if n_high == 0:
        verdict = "MIXED"
        verdict_line = "No high back/wait sessions in cohort."
    elif scroll_n >= empty_n and scroll_n >= other_n:
        verdict = "SCROLL-BOUND"
        verdict_line = (
            f"SCROLL-BOUND: among {n_high} high back/wait sessions, {scroll_n} had scrollable content "
            f"vs {empty_n} empty/degenerate vs {other_n} other."
        )
    elif empty_n >= scroll_n and empty_n >= other_n:
        verdict = "NON-NAVIGABLE-BOUND"
        verdict_line = (
            f"NON-NAVIGABLE-BOUND: among {n_high} high back/wait sessions, {empty_n} empty/degenerate "
            f"vs {scroll_n} scrollable vs {other_n} other."
        )
    else:
        verdict = "MIXED"
        verdict_line = (
            f"MIXED: high back/wait split scrollable={scroll_n} empty={empty_n} other={other_n} (n={n_high})."
        )

    return {
        "session_count": len(sessions),
        "direct_action_ratio_old_distribution": _summarize_distribution(old_ratios),
        "direct_action_ratio_all_phase_distribution": _summarize_distribution(new_ratios),
        "direct_action_ratio_delta_distribution": _summarize_distribution(deltas),
        "explore_metrics_distributions": {
            "explore_back_wait_ratio": _summarize_distribution(
                [s["explore_metrics"]["explore_back_wait_ratio"] for s in sessions]
            ),
            "explore_named_tap_ratio": _summarize_distribution(
                [s["explore_metrics"]["explore_named_tap_ratio"] for s in sessions]
            ),
            "explore_functional_tap_count": _summarize_distribution(
                [float(s["explore_metrics"]["explore_functional_tap_count"]) for s in sessions]
            ),
        },
        "scrollability_summary": {
            "sessions_with_any_scrollable": sum(1 for s in sessions if s["scrollability"]["had_scrollable_content"]),
            "recycling_containers_corpus": sorted(
                {c for s in sessions for c in s["scrollability"]["recycling_containers_seen"]}
            ),
            "present_child_containers_corpus": sorted(
                {c for s in sessions for c in s["scrollability"]["present_child_containers_seen"]}
            ),
        },
        "phantom_tap_summary": {
            "sessions_with_phantoms": len(phantom_sessions),
            "phantom_tap_ratio_distribution": _summarize_distribution(phantom_ratio_vals),
            "note": (
                "Non-trivial phantom_tap_ratio means some explore taps did not land on in-viewport "
                "targets per verified_start.xml bounds check."
                if any(r > 0.05 for r in phantom_ratio_vals)
                else "Phantom taps appear limited; verified_start-only bounds may under-count."
            ),
        },
        "cross_tab": {
            "high_back_wait_threshold": HIGH_BACK_WAIT_THRESHOLD,
            "high_back_wait_session_count": n_high,
            "high_back_wait_scrollable_count": scroll_n,
            "high_back_wait_empty_hierarchy_count": empty_n,
            "high_back_wait_other_count": other_n,
            "buckets": {k: v for k, v in buckets.items()},
            "verdict": verdict,
            "verdict_line": verdict_line,
        },
        "flailing_recheck": {
            "flailing_old_count": flail_old_n,
            "flailing_new_count": flail_new_n,
            "flailing_merged_count": flail_merged_n,
            "newly_flailing_count": len(newly_flailing),
            "cleared_flailing_count": len(cleared),
            "restored_from_interim_under_detection_count": len(restored),
            "restored_from_interim_under_detection_packages": [s["package"] for s in restored],
            "merged_additions_beyond_legacy_count": len(merged_additions),
            "merged_additions_beyond_legacy_packages": [s["package"] for s in merged_additions],
            "newly_flailing_packages": [s["package"] for s in newly_flailing],
            "mensa_class": next(
                (s for s in sessions if s["package"] == "ch.famoser.mensa"),
                None,
            ),
        },
        "fail_fast_k_analysis": {
            "max_consecutive_empty_recovery_distribution": _summarize_distribution(
                [float(x) for x in max_streaks]
            ),
            "p99_max_streak": sorted(max_streaks)[int(0.99 * max(len(max_streaks) - 1, 0))] if max_streaks else 0,
            "sessions_with_streak_ge_8": sum(1 for x in max_streaks if x >= 8),
            "sessions_with_streak_ge_12": sum(1 for x in max_streaks if x >= 12),
            "control_protonvpn_streak": next(
                (s["max_consecutive_empty_recovery"] for s in sessions if s["package"] == "ch.protonvpn.android"),
                None,
            ),
            "mensa_streak": next(
                (s["max_consecutive_empty_recovery"] for s in sessions if s["package"] == "ch.famoser.mensa"),
                None,
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--working-csv", default="experiment/working_dataset.csv")
    parser.add_argument("--index", default="logs/bulk_llm_benign_v6/dataset_index.csv")
    parser.add_argument("--out", default="experiment/phase_aware_metrics.json")
    parser.add_argument("--include-v6-pool", action="store_true", default=True)
    args = parser.parse_args()

    working_rows = _load_working_dataset(REPO / args.working_csv)
    working_sessions = []
    for row in working_rows:
        working_sessions.append(
            analyze_session(
                package=row["package"],
                session_id=row["session_id"],
                artifact_dir=Path(row["artifact_dir"]),
            )
        )

    v6_sessions = []
    if args.include_v6_pool:
        for row in _load_v6_success(REPO / args.index):
            v6_sessions.append(
                analyze_session(
                    package=row["package"],
                    session_id=row["session_id"],
                    artifact_dir=Path(row["artifact_dir"]),
                )
            )

    out = {
        "experiment": "phase_aware_metrics",
        "measurement_only": True,
        "named_functional_definition": NAMED_FUNCTIONAL_DEFINITION,
        "direct_action_ratio_definitions": {
            "old": "execute+primary_ux+legacy scored events; direct = execution_kind direct/dialog per audit._execution_counts_as_ux_progress",
            "all_phase": "explore+execute+primary_ux+legacy scored events; direct = successful tap/input/back/swipe",
            "by_phase": "same as all_phase but reported per pipeline_phase",
        },
        "working_dataset_129": {
            "sessions": working_sessions,
            "aggregate": _aggregate(working_sessions),
        },
        "v6_success_pool_238": {
            "sessions": v6_sessions,
            "aggregate": _aggregate(v6_sessions),
        },
    }

    out_path = REPO / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    agg = out["working_dataset_129"]["aggregate"]
    print(f"wrote {out_path}")
    print("working_dataset_129:")
    print("  old ratio median:", agg["direct_action_ratio_old_distribution"].get("median"))
    print("  new ratio median:", agg["direct_action_ratio_all_phase_distribution"].get("median"))
    print("  delta median:", agg["direct_action_ratio_delta_distribution"].get("median"))
    print(" ", agg["cross_tab"]["verdict_line"])
    print("  flailing old→interim→merged:", agg["flailing_recheck"]["flailing_old_count"], "→", agg["flailing_recheck"]["flailing_new_count"], "→", agg["flailing_recheck"]["flailing_merged_count"])
    print("  restored from interim under-detection:", agg["flailing_recheck"]["restored_from_interim_under_detection_count"])
    print("  newly flailing (interim only):", agg["flailing_recheck"]["newly_flailing_count"])
    mensa = agg["flailing_recheck"]["mensa_class"]
    if mensa:
        print(
            "  mensa: flail_old", mensa["flailing_old"],
            "flail_interim", mensa["flailing_new"],
            "flail_merged", mensa["flailing_merged"],
            "explore_bw", mensa["explore_metrics"]["explore_back_wait_ratio"],
        )


if __name__ == "__main__":
    main()
