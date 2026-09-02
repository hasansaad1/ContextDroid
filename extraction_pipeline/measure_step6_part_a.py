#!/usr/bin/env python3
"""Step 6 PART A — re-score scrollable + high back/wait cohort on current code."""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "extraction_pipeline"))

from llm_agent.screen import _normalized_elements, _screen_hash
from phase_aware_metrics import (
    RECOVERY_REASONS,
    SCROLLABLE_CLASSES,
    _analyze_xml_scrollability,
    _empty_hierarchy_rate,
    _explore_metrics,
    _scrollability_for_session,
    analyze_session,
)
from quality_rules import HIGH_BACK_WAIT_THRESHOLD

AFTER_ROOT = ROOT / "logs/step6_part_a/after"
METRICS_JSON = ROOT / "experiment/phase_aware_metrics.json"
REPORT_MD = ROOT / "docs/step6_part_a_scroll_residual.md"

RECYCLING = frozenset({"RecyclerView", "ListView", "GridView"})
PRESENT_CHILD = frozenset({"ScrollView", "NestedScrollView", "ViewPager"})


def _load_scrollable_cohort() -> list[dict[str, Any]]:
    data = json.loads(METRICS_JSON.read_text(encoding="utf-8"))
    sessions = (data.get("v6_success_pool_238") or {}).get("sessions") or []
    return [s for s in sessions if s.get("cross_tab_bucket") == "high_back_wait_scrollable"]


def _find_artifact_dir(pkg: str, *, after: bool) -> Path | None:
    if after:
        hits = list((AFTER_ROOT / pkg).glob(f"**/session_1"))
        for d in hits:
            if (d / f"{pkg}_llm_actions.jsonl").is_file():
                return d
        return None
    cohort = _load_scrollable_cohort()
    for s in cohort:
        if s.get("package") == pkg:
            p = Path(str(s.get("artifact_dir") or ""))
            return p if p.is_dir() else None
    return None


def _load_actions(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def _viewport_rect(xml_text: str) -> tuple[int, int, int, int] | None:
    m = re.search(r'bounds="\[0,0\]\[(\d+),(\d+)\]"', xml_text)
    if not m:
        return None
    return 0, 0, int(m.group(1)), int(m.group(2))


def _bounds_inside_viewport(bounds: str, viewport: tuple[int, int, int, int]) -> bool:
    m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds or "")
    if not m:
        return False
    x1, y1, x2, y2 = map(int, m.groups())
    _, _, vw, vh = viewport
    cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
    return 0 <= cx <= vw and 0 <= cy <= vh


def _off_viewport_named_children(xml_text: str) -> list[dict[str, str]]:
    viewport = _viewport_rect(xml_text)
    if viewport is None:
        return []
    out: list[dict[str, str]] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    for node in root.iter("node"):
        cls = node.attrib.get("class") or ""
        rid = (node.attrib.get("resource-id") or "").strip()
        cd = (node.attrib.get("content-desc") or "").strip()
        text = (node.attrib.get("text") or "").strip()
        bounds = node.attrib.get("bounds") or ""
        if not (rid or cd or text):
            continue
        if bounds and not _bounds_inside_viewport(bounds, viewport):
            out.append({"class": cls.split(".")[-1], "resource_id": rid, "content_desc": cd, "text": text, "bounds": bounds})
    return out[:10]


def _top_viewport_anonymous_clickables(xml_text: str) -> int:
    viewport = _viewport_rect(xml_text)
    if viewport is None:
        return 0
    n = 0
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return 0
    for node in root.iter("node"):
        if node.attrib.get("clickable") != "true":
            continue
        rid = (node.attrib.get("resource-id") or "").strip()
        cd = (node.attrib.get("content-desc") or "").strip()
        text = (node.attrib.get("text") or "").strip()
        if rid or cd or text:
            continue
        bounds = node.attrib.get("bounds") or ""
        if bounds and _bounds_inside_viewport(bounds, viewport):
            n += 1
    return n


def _recovery_step_analysis(actions: list[dict[str, Any]], artifact_dir: Path, pkg: str) -> dict[str, Any]:
    explore = [a for a in actions if str(a.get("pipeline_phase") or "") == "explore"]
    recovery_steps: list[dict[str, Any]] = []
    edittext_steps = 0
    for a in explore:
        at = str((a.get("parsed_action") or {}).get("action_type") or "")
        reason = str((a.get("parsed_action") or {}).get("reason") or "")
        if at in {"back", "wait"} and reason in RECOVERY_REASONS:
            counts = a.get("explore_candidate_counts") or {}
            recovery_steps.append(
                {
                    "step": a.get("step"),
                    "reason": reason,
                    "screen_hash": str(a.get("screen_hash") or "")[:16],
                    "nav_cands": int(counts.get("nav_cands") or 0),
                    "other_cands": int(counts.get("other_cands") or 0),
                    "expand_cands": int(counts.get("expand_cands") or 0),
                    "skipped_interactive": int(counts.get("skipped_interactive") or 0),
                    "interactive_element_count": int(a.get("interactive_element_count") or 0),
                }
            )
        if at == "input" or reason == "bfs_text_entry_probe":
            edittext_steps += 1

    verified = artifact_dir / f"{pkg}_verified_start.xml"
    xml = verified.read_text(encoding="utf-8", errors="ignore") if verified.is_file() else ""
    scroll_info = _analyze_xml_scrollability(xml) if xml else {}
    off_viewport_named = _off_viewport_named_children(xml) if xml else []
    top_anonymous = _top_viewport_anonymous_clickables(xml) if xml else 0

    empty_recovery = sum(
        1
        for a in explore
        if str((a.get("app_state") or {}).get("screen_role") or "") == "empty_hierarchy"
        and str((a.get("parsed_action") or {}).get("action_type") or "") in {"back", "wait"}
    )

    return {
        "recovery_step_count": len(recovery_steps),
        "recovery_steps_sample": recovery_steps[:5],
        "edittext_probe_steps": edittext_steps,
        "empty_hierarchy_recovery_steps": empty_recovery,
        "verified_start_scrollable": bool(scroll_info.get("scrollable")),
        "recycling_containers": scroll_info.get("recycling_containers") or [],
        "present_child_containers": scroll_info.get("present_child_containers") or [],
        "off_viewport_named_children": off_viewport_named,
        "top_viewport_anonymous_clickables": top_anonymous,
        "scroll_signals": (scroll_info.get("signals") or [])[:5],
    }


def _classify(
    *,
    before: dict[str, Any],
    after: dict[str, Any] | None,
    recovery: dict[str, Any],
    scroll: dict[str, Any],
    empty: dict[str, Any],
) -> tuple[str, str]:
    if after is None:
        return "PENDING", "no_fresh_log"

    b_ft = int(before.get("explore_functional_tap_count") or 0)
    b_bw = float(before.get("explore_back_wait_ratio") or 0)
    a_ft = int(after.get("explore_functional_tap_count") or 0)
    a_bw = float(after.get("explore_back_wait_ratio") or 0)
    empty_rate = float(empty.get("empty_hierarchy_rate") or 0)

    if empty_rate >= 0.75:
        return "OTHER", "empty_hierarchy_dominant"

    if recovery.get("edittext_probe_steps", 0) >= 3 and a_ft <= 1:
        return "OTHER", "text_entry_edittext_loop"

    if recovery.get("empty_hierarchy_recovery_steps", 0) >= 3:
        return "OTHER", "empty_hierarchy_recovery"

    if a_ft > 0 and (a_bw < HIGH_BACK_WAIT_THRESHOLD or (b_bw - a_bw) >= 0.25):
        return "RESOLVED", "engaged_without_scroll"

    if a_ft > 0 and b_ft == 0 and a_bw < b_bw:
        return "RESOLVED", "engaged_without_scroll"

    # Still stalling
    still_stalled = a_bw >= HIGH_BACK_WAIT_THRESHOLD or (a_ft == 0 and b_ft == 0)

    if not still_stalled:
        return "OTHER", "partial_engagement_not_scroll_case"

    # Scroll-gated vs more anonymous clickables
    top_anon = int(recovery.get("top_viewport_anonymous_clickables") or 0)
    off_named = recovery.get("off_viewport_named_children") or []
    recycling = recovery.get("recycling_containers") or []
    present_child = recovery.get("present_child_containers") or []

    last_recovery = (recovery.get("recovery_steps_sample") or [{}])[-1]
    exhausted = (
        int(last_recovery.get("nav_cands") or 0) == 0
        and int(last_recovery.get("other_cands") or 0) == 0
        and int(last_recovery.get("expand_cands") or 0) == 0
    )

    if top_anon >= 2 and not exhausted:
        return "OTHER", "anonymous_clickables_visible_should_tap_not_scroll"

    scroll_gated = bool(recycling or present_child or off_named or recovery.get("verified_start_scrollable"))
    if scroll_gated and exhausted:
        if recycling:
            return "STILL-NEEDS-SCROLL", "recycler_list_off_screen_content"
        if off_named:
            return "STILL-NEEDS-SCROLL", "scrollview_off_viewport_named_children"
        if present_child:
            return "STILL-NEEDS-SCROLL", "present_child_container_below_fold"
        return "STILL-NEEDS-SCROLL", "scrollable_container_candidate_exhaustion"

    if scroll.get("had_scrollable_content") and exhausted:
        return "STILL-NEEDS-SCROLL", "scrollable_screen_exhausted_candidates"

    return "OTHER", "stall_non_scroll_gated"


def analyze_one(pkg: str, before_session: dict[str, Any]) -> dict[str, Any]:
    before_em = before_session.get("explore_metrics") or {}
    before_dir = Path(str(before_session.get("artifact_dir") or ""))
    after_dir = _find_artifact_dir(pkg, after=True)

    after_analysis = None
    if after_dir is not None:
        after_analysis = analyze_session(
            package=pkg,
            session_id=f"{pkg}_step6_rescore",
            artifact_dir=after_dir,
        )

    after_em = (after_analysis or {}).get("explore_metrics") or {}
    after_empty = (after_analysis or {}).get("empty_hierarchy") or {}
    after_scroll = (after_analysis or {}).get("scrollability") or {}

    actions = _load_actions(after_dir / f"{pkg}_llm_actions.jsonl") if after_dir else []
    recovery = _recovery_step_analysis(actions, after_dir or before_dir, pkg) if (after_dir or before_dir).is_dir() else {}

    classification, reason = _classify(
        before=before_em,
        after=after_em if after_analysis else None,
        recovery=recovery,
        scroll=after_scroll,
        empty=after_empty if after_analysis else _empty_hierarchy_rate(_load_actions(before_dir / f"{pkg}_llm_actions.jsonl")),
    )

    return {
        "package": pkg,
        "classification": classification,
        "reason": reason,
        "before": {
            "explore_functional_tap_count": before_em.get("explore_functional_tap_count"),
            "explore_back_wait_ratio": before_em.get("explore_back_wait_ratio"),
            "explore_action_count": before_em.get("explore_action_count"),
        },
        "after": {
            "explore_functional_tap_count": after_em.get("explore_functional_tap_count"),
            "explore_back_wait_ratio": after_em.get("explore_back_wait_ratio"),
            "explore_action_count": after_em.get("explore_action_count"),
            "artifact_dir": str(after_dir) if after_dir else None,
        },
        "recovery_analysis": recovery,
        "scrollability_after": {
            "had_scrollable_content": after_scroll.get("had_scrollable_content"),
            "recycling": after_scroll.get("recycling_containers_seen"),
            "present_child": after_scroll.get("present_child_containers_seen"),
        },
    }


def render_report(rows: list[dict[str, Any]]) -> str:
    from collections import Counter

    counts = Counter(r["classification"] for r in rows)
    lines = [
        "# Step 6 PART A — scrollable cohort residual measurement",
        "",
        "## Summary",
        "",
        f"| Classification | Count |",
        f"|---|---:|",
    ]
    for k in ("RESOLVED", "STILL-NEEDS-SCROLL", "OTHER", "PENDING"):
        if counts.get(k):
            lines.append(f"| {k} | {counts[k]} |")
    lines.append("")
    lines.append("## Per-app (before → after)")
    lines.append("")
    lines.append("| Package | Before ft/bw | After ft/bw | Class | Reason |")
    lines.append("|---|---|---|---|---|")
    for r in sorted(rows, key=lambda x: (x["classification"], x["package"])):
        b = r["before"]
        a = r["after"]
        aft = f"{a.get('explore_functional_tap_count', '—')}/{a.get('explore_back_wait_ratio', '—')}"
        lines.append(
            f"| `{r['package']}` | {b['explore_functional_tap_count']}/{b['explore_back_wait_ratio']} "
            f"| {aft} | **{r['classification']}** | {r['reason']} |"
        )
    lines.append("")
    scroll_need = [r["package"] for r in rows if r["classification"] == "STILL-NEEDS-SCROLL"]
    if scroll_need:
        lines.append("## STILL-NEEDS-SCROLL validation targets for PART B")
        lines.append("")
        for p in scroll_need:
            lines.append(f"- `{p}`")
    else:
        lines.append("## Gate")
        lines.append("")
        lines.append("STILL-NEEDS-SCROLL count is 0 or near-0 — defer Step 6 scroll implementation.")
    return "\n".join(lines) + "\n"


def main() -> int:
    cohort = _load_scrollable_cohort()
    rows = [analyze_one(str(s["package"]), s) for s in cohort]
    report = render_report(rows)
    REPORT_MD.parent.mkdir(parents=True, exist_ok=True)
    REPORT_MD.write_text(report, encoding="utf-8")
    out_json = ROOT / "logs/step6_part_a/rescore_report.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(report)
    pending = sum(1 for r in rows if r["classification"] == "PENDING")
    if pending:
        print(f"\n{pending} sessions pending fresh logs — run collect_step6_scrollable_rescore.py")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
