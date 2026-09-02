#!/usr/bin/env python3
"""Attribute meaningful Frida events to agent pipeline phases (re-analysis only)."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluate_scenario_level import (
    _is_meaningful_event,
    _load_actions,
    _load_frida_events,
    _session_alignment,
)

GOAL_ASSOC_WINDOW_MS = 8000
PHASE_BUCKETS = ("explore", "execute", "primary_ux", "legacy", "pre_session", "post_session", "unknown")


def _classify_emitter(row: dict[str, Any]) -> str:
    reason = str((row.get("parsed_action") or {}).get("reason") or "")
    raw = str(row.get("raw_response") or "")
    prompt = str(row.get("prompt_hash") or "")
    if reason.startswith("engine_") or "deterministic" in raw.lower():
        return "engine_injected"
    if prompt == "bfs_navigation_phase":
        return "bfs_engine"
    if row.get("planner_model"):
        return "llm_emitted"
    return "unknown"


def _action_timeline(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in actions:
        pa = row.get("parsed_action") or {}
        out.append(
            {
                "step": row.get("step"),
                "ts_epoch_ms": row.get("ts_epoch_ms"),
                "pipeline_phase": str(row.get("pipeline_phase") or "unknown"),
                "action_type": str(pa.get("action_type") or ""),
                "ux_goal_index": row.get("ux_goal_index"),
                "ux_goal_status": row.get("ux_goal_status"),
                "execution_kind": row.get("execution_kind"),
                "emitter": _classify_emitter(row),
                "reason": pa.get("reason"),
            }
        )
    return out


def _goal_anchor_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    anchors: list[dict[str, Any]] = []
    for row in actions:
        pa = row.get("parsed_action") or {}
        at = str(pa.get("action_type") or "")
        phase = str(row.get("pipeline_phase") or "")
        ts = row.get("ts_epoch_ms")
        if ts is None:
            continue
        if at == "advance_goal" and phase in {"execute", "primary_ux"}:
            anchors.append(
                {
                    "kind": "advance_goal",
                    "ts_epoch_ms": int(ts),
                    "step": row.get("step"),
                    "ux_goal_index": row.get("ux_goal_index"),
                    "ux_goal_status": row.get("ux_goal_status"),
                    "reason": pa.get("reason"),
                }
            )
        elif at == "tap" and phase in {"execute", "primary_ux"} and row.get("ux_goal_index") is not None:
            anchors.append(
                {
                    "kind": "goal_tap",
                    "ts_epoch_ms": int(ts),
                    "step": row.get("step"),
                    "ux_goal_index": row.get("ux_goal_index"),
                    "ux_goal_status": row.get("ux_goal_status"),
                    "reason": pa.get("reason"),
                }
            )
    return anchors


def _phase_at_agent_time(
    agent_equiv_ms: int, actions: list[dict[str, Any]]
) -> tuple[str, dict[str, Any] | None]:
    if not actions:
        return "unknown", None
    first_ts = int(actions[0]["ts_epoch_ms"])
    last_ts = int(actions[-1]["ts_epoch_ms"])
    if agent_equiv_ms < first_ts:
        return "pre_session", None
    if agent_equiv_ms > last_ts:
        return "post_session", actions[-1]
    active = actions[0]
    for row in actions:
        ts = row.get("ts_epoch_ms")
        if ts is None:
            continue
        if int(ts) <= agent_equiv_ms:
            active = row
        else:
            break
    phase = str(active.get("pipeline_phase") or "unknown")
    if phase not in {"explore", "execute", "primary_ux", "legacy"}:
        return phase if phase in PHASE_BUCKETS else "unknown", active
    return phase, active


def _is_goal_associated(
    frida_ts: int, session_offset_ms: int, anchors: list[dict[str, Any]], window_ms: int
) -> tuple[bool, dict[str, Any] | None]:
    for anchor in anchors:
        aligned = int(anchor["ts_epoch_ms"]) + session_offset_ms
        if abs(frida_ts - aligned) <= window_ms:
            return True, anchor
    return False, None


def analyze_session(
    *,
    pkg: str,
    base: Path,
    frida_path: Path,
    meta_path: Path,
    goal_window_ms: int,
) -> dict[str, Any]:
    actions_raw = _load_actions(base / f"{pkg}_llm_actions.jsonl")
    actions_raw.sort(key=lambda a: int(a.get("ts_epoch_ms") or 0))
    frida_events = _load_frida_events(frida_path)
    session_offset_ms, alignment_confidence = _session_alignment(frida_events, actions_raw)

    started_at_ms: int | None = None
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        started_at_ms = meta.get("started_at_epoch_ms")
        if started_at_ms is not None:
            started_at_ms = int(started_at_ms)

    first_meaningful_frida = next(
        (ev["timestamp"] for ev in frida_events if _is_meaningful_event(ev)), None
    )
    started_at_offset_ms = None
    if started_at_ms is not None and first_meaningful_frida is not None:
        started_at_offset_ms = int(first_meaningful_frida) - started_at_ms

    timeline = _action_timeline(actions_raw)
    anchors = _goal_anchor_actions(actions_raw)

    events_by_phase: Counter[str] = Counter()
    cats_first_in_phase: dict[str, str] = {}
    cat_first_details: dict[str, dict[str, Any]] = {}
    execute_events = 0
    execute_goal_assoc = 0
    all_goal_assoc = 0
    meaningful_total = 0
    attributed_events: list[dict[str, Any]] = []

    for ev in frida_events:
        if not _is_meaningful_event(ev):
            continue
        meaningful_total += 1
        frida_ts = int(ev["timestamp"])
        cat = ev["category"]

        if session_offset_ms is None or alignment_confidence != "aligned":
            phase = "unknown"
            active = None
            goal_assoc = False
            anchor = None
        else:
            agent_equiv = frida_ts - session_offset_ms
            phase, active = _phase_at_agent_time(agent_equiv, actions_raw)
            goal_assoc, anchor = _is_goal_associated(
                frida_ts, session_offset_ms, anchors, goal_window_ms
            )

        events_by_phase[phase] += 1
        if goal_assoc:
            all_goal_assoc += 1
        if phase == "execute":
            execute_events += 1
            if goal_assoc:
                execute_goal_assoc += 1

        if cat not in cats_first_in_phase:
            cats_first_in_phase[cat] = phase
            skip_near = False
            nearest_skip: dict[str, Any] | None = None
            if anchor and anchor.get("kind") == "advance_goal":
                nearest_skip = anchor
                skip_near = True
            elif session_offset_ms is not None:
                for a in anchors:
                    if a.get("kind") != "advance_goal":
                        continue
                    aligned = int(a["ts_epoch_ms"]) + session_offset_ms
                    if abs(frida_ts - aligned) <= goal_window_ms:
                        nearest_skip = a
                        skip_near = True
                        break
            cat_first_details[cat] = {
                "phase_first_surfaced": phase,
                "frida_timestamp": frida_ts,
                "api": ev.get("api"),
                "goal_associated": goal_assoc,
                "within_window_of_advance_goal": skip_near,
                "nearest_goal_anchor": nearest_skip,
                "active_action_at_event": {
                    "step": active.get("step") if active else None,
                    "pipeline_phase": active.get("pipeline_phase") if active else None,
                    "action_type": (active.get("parsed_action") or {}).get("action_type")
                    if active
                    else None,
                },
            }

        attributed_events.append(
            {
                "category": cat,
                "api": ev.get("api"),
                "frida_timestamp": frida_ts,
                "phase": phase,
                "goal_associated": goal_assoc,
            }
        )

    phase_cat_credit: dict[str, list[str]] = defaultdict(list)
    for cat, phase in cats_first_in_phase.items():
        phase_cat_credit[phase].append(cat)

    return {
        "package": pkg,
        "session_offset_ms_evaluator": session_offset_ms,
        "started_at_offset_ms_first_meaningful_minus_started": started_at_offset_ms,
        "alignment_confidence": alignment_confidence,
        "goal_association_window_ms": goal_window_ms,
        "action_timeline": timeline,
        "goal_anchor_actions": anchors,
        "meaningful_events_total": meaningful_total,
        "meaningful_events_by_phase": dict(events_by_phase),
        "distinct_categories_credited_by_phase": {
            ph: sorted(cats) for ph, cats in phase_cat_credit.items()
        },
        "distinct_category_count_by_phase": {
            ph: len(cats) for ph, cats in phase_cat_credit.items()
        },
        "category_first_surface_details": cat_first_details,
        "execute_phase": {
            "meaningful_events": execute_events,
            "goal_associated_events": execute_goal_assoc,
            "non_goal_associated_events": execute_events - execute_goal_assoc,
        },
        "all_phases": {
            "goal_associated_events": all_goal_assoc,
            "non_goal_associated_events": meaningful_total - all_goal_assoc,
        },
    }


def _corpus_verdict(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    credit_phase = Counter()
    total_credits = 0
    total_events = 0
    goal_assoc_events = 0

    for s in sessions:
        for ph, cats in s["distinct_categories_credited_by_phase"].items():
            if ph in {"explore", "execute", "primary_ux"}:
                credit_phase[ph] += len(cats)
                total_credits += len(cats)
            elif ph in {"pre_session", "post_session", "legacy", "unknown"}:
                credit_phase[ph] += len(cats)
                total_credits += len(cats)
        total_events += s["meaningful_events_total"]
        goal_assoc_events += s["all_phases"]["goal_associated_events"]

    pct = lambda n, d: (100.0 * n / d) if d else 0.0
    explore_c = credit_phase.get("explore", 0)
    execute_c = credit_phase.get("execute", 0)
    primary_c = credit_phase.get("primary_ux", 0)
    core_credits = explore_c + execute_c + primary_c

    pct_explore = pct(explore_c, core_credits) if core_credits else 0.0
    pct_execute = pct(execute_c, core_credits) if core_credits else 0.0
    pct_primary = pct(primary_c, core_credits) if core_credits else 0.0
    pct_goal_assoc = pct(goal_assoc_events, total_events)

    non_goal = total_events - goal_assoc_events
    # GOAL-INDEPENDENT if majority categories credited outside goal windows OR majority events non-goal
    goal_driven_cats = execute_c  # execute is most goal-adjacent; explore+primary are non-goal-heavy
    non_goal_credited = explore_c + primary_c + credit_phase.get("pre_session", 0) + credit_phase.get(
        "post_session", 0
    )

    if pct_goal_assoc < 50.0 and non_goal_credited >= goal_driven_cats:
        finding = "GOAL-INDEPENDENT"
        finding_line = (
            "Most meaningful categories and events surfaced outside goal-associated windows "
            f"({pct_goal_assoc:.1f}% events goal-associated; "
            f"{pct_explore:.1f}% explore / {pct_execute:.1f}% execute / {pct_primary:.1f}% primary_ux category credit)."
        )
    else:
        finding = "GOAL-DRIVEN"
        finding_line = (
            f"Majority of events goal-associated ({pct_goal_assoc:.1f}%) or execute-credited categories dominate."
        )

    return {
        "distinct_category_credits_explore": explore_c,
        "distinct_category_credits_execute": execute_c,
        "distinct_category_credits_primary_ux": primary_c,
        "distinct_category_credits_other": total_credits - core_credits,
        "pct_category_credit_explore_of_core_phases": pct_explore,
        "pct_category_credit_execute_of_core_phases": pct_execute,
        "pct_category_credit_primary_ux_of_core_phases": pct_primary,
        "meaningful_events_total": total_events,
        "meaningful_events_goal_associated": goal_assoc_events,
        "meaningful_events_non_goal_associated": non_goal,
        "pct_events_goal_associated": pct_goal_assoc,
        "pct_events_non_goal_associated": pct(non_goal, total_events),
        "finding": finding,
        "finding_one_line": finding_line,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", default="logs/exp_engineoff_v6/dataset_index.csv")
    parser.add_argument("--out", default="experiment/phase_attribution_result.json")
    parser.add_argument("--goal-window-ms", type=int, default=GOAL_ASSOC_WINDOW_MS)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    sessions: list[dict[str, Any]] = []
    for row in csv.DictReader((root / args.index).open(encoding="utf-8")):
        if row.get("status") != "success":
            continue
        pkg = row["package_name"]
        base = Path(row["metadata_path"]).parent
        sessions.append(
            analyze_session(
                pkg=pkg,
                base=base,
                frida_path=Path(row["frida_log_path"]),
                meta_path=Path(row["metadata_path"]),
                goal_window_ms=int(args.goal_window_ms),
            )
        )

    summary_table = []
    for s in sessions:
        summary_table.append(
            {
                "package": s["package"],
                "offset_ms": s["session_offset_ms_evaluator"],
                "meaningful_events": s["meaningful_events_total"],
                "events_explore": s["meaningful_events_by_phase"].get("explore", 0),
                "events_execute": s["meaningful_events_by_phase"].get("execute", 0),
                "events_primary_ux": s["meaningful_events_by_phase"].get("primary_ux", 0),
                "cats_credited_explore": s["distinct_category_count_by_phase"].get("explore", 0),
                "cats_credited_execute": s["distinct_category_count_by_phase"].get("execute", 0),
                "cats_credited_primary_ux": s["distinct_category_count_by_phase"].get(
                    "primary_ux", 0
                ),
                "goal_assoc_events": s["all_phases"]["goal_associated_events"],
            }
        )

    newpipe = next(s for s in sessions if s["package"] == "InfinityLoop1309.NewPipeEnhanced")
    newpipe_breakdown = {
        cat: newpipe["category_first_surface_details"][cat]
        for cat in sorted(newpipe["category_first_surface_details"])
    }

    result = {
        "experiment": "phase_attribution_engine_off",
        "index": str(root / args.index),
        "goal_association_window_ms": int(args.goal_window_ms),
        "offset_method": "evaluator_per_session_first_meaningful_frida_minus_first_agent_action_ts",
        "sessions": sessions,
        "summary_table": summary_table,
        "newpipe_enhanced_category_breakdown": newpipe_breakdown,
        "corpus_verdict": _corpus_verdict(sessions),
    }

    out_path = root / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"wrote {out_path}")
    print(f"finding: {result['corpus_verdict']['finding']}")


if __name__ == "__main__":
    main()
