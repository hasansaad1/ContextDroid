#!/usr/bin/env python3
"""Reconcile S1/S2/S3 goal-completion signals from existing session logs."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

GOAL_INDEX_RE = re.compile(r"final_goal_index=(\d+)\s+of\s+(\d+)")


def _load_actions(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _parse_report_idx(report_path: Path) -> tuple[int | None, int | None]:
    if not report_path.exists():
        return None, None
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None, None
    for check in report.get("checks") or []:
        m = GOAL_INDEX_RE.search(str(check.get("detail") or ""))
        if m:
            return int(m.group(1)), int(m.group(2))
    return None, None


def _classify_emitter(row: dict[str, Any]) -> str:
    reason = str((row.get("parsed_action") or {}).get("reason") or "")
    raw = str(row.get("raw_response") or "")
    prompt = str(row.get("prompt_hash") or "")
    if reason.startswith("engine_") or "deterministic" in raw.lower():
        return "engine_injected"
    if prompt in {"bfs_navigation_phase"}:
        return "bfs_engine"
    if row.get("planner_model"):
        return "llm_emitted"
    return "unknown"


def _summarize_advance_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        pa = row.get("parsed_action") or {}
        if pa.get("action_type") != "advance_goal":
            continue
        out.append(
            {
                "step": row.get("step"),
                "ts_epoch_ms": row.get("ts_epoch_ms"),
                "ux_goal_index": row.get("ux_goal_index"),
                "ux_goal_status": row.get("ux_goal_status"),
                "action_success": row.get("action_success"),
                "pipeline_phase": row.get("pipeline_phase"),
                "execution_kind": row.get("execution_kind"),
                "reason": pa.get("reason"),
                "emitter": _classify_emitter(row),
                "raw_response_excerpt": str(row.get("raw_response") or "")[:160],
            }
        )
    return out


def _agreement_note(s1: int | None, s2: int, s3_sat: int, s3_ok_adv: int, advances: list[dict]) -> tuple[str, str]:
    vals = {"S1": s1, "S2": s2, "S3_satisfied": s3_sat}
    uniq = {k: v for k, v in vals.items() if v is not None}
    if len(set(uniq.values())) <= 1 and s1 == s2 == s3_sat:
        return "MATCH", "S1, S2, S3_satisfied equal"
    notes: list[str] = []
    if s1 is not None and s1 != s2:
        notes.append(f"idx/report={s1} but advance_actions={s2}")
    if s1 is not None and s1 != s3_sat:
        notes.append(f"idx={s1} but satisfied_rows={s3_sat}")
    if s2 != s3_sat:
        notes.append(f"advance_actions={s2} but satisfied_rows={s3_sat}")
    if s3_ok_adv != s3_sat:
        notes.append(f"successful_advance={s3_ok_adv} vs satisfied={s3_sat}")
    engine = sum(1 for a in advances if a.get("emitter") == "engine_injected")
    if engine and s3_sat == 0 and (s1 or 0) > 0:
        notes.append(f"{engine} engine-injected advances, none satisfied")
    return "DISAGREE", "; ".join(notes) if notes else "values differ"


def analyze_session(base: Path, pkg: str) -> dict[str, Any]:
    actions = _load_actions(base / f"{pkg}_llm_actions.jsonl")
    report_idx, report_total = _parse_report_idx(base / f"{pkg}_human_ux_report.json")

    goals_planned: int | None = None
    plan_path = base / f"{pkg}_llm_ux_plan.json"
    if plan_path.exists():
        goals_planned = len(json.loads(plan_path.read_text(encoding="utf-8")).get("goals") or [])

    last_row_idx = actions[-1].get("ux_goal_index") if actions else None
    last_nonnull_idx = None
    for row in reversed(actions):
        if row.get("ux_goal_index") is not None:
            last_nonnull_idx = row.get("ux_goal_index")
            break

    s1_report = report_idx
    s1_last_action = last_row_idx
    s1 = s1_report if s1_report is not None else last_nonnull_idx

    advance_rows = [a for a in actions if (a.get("parsed_action") or {}).get("action_type") == "advance_goal"]
    s2 = len(advance_rows)

    s3_satisfied_rows = sum(1 for a in actions if a.get("ux_goal_status") == "satisfied")
    s3_satisfied_advance = sum(
        1 for a in advance_rows if a.get("ux_goal_status") == "satisfied"
    )
    s3_successful_advance = sum(1 for a in advance_rows if a.get("action_success") is True)

    advance_summaries = _summarize_advance_rows(actions)
    phase_dist = dict(Counter(a.get("pipeline_phase") for a in advance_rows))
    emitter_dist = dict(Counter(a["emitter"] for a in advance_summaries))
    status_on_advances = dict(Counter(a.get("ux_goal_status") for a in advance_rows))
    reason_dist = dict(Counter((a.get("parsed_action") or {}).get("reason") for a in advance_rows))

    flag, note = _agreement_note(s1, s2, s3_satisfied_rows, s3_successful_advance, advance_summaries)

    return {
        "package": pkg,
        "goals_planned": goals_planned,
        "report_final_of": f"{report_idx} of {report_total}" if report_idx is not None else None,
        "S1_final_ux_goal_idx": {
            "human_ux_report_idx": s1_report,
            "last_action_ux_goal_index": s1_last_action,
            "last_nonnull_ux_goal_index": last_nonnull_idx,
            "primary_S1": s1,
        },
        "S2_advance_goal_action_count": s2,
        "S3_satisfied": {
            "satisfied_row_count_any_action": s3_satisfied_rows,
            "satisfied_advance_goal_count": s3_satisfied_advance,
            "successful_advance_goal_count": s3_successful_advance,
        },
        "advance_goal_phase_distribution": phase_dist,
        "advance_goal_emitter_distribution": emitter_dist,
        "advance_goal_status_on_advances": status_on_advances,
        "advance_goal_reason_distribution": reason_dist,
        "agreement_flag": flag,
        "agreement_note": note,
        "advance_goal_rows": advance_summaries,
    }


def _verdict(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    s1_without_s3 = 0
    s1_with_advances = 0
    total_s3_sat = 0
    total_s2 = 0
    for s in sessions:
        s1 = s["S1_final_ux_goal_idx"]["primary_S1"] or 0
        s2 = s["S2_advance_goal_action_count"]
        s3 = s["S3_satisfied"]["satisfied_row_count_any_action"]
        total_s3_sat += s3
        total_s2 += s2
        if s1 > 0 and s3 == 0:
            s1_without_s3 += 1
        if s1 > 0 and s2 > 0:
            s1_with_advances += 1

    s1_pointer_not_accomplishment = s1_without_s3 >= 3
    s3_sparse = total_s3_sat <= max(2, total_s2 // 4)

    if s3_sparse and s1_pointer_not_accomplishment:
        one_line = (
            "NONE of S1/S2/S3 reliably means task accomplished; "
            "S1 is a plan pointer, S2 counts engine skips, S3 is too sparse."
        )
        recommendation = (
            "Retire goal-completion metrics; evaluate on distinct_meaningful_categories only."
        )
    elif s3_sparse:
        one_line = "S3 (satisfied) is too sparse; S1/S2 overstate accomplishment."
        recommendation = "Retire goal-completion metrics; use meaningful-category signal."
    else:
        one_line = "S3 (satisfied advance_goal) is the only accomplishment signal with semantic grounding."
        recommendation = "Use S3 satisfied_advance_goal_count only."

    return {
        "S1_advances_without_satisfied": s1_without_s3,
        "sessions_with_S1_gt0_and_S2_gt0": s1_with_advances,
        "corpus_total_S2_advance_actions": total_s2,
        "corpus_total_S3_satisfied_rows": total_s3_sat,
        "S1_is_pointer_not_accomplishment": s1_pointer_not_accomplishment,
        "S3_near_zero_across_corpus": s3_sparse,
        "verdict_one_line": one_line,
        "recommendation_one_line": recommendation,
    }


def _impact() -> dict[str, Any]:
    return {
        "evaluator_goals_completed_source": (
            "S1: goals_completed_primary = final_goal_index from *_human_ux_report.json "
            "(parsed as goals_completed_report); falls back to S2 only if report missing."
        ),
        "evaluator_productive_numerator_source": (
            "S3 subset: satisfied advance_goal rows in execute/primary_ux only "
            "(goals_completed_advance_satisfied)."
        ),
        "engineoff_compare_goals_completed_column": "goals_completed_primary from scenario evaluator (= S1 report index)",
        "goals_completed_improved_count": 6,
        "goals_completed_improved_packages": [
            "InfinityLoop1309.NewPipeEnhanced",
            "ac.robinson.mediaphone",
            "app.fedilab.castlab",
            "app.fedilab.mobilizon",
            "anonvpn.anon_next.android",
            "ca.littlesvr.everyonestimetable",
        ],
        "corr_0_607_computed_on": "S1 (goals_completed_primary) vs distinct_meaningful_categories",
        "weight_carry_statement": (
            "The 6/12 goals_completed improvement and corr=0.607 carry limited weight: both use "
            "S1 (plan-pointer index), not S3 (satisfied). Of 6 improved apps, 4 show S1=4 with "
            "S3_satisfied=0 (engine skip advances only); mobilizon has S3=2, everyonestimetable "
            "S3=1. Correlation partly reflects pointer movement co-occurring with richer Frida traces."
        ),
        "distinct_meaningful_categories": (
            "Read directly from Frida jsonl via meaningful-event category filter; "
            "independent of S1/S2/S3 — remains trustworthy."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", default="logs/exp_engineoff_v6/dataset_index.csv")
    parser.add_argument("--out", default="experiment/completion_reconciliation.json")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    sessions: list[dict[str, Any]] = []
    for row in csv.DictReader((root / args.index).open(encoding="utf-8")):
        if row.get("status") != "success":
            continue
        pkg = row["package_name"]
        base = Path(row["metadata_path"]).parent
        sessions.append(analyze_session(base, pkg))

    newpipe = next(s for s in sessions if s["package"] == "InfinityLoop1309.NewPipeEnhanced")
    table = []
    for s in sessions:
        table.append(
            {
                "package": s["package"],
                "planned": s["goals_planned"],
                "S1_idx": s["S1_final_ux_goal_idx"]["primary_S1"],
                "S2_advance_actions": s["S2_advance_goal_action_count"],
                "S3_satisfied": s["S3_satisfied"]["satisfied_row_count_any_action"],
                "S3_satisfied_advance": s["S3_satisfied"]["satisfied_advance_goal_count"],
                "S3_successful_advance": s["S3_satisfied"]["successful_advance_goal_count"],
                "agreement_flag": s["agreement_flag"],
                "agreement_note": s["agreement_note"],
            }
        )

    result = {
        "experiment": "goal_completion_signal_reconciliation",
        "index": str(root / args.index),
        "sessions": sessions,
        "summary_table": table,
        "newpipe_explanation": {
            "why_S1_is_4": (
                "human_ux_report final_goal_index=4 of 9; last advance_goal row has ux_goal_index=4. "
                "Four advance_goal actions moved the pointer to index 4."
            ),
            "why_S3_is_0": (
                "No row has ux_goal_status=='satisfied'. All four advance_goal rows are engine-injected "
                "skips with status feasible (3) or blocked (1), reason engine_prose_spiral_skip_*."
            ),
            "quoted_advance_goal_rows": newpipe["advance_goal_rows"],
            "final_action_row": {
                "step": 95,
                "pipeline_phase": "primary_ux",
                "ux_goal_index": None,
                "ux_goal_status": None,
                "note": "Session ended in primary_ux tap; pointer index not on final row.",
            },
        },
        "step3_verdict": _verdict(sessions),
        "step4_impact": _impact(),
    }

    out_path = root / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
