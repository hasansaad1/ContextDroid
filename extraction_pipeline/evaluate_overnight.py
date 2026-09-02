#!/usr/bin/env python3
"""Evaluate overnight engine-off sessions on workability vs UX quality axes."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluate_scenario_level import (
    LOW_SIGNAL_CATEGORIES,
    FRAMEWORK_APIS,
    _is_meaningful_event,
    _load_actions,
    _load_frida_events,
    _session_alignment,
)
from phase_attribution import _phase_at_agent_time, _goal_anchor_actions, _is_goal_associated

OVERNIGHT_CUTOFF_ISO = "2026-06-28T21:41:00Z"
HOOK_CATEGORIES_22 = [
    "accounts",
    "audio",
    "camera",
    "clipboard",
    "content_access",
    "crypto",
    "database",
    "device_info",
    "dynamic_code_loading",
    "file_io",
    "lifecycle",
    "location",
    "media",
    "navigation",
    "network",
    "notifications",
    "package_manager",
    "process",
    "reflection",
    "sms",
    "storage",
    "webview",
]
MEANINGFUL_HOOK_CATEGORIES = [c for c in HOOK_CATEGORIES_22 if c not in LOW_SIGNAL_CATEGORIES]


def _dist(vals: list[float]) -> dict[str, float]:
    if not vals:
        return {"min": 0.0, "p25": 0.0, "median": 0.0, "p75": 0.0, "max": 0.0, "n": 0}
    s = sorted(vals)
    n = len(s)
    q1 = statistics.quantiles(s, n=4)[0] if n >= 4 else s[0]
    q3 = statistics.quantiles(s, n=4)[2] if n >= 4 else s[-1]
    return {
        "min": float(s[0]),
        "p25": float(q1),
        "median": float(statistics.median(s)),
        "p75": float(q3),
        "max": float(s[-1]),
        "n": float(n),
    }


def _frida_behavior(frida_path: Path) -> dict[str, Any]:
    events = _load_frida_events(frida_path)
    meaningful = [e for e in events if _is_meaningful_event(e)]
    total = len(events)
    reflection = sum(
        1
        for e in events
        if e.get("api") in FRAMEWORK_APIS or e.get("category") in {"reflection", "lifecycle"}
    )
    cats = sorted({e["category"] for e in meaningful})
    return {
        "meaningful_events": len(meaningful),
        "distinct_meaningful_categories": len(cats),
        "category_set": cats,
        "reflection_share": (reflection / total) if total else None,
        "total_frida_events": total,
    }


def _phase_credit(frida_path: Path, actions_path: Path) -> dict[str, Any]:
    frida_events = _load_frida_events(frida_path)
    actions = _load_actions(actions_path)
    actions.sort(key=lambda a: int(a.get("ts_epoch_ms") or 0))
    offset, conf = _session_alignment(frida_events, actions)
    cats_first: dict[str, str] = {}
    events_by_phase: Counter[str] = Counter()
    if conf != "aligned" or offset is None:
        return {
            "session_offset_ms": offset,
            "alignment_confidence": conf,
            "categories_credited_explore": 0,
            "categories_credited_execute": 0,
            "categories_credited_primary_ux": 0,
            "events_by_phase": {},
        }
    for ev in frida_events:
        if not _is_meaningful_event(ev):
            continue
        agent_equiv = int(ev["timestamp"]) - offset
        phase, _ = _phase_at_agent_time(agent_equiv, actions)
        events_by_phase[phase] += 1
        cat = ev["category"]
        if cat not in cats_first:
            cats_first[cat] = phase
    credit = Counter(cats_first.values())
    return {
        "session_offset_ms": offset,
        "alignment_confidence": conf,
        "categories_credited_explore": credit.get("explore", 0),
        "categories_credited_execute": credit.get("execute", 0),
        "categories_credited_primary_ux": credit.get("primary_ux", 0),
        "events_by_phase": dict(events_by_phase),
    }


def _ux_metrics(base: Path, pkg: str, meta: dict[str, Any]) -> dict[str, Any]:
    report_path = base / f"{pkg}_human_ux_report.json"
    actions = _load_actions(base / f"{pkg}_llm_actions.jsonl")
    sim = str(meta.get("llm_simulation_status") or "")
    ux: dict[str, Any] = {
        "llm_simulation_status": sim,
        "sim_success": sim == "success",
    }
    if report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        checks = {c["id"]: c for c in report.get("checks") or []}
        ux.update(
            {
                "human_ux_overall_pass": bool(report.get("human_ux_overall_pass")),
                "human_ux_mechanistic_pass": bool(report.get("human_ux_mechanistic_pass")),
                "human_ux_behavior_pass": bool(report.get("human_ux_behavior_pass")),
                "human_ux_session_pass": bool(report.get("human_ux_session_pass")),
                "check_pass_rates": {
                    cid: bool(c.get("passed")) for cid, c in checks.items()
                },
            }
        )
        for key in (
            "min_screen_diversity",
            "direct_action_ratio",
            "planner_action_contract",
            "meaningful_goal_progress",
        ):
            if key in checks:
                ux[f"{key}_passed"] = bool(checks[key].get("passed"))
    else:
        ux["human_ux_overall_pass"] = None

    screens: set[str] = set()
    ts_vals: list[int] = []
    for act in actions:
        for k in ("screen_hash", "screen_hash_after"):
            h = act.get(k)
            if h:
                screens.add(str(h))
        if act.get("ts_epoch_ms") is not None:
            ts_vals.append(int(act["ts_epoch_ms"]))
    ux["distinct_screens"] = len(screens)
    ux["total_actions"] = len(actions)

    started = int(meta.get("started_at_epoch_ms") or 0)
    elapsed_ms = int(float(meta.get("elapsed_sec") or 0) * 1000)
    end_ms = started + elapsed_ms if started and elapsed_ms else (max(ts_vals) if ts_vals else 0)
    start_ms = min(ts_vals) if ts_vals else started
    span = max(1, end_ms - start_ms) if end_ms > start_ms else 1
    bins = [0, 0, 0, 0]
    for t in ts_vals:
        q = min(3, int((t - start_ms) / span * 4))
        bins[q] += 1
    total = sum(bins)
    fracs = [b / total for b in bins] if total else [0.0, 0.0, 0.0, 0.0]
    ux["temporal_spread_quartiles"] = fracs
    ux["front_loaded_then_flat"] = fracs[2] + fracs[3] < 0.1 and total >= 20
    return ux


def _is_workable(behavior: dict[str, Any]) -> bool:
    cats = behavior.get("distinct_meaningful_categories") or 0
    rs = behavior.get("reflection_share")
    return cats >= 3 and rs is not None and rs < 0.50


def _analyze_row(row: dict[str, str]) -> dict[str, Any] | None:
    if row.get("status") != "success":
        return None
    pkg = row["package_name"]
    base = Path(row["metadata_path"]).parent
    frida_path = Path(row["frida_log_path"])
    if not frida_path.exists():
        return None
    meta = json.loads(Path(row["metadata_path"]).read_text(encoding="utf-8"))
    behavior = _frida_behavior(frida_path)
    phase = _phase_credit(frida_path, base / f"{pkg}_llm_actions.jsonl")
    ux = _ux_metrics(base, pkg, meta)
    workable = _is_workable(behavior)
    ux_pass = bool(ux.get("human_ux_overall_pass"))
    return {
        "package": pkg,
        "session_id": row.get("session_id") or meta.get("session_id"),
        "artifact_path": str(base),
        "analysis_timestamp": row.get("analysis_timestamp"),
        "axis1_behavior": {**behavior, **phase},
        "axis2_ux": ux,
        "behaviorally_workable": workable,
        "ux_overall_pass": ux_pass,
        "cross_tab_cell": (
            "both"
            if workable and ux_pass
            else "rich_but_failed"
            if workable and not ux_pass
            else "looks_good_useless"
            if not workable and ux_pass
            else "neither"
        ),
    }


def _cohort(rows: list[dict[str, str]], *, overnight: bool) -> list[dict[str, str]]:
    cutoff = datetime.fromisoformat(OVERNIGHT_CUTOFF_ISO.replace("Z", "+00:00"))
    out: list[dict[str, str]] = []
    for row in rows:
        ts = row.get("analysis_timestamp") or ""
        if not ts:
            continue
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        is_overnight = dt >= cutoff
        if overnight and is_overnight:
            out.append(row)
        elif not overnight and not is_overnight:
            out.append(row)
    return out


def _aggregate(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    cats_vals = [s["axis1_behavior"]["distinct_meaningful_categories"] for s in sessions]
    degenerate = [s["package"] for s in sessions if s["axis1_behavior"]["distinct_meaningful_categories"] <= 1]
    corpus_cats: set[str] = set()
    for s in sessions:
        corpus_cats.update(s["axis1_behavior"]["category_set"])
    workable = [s for s in sessions if s["behaviorally_workable"]]
    sim_dist = Counter(s["axis2_ux"]["llm_simulation_status"] for s in sessions)
    ux_pass_n = sum(1 for s in sessions if s["ux_overall_pass"])
    cross = Counter(s["cross_tab_cell"] for s in sessions)
    credit_explore = sum(s["axis1_behavior"]["categories_credited_explore"] for s in sessions)
    credit_execute = sum(s["axis1_behavior"]["categories_credited_execute"] for s in sessions)
    credit_primary = sum(s["axis1_behavior"]["categories_credited_primary_ux"] for s in sessions)
    credit_total = credit_explore + credit_execute + credit_primary
    return {
        "sessions": len(sessions),
        "distinct_meaningful_categories_distribution": _dist([float(v) for v in cats_vals]),
        "corpus_meaningful_category_coverage": {
            "categories_seen": sorted(corpus_cats),
            "count_seen": len(corpus_cats),
            "of_22_hook_categories": len(HOOK_CATEGORIES_22),
            "of_20_meaningful_hook_categories": len(MEANINGFUL_HOOK_CATEGORIES),
        },
        "degenerate_apps_0_1_categories": degenerate,
        "behaviorally_usable_sessions": len(workable),
        "behaviorally_usable_pct": (100.0 * len(workable) / len(sessions)) if sessions else 0.0,
        "distinct_apps_with_usable_session": len({s["package"] for s in workable}),
        "phase_category_credit": {
            "explore": credit_explore,
            "execute": credit_execute,
            "primary_ux": credit_primary,
            "pct_explore": (100.0 * credit_explore / credit_total) if credit_total else 0.0,
            "pct_execute": (100.0 * credit_execute / credit_total) if credit_total else 0.0,
            "pct_primary_ux": (100.0 * credit_primary / credit_total) if credit_total else 0.0,
        },
        "axis2_ux_process_quality": {
            "llm_simulation_status_distribution": dict(sim_dist),
            "human_ux_overall_pass_count": ux_pass_n,
            "human_ux_overall_pass_pct": (100.0 * ux_pass_n / len(sessions)) if sessions else 0.0,
            "front_loaded_then_flat_count": sum(
                1 for s in sessions if s["axis2_ux"].get("front_loaded_then_flat")
            ),
        },
        "cross_tab": dict(cross),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", default="logs/bulk_llm_benign_v6/dataset_index.csv")
    parser.add_argument("--out-json", default="experiment/overnight_evaluation.json")
    parser.add_argument("--out-csv", default="experiment/reference_overnight_usable.csv")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    rows = list(csv.DictReader((root / args.index).open(encoding="utf-8")))
    overnight_rows = _cohort(rows, overnight=True)
    prior_rows = _cohort(rows, overnight=False)

    overnight_sessions = [s for r in overnight_rows if (s := _analyze_row(r))]
    prior_sessions = [s for r in prior_rows if (s := _analyze_row(r))]

    overnight_agg = _aggregate(overnight_sessions)
    prior_agg = _aggregate(prior_sessions)

    usable_csv = root / args.out_csv
    usable_csv.parent.mkdir(parents=True, exist_ok=True)
    with usable_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "package",
                "session_id",
                "artifact_path",
                "distinct_meaningful_categories",
                "category_set",
                "reflection_share",
            ],
        )
        writer.writeheader()
        for s in overnight_sessions:
            if not s["behaviorally_workable"]:
                continue
            b = s["axis1_behavior"]
            writer.writerow(
                {
                    "package": s["package"],
                    "session_id": s["session_id"],
                    "artifact_path": s["artifact_path"],
                    "distinct_meaningful_categories": b["distinct_meaningful_categories"],
                    "category_set": "|".join(b["category_set"]),
                    "reflection_share": b["reflection_share"],
                }
            )

    o_usable = overnight_agg["behaviorally_usable_sessions"]
    p_usable = prior_agg["behaviorally_usable_sessions"]
    o_pct = overnight_agg["behaviorally_usable_pct"]
    shift = (
        "more"
        if o_usable > p_usable
        else "fewer"
        if o_usable < p_usable
        else "similar"
    )
    med_o = overnight_agg["distinct_meaningful_categories_distribution"]["median"]
    med_p = prior_agg["distinct_meaningful_categories_distribution"]["median"]

    if o_usable >= max(10, int(0.15 * len(overnight_sessions))):
        verdict = "partially workable thesis dataset"
        verdict_detail = (
            f"{o_usable} behaviorally usable sessions ({o_pct:.1f}% of overnight cohort) "
            f"across {overnight_agg['distinct_apps_with_usable_session']} apps."
        )
    elif o_usable > 0:
        verdict = "marginally workable — small usable subset only"
        verdict_detail = f"Only {o_usable} usable sessions ({o_pct:.1f}%) in overnight engine-off cohort."
    else:
        verdict = "not yet workable on behavioral category signal"
        verdict_detail = "Zero sessions met >=3 meaningful categories with reflection_share < 50%."

    result = {
        "experiment": "overnight_engine_off_evaluation",
        "log_dir": str(root / "logs/bulk_llm_benign_v6"),
        "overnight_cohort_cutoff": OVERNIGHT_CUTOFF_ISO,
        "overnight_cohort_note": (
            "Sessions with analysis_timestamp >= resume start (engine-off batch on previously-unrun apps). "
            "First 164 completed apps before cutoff used engine-only=1; excluded from overnight cohort."
        ),
        "config_confirmed": {
            "CONTEXTDROID_LLM_EXECUTE_ENGINE_ONLY": 0,
            "OLLAMA_MODEL": "llama3.2",
            "duration_sec": 600,
            "EXPLORE_RATIO": 0.30,
            "hook_script": "frida_scripts/hook_apis.js",
            "note": "EXECUTE_ENGINE_ONLY not stored per-session in metadata; inferred from run script default at resume.",
        },
        "overnight_sessions_in_index": len(overnight_rows),
        "overnight_sessions_analyzed": len(overnight_sessions),
        "axis1_workability": {
            "per_session": overnight_sessions,
            "aggregates": overnight_agg,
        },
        "axis2_ux_process_quality": {
            "label": "process quality, not behavioral quality",
            "per_session_ux": [
                {"package": s["package"], "session_id": s["session_id"], **s["axis2_ux"]}
                for s in overnight_sessions
            ],
            "aggregates": overnight_agg["axis2_ux_process_quality"],
        },
        "cross_tab": overnight_agg["cross_tab"],
        "comparison_prior_v6_engine_on": {
            "prior_sessions_analyzed": len(prior_sessions),
            "prior_usable_sessions": p_usable,
            "prior_usable_pct": prior_agg["behaviorally_usable_pct"],
            "prior_median_distinct_meaningful_categories": med_p,
            "overnight_median_distinct_meaningful_categories": med_o,
            "usable_session_shift": shift,
            "category_median_shift": med_o - med_p,
        },
        "workability_verdict": verdict,
        "workability_verdict_detail": verdict_detail,
    }

    out_json = root / args.out_json
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"wrote {out_json}")
    print(f"wrote {usable_csv}")
    print(f"overnight usable: {o_usable}/{len(overnight_sessions)} ({o_pct:.1f}%)")
    print(f"verdict: {verdict}")


if __name__ == "__main__":
    main()
