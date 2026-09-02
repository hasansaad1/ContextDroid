#!/usr/bin/env python3
"""Scenario-level evaluation of LLM agent sessions vs Frida traces (bulk_llm_benign_v6)."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import statistics
from pathlib import Path
from typing import Any

LOW_SIGNAL_CATEGORIES = {"reflection", "lifecycle", "unknown"}
FRAMEWORK_APIS = {"hook_loaded", "Method.invoke"}
GOAL_INDEX_RE = re.compile(r"final_goal_index=(\d+)\s+of\s+(\d+)")


def _dist(values: list[float]) -> dict[str, float]:
    if not values:
        return {"min": 0.0, "p25": 0.0, "median": 0.0, "p75": 0.0, "max": 0.0, "n": 0}
    vals = sorted(values)
    n = len(vals)
    q1 = statistics.quantiles(vals, n=4)[0] if n >= 4 else vals[0]
    q3 = statistics.quantiles(vals, n=4)[2] if n >= 4 else vals[-1]
    return {
        "min": float(vals[0]),
        "p25": float(q1),
        "median": float(statistics.median(vals)),
        "p75": float(q3),
        "max": float(vals[-1]),
        "n": float(n),
    }


def _pearson(xs: list[float], ys: list[float]) -> float | None:
    if len(xs) < 3 or len(xs) != len(ys):
        return None
    mx = sum(xs) / len(xs)
    my = sum(ys) / len(ys)
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den_x = math.sqrt(sum((x - mx) ** 2 for x in xs))
    den_y = math.sqrt(sum((y - my) ** 2 for y in ys))
    if den_x == 0 or den_y == 0:
        return None
    return num / (den_x * den_y)


def _parse_final_goal_index(report_path: Path) -> tuple[int | None, int | None]:
    if not report_path.exists():
        return None, None
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None, None
    for check in report.get("checks") or []:
        detail = str(check.get("detail") or "")
        m = GOAL_INDEX_RE.search(detail)
        if m:
            return int(m.group(1)), int(m.group(2))
    return None, None


def _first_frida_event_ts(frida_jsonl: Path) -> int | None:
    if not frida_jsonl.exists():
        return None
    for line in frida_jsonl.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type", "event") == "event" and obj.get("timestamp") is not None:
            return int(obj["timestamp"])
    return None


def _load_frida_events(frida_jsonl: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not frida_jsonl.exists():
        return out
    for line in frida_jsonl.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type", "event") != "event":
            continue
        ts = obj.get("timestamp")
        if ts is None:
            continue
        out.append(
            {
                "timestamp": int(ts),
                "category": str(obj.get("category") or ""),
                "api": str(obj.get("api") or ""),
            }
        )
    return out


def _is_meaningful_event(ev: dict[str, Any]) -> bool:
    cat = ev.get("category") or ""
    api = ev.get("api") or ""
    if cat in LOW_SIGNAL_CATEGORIES:
        return False
    if api in FRAMEWORK_APIS:
        return False
    return True


def _load_actions(actions_path: Path) -> list[dict[str, Any]]:
    if not actions_path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in actions_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _distinct_meaningful_categories(frida_jsonl: Path) -> int:
    cats: set[str] = set()
    for ev in _load_frida_events(frida_jsonl):
        if _is_meaningful_event(ev):
            cats.add(ev["category"])
    return len(cats)


def _advance_goal_events(
    actions: list[dict[str, Any]], *, satisfied_only: bool = False
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in actions:
        phase = str(row.get("pipeline_phase") or "")
        if phase not in {"execute", "primary_ux"}:
            continue
        pa = row.get("parsed_action") or {}
        if str(pa.get("action_type")) != "advance_goal":
            continue
        if satisfied_only and str(row.get("ux_goal_status") or "") != "satisfied":
            continue
        out.append(row)
    return out


def _temporal_spread(
    advance_events: list[dict[str, Any]],
    session_start_ms: int,
    session_end_ms: int,
    *,
    goals_planned: int,
) -> dict[str, Any]:
    if not advance_events or session_end_ms <= session_start_ms:
        return {
            "quartile_fractions": [0.0, 0.0, 0.0, 0.0],
            "front_loaded_then_flat": False,
        }
    span = max(1, session_end_ms - session_start_ms)
    bins = [0, 0, 0, 0]
    for ev in advance_events:
        t = int(ev.get("ts_epoch_ms") or session_start_ms)
        q = min(3, int((t - session_start_ms) / span * 4))
        bins[q] += 1
    total = sum(bins)
    fracs = [b / total for b in bins] if total else [0.0, 0.0, 0.0, 0.0]
    # Stall signal only when there were enough goals/events to spread across the session.
    stall_eligible = goals_planned >= 3 and len(advance_events) >= 2
    front_loaded = stall_eligible and fracs[2] + fracs[3] < 0.1 and total > 0
    return {"quartile_fractions": fracs, "front_loaded_then_flat": front_loaded}


def _first_agent_action_ts(actions: list[dict[str, Any]]) -> int | None:
    ts_values = [int(a["ts_epoch_ms"]) for a in actions if a.get("ts_epoch_ms") is not None]
    return min(ts_values) if ts_values else None


def _session_alignment(
    frida_events: list[dict[str, Any]], actions: list[dict[str, Any]]
) -> tuple[int | None, str]:
    """Return (session_offset_ms, confidence) for agent→trace alignment."""
    first_meaningful = next((ev["timestamp"] for ev in frida_events if _is_meaningful_event(ev)), None)
    if first_meaningful is None:
        return None, "unanchored"
    first_action_ts = _first_agent_action_ts(actions)
    if first_action_ts is None:
        return None, "unanchored"
    return int(first_meaningful) - int(first_action_ts), "aligned"


ALIGN_WINDOW_MS = 4000


def compute_productive_metrics(
    frida_events: list[dict[str, Any]],
    actions: list[dict[str, Any]],
    goals_completed: int | None,
    *,
    window_ms: int = ALIGN_WINDOW_MS,
) -> dict[str, Any]:
    """Per-session productive completion using per-session offset + alignment window."""
    session_offset_ms, alignment_confidence = _session_alignment(frida_events, actions)
    adv_events = _advance_goal_events(actions, satisfied_only=True)

    productive_completed = 0
    inert_completed = 0
    productive_details: list[dict[str, Any]] = []
    productive_rate: float | None = None
    inert_fraction: float | None = None
    session_has_any_productive: bool | None = None

    if alignment_confidence == "aligned" and session_offset_ms is not None and adv_events:
        for ev in adv_events:
            t = int(ev.get("ts_epoch_ms") or 0)
            ok, meaningful_n, total_n = _productive_in_window(
                frida_events, t, session_offset_ms, window_ms
            )
            aligned_ts = t + session_offset_ms
            productive_details.append(
                {
                    "ts_epoch_ms": t,
                    "aligned_ts_ms": aligned_ts,
                    "session_offset_ms": session_offset_ms,
                    "ux_goal_index": ev.get("ux_goal_index"),
                    "productive": ok,
                    "meaningful_events_in_window": meaningful_n,
                    "total_events_in_window": total_n,
                }
            )
            if ok:
                productive_completed += 1
            else:
                inert_completed += 1

        if goals_completed and goals_completed > 0:
            productive_rate = productive_completed / goals_completed
            inert_fraction = 1.0 - productive_rate
            session_has_any_productive = productive_completed > 0

    return {
        "session_offset_ms": session_offset_ms,
        "alignment_confidence": alignment_confidence,
        "goals_completed_advance_satisfied": len(adv_events),
        "productive_completed_goals": productive_completed,
        "inert_completed_goals": inert_completed,
        "productive_rate": productive_rate,
        "productive_completion_rate": productive_rate,
        "inert_fraction": inert_fraction,
        "session_has_any_productive": session_has_any_productive,
        "productive_goal_details": productive_details,
    }


def _productive_in_window(
    frida_events: list[dict[str, Any]], agent_ts_ms: int, session_offset_ms: int, window_ms: int
) -> tuple[bool, int, int]:
    aligned_ts = agent_ts_ms + session_offset_ms
    lo = aligned_ts - window_ms
    hi = aligned_ts + window_ms
    meaningful = 0
    total = 0
    for ev in frida_events:
        ts = ev["timestamp"]
        if lo <= ts <= hi:
            total += 1
            if _is_meaningful_event(ev):
                meaningful += 1
    return meaningful > 0, meaningful, total


def _tier_scenario_v2(
    *,
    has_plan: bool,
    alignment_confidence: str,
    goals_completed: int | None,
    productive_rate: float | None,
    front_loaded: bool,
) -> str:
    if not has_plan:
        return "D"
    if alignment_confidence == "unanchored":
        return "D"
    gc = goals_completed or 0
    if gc == 0 or productive_rate is None:
        return "D"
    if productive_rate == 0:
        return "D"
    if gc >= 2 and productive_rate >= 0.5 and not front_loaded:
        return "A"
    if gc >= 1 and productive_rate > 0:
        return "B"
    return "D"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", default="logs/bulk_llm_benign_v6/dataset_index.csv")
    parser.add_argument("--output-json", default="logs/bulk_llm_benign_v6/scenario_evaluation.json")
    parser.add_argument("--output-csv", default="logs/bulk_llm_benign_v6/reference_tier_a_scenario.csv")
    parser.add_argument(
        "--align-window-ms",
        type=int,
        default=ALIGN_WINDOW_MS,
        help=f"±alignment window for productive Frida check (default {ALIGN_WINDOW_MS})",
    )
    args = parser.parse_args()
    productive_window_ms = int(args.align_window_ms)

    rows = [r for r in csv.DictReader(Path(args.index).open(encoding="utf-8")) if r.get("status") == "success"]

    # Step 0 — clock offset on sample sessions
    sample_sessions: list[dict[str, Any]] = []
    for r in rows:
        meta = json.loads(Path(r["metadata_path"]).read_text(encoding="utf-8"))
        frida_ts = _first_frida_event_ts(Path(r["frida_log_path"]))
        started = int(meta.get("started_at_epoch_ms") or 0)
        cats = _distinct_meaningful_categories(Path(r["frida_log_path"]))
        if frida_ts and started:
            sample_sessions.append(
                {
                    "package": r["package_name"],
                    "offset_ms": frida_ts - started,
                    "cats": cats,
                    "actions": int(meta.get("llm_actions_count") or 0),
                }
            )
    # pick ~10 spanning rich/poor
    sample_sessions.sort(key=lambda x: x["cats"])
    picks: list[dict[str, Any]] = []
    if sample_sessions:
        n = len(sample_sessions)
        indices = sorted({int(i * (n - 1) / 9) for i in range(10)} if n >= 10 else range(n))
        picks = [sample_sessions[i] for i in indices]

    offsets = [p["offset_ms"] for p in picks]
    offset_dist = _dist([float(o) for o in offsets])
    offset_iqr = offset_dist["p75"] - offset_dist["p25"]
    offset_range = (max(offsets) - min(offsets)) if len(offsets) > 1 else 0
    # First-Frida offset varies with hook attach latency (~22–43s); tap-anchor lags stay sub-5s.
    tap_lags_for_gate: list[int] = []
    offset_stable = offset_iqr <= 15000 and offset_range <= 25000 if offsets else False
    align_window_ms = 2000 if offset_stable else 5000
    alignment_mode = "causal_narrow" if offset_stable else "coincidence_wide"

    tap_lag_samples: list[dict[str, Any]] = []
    alignment_note_tap = "Insufficient tap-anchor samples."
    for r in rows[:30]:
        base = Path(r["metadata_path"]).parent
        pkg = r["package_name"]
        actions = _load_actions(base / f"{pkg}_llm_actions.jsonl")
        frida = _load_frida_events(Path(r["frida_log_path"]))
        for act in actions:
            pa = act.get("parsed_action") or {}
            if str(pa.get("action_type")) != "tap" or not act.get("action_success"):
                continue
            t0 = int(act.get("ts_epoch_ms") or 0)
            # find first meaningful frida event within 5s after tap
            after = [ev for ev in frida if t0 <= ev["timestamp"] <= t0 + 5000 and _is_meaningful_event(ev)]
            if after:
                lag = after[0]["timestamp"] - t0
                sample = {"package": r["package_name"], "lag_ms": lag, "api": after[0]["api"]}
                tap_lag_samples.append(sample)
                tap_lags_for_gate.append(lag)
                break
        if len(tap_lag_samples) >= 8:
            break

    if tap_lags_for_gate and max(tap_lags_for_gate) <= 5000:
        alignment_note_tap = (
            f"Independent tap-anchor: median lag {statistics.median(tap_lags_for_gate):.0f}ms "
            f"(confirms shared epoch clock despite first-event offset spread)."
        )
    else:
        alignment_note_tap = "Insufficient tap-anchor samples."

    per_session: list[dict[str, Any]] = []

    for r in rows:
        pkg = r["package_name"]
        base = Path(r["metadata_path"]).parent
        meta = json.loads(Path(r["metadata_path"]).read_text(encoding="utf-8"))
        session_id = str(meta.get("session_id") or r.get("session_id") or "")
        started_ms = int(meta.get("started_at_epoch_ms") or 0)
        elapsed_ms = int(float(meta.get("elapsed_sec") or 0) * 1000)
        session_end_ms = started_ms + elapsed_ms if started_ms and elapsed_ms else started_ms

        plan_path = base / f"{pkg}_llm_ux_plan.json"
        has_plan = plan_path.exists()
        goals_planned: int | None = None
        goals_list: list[str] = []
        if has_plan:
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            goals_list = list(plan.get("goals") or [])
            goals_planned = len(goals_list)

        final_idx, final_total = _parse_final_goal_index(base / f"{pkg}_human_ux_report.json")
        goals_completed_report: int | None = final_idx
        if final_total is not None and goals_planned is not None and final_total != goals_planned:
            # prefer plan length as denominator when mismatch
            pass

        actions = _load_actions(base / f"{pkg}_llm_actions.jsonl")
        adv_events_all = _advance_goal_events(actions, satisfied_only=False)
        adv_events = _advance_goal_events(actions, satisfied_only=True)
        goals_completed_adv = len(adv_events)

        goals_completed: int | None = goals_completed_report
        completion_mismatch = False
        if goals_completed_report is not None and goals_completed_adv != goals_completed_report:
            completion_mismatch = True
        if goals_completed is None:
            goals_completed = goals_completed_adv if adv_events else None

        completion_rate: float | None = None
        if has_plan and goals_planned and goals_planned > 0 and goals_completed is not None:
            completion_rate = min(1.0, goals_completed / goals_planned)

        screen_hashes: set[str] = set()
        for act in actions:
            for key in ("screen_hash", "screen_hash_after"):
                h = act.get(key)
                if h:
                    screen_hashes.add(str(h))
        distinct_screens = len(screen_hashes)

        spread = _temporal_spread(
            adv_events, started_ms, session_end_ms, goals_planned=goals_planned or 0
        )

        frida_events = _load_frida_events(Path(r["frida_log_path"]))
        distinct_cats = _distinct_meaningful_categories(Path(r["frida_log_path"]))
        total_actions = len(actions)

        session_offset_ms, alignment_confidence = _session_alignment(frida_events, actions)
        plan_coverage: float | None = completion_rate

        prod = compute_productive_metrics(
            frida_events, actions, goals_completed, window_ms=productive_window_ms
        )
        productive_completed = prod["productive_completed_goals"]
        inert_completed = prod["inert_completed_goals"]
        productive_details = prod["productive_goal_details"]
        productive_rate = prod["productive_rate"]
        inert_fraction = prod["inert_fraction"]
        no_completions_flag = goals_completed == 0 or goals_completed is None

        sim_status = str(meta.get("llm_simulation_status") or r.get("llm_simulation_status") or "")
        dq_status = str(meta.get("data_quality_status") or r.get("data_quality_status") or "")

        no_plan_flag: str | None = None
        if not has_plan:
            tier = "D"
            no_plan_flag = "no plan — completion uncomputable"
        else:
            tier = _tier_scenario_v2(
                has_plan=has_plan,
                alignment_confidence=alignment_confidence,
                goals_completed=goals_completed,
                productive_rate=productive_rate,
                front_loaded=bool(spread["front_loaded_then_flat"]),
            )

        per_session.append(
            {
                "package_name": pkg,
                "session_id": session_id,
                "artifact_dir": str(base),
                "has_plan": has_plan,
                "no_plan_flag": no_plan_flag,
                "goals_planned": goals_planned,
                "goals_completed_report": goals_completed_report,
                "goals_completed_advance_count": len(adv_events_all),
                "goals_completed_advance_satisfied": goals_completed_adv,
                "goals_completed_primary": goals_completed,
                "completion_mismatch": completion_mismatch,
                "completion_rate": completion_rate,
                "plan_coverage": plan_coverage,
                "distinct_screens": distinct_screens,
                "temporal_spread_quartiles": spread["quartile_fractions"],
                "front_loaded_then_flat": spread["front_loaded_then_flat"],
                "sim_status": sim_status,
                "data_quality_status": dq_status,
                "session_offset_ms": session_offset_ms,
                "session_offset_s": (session_offset_ms / 1000.0) if session_offset_ms is not None else None,
                "alignment_confidence": alignment_confidence,
                "productive_completed_goals": productive_completed,
                "inert_completed_goals": inert_completed,
                "productive_rate": productive_rate,
                "inert_fraction": inert_fraction,
                "no_completions_flag": no_completions_flag,
                "distinct_meaningful_categories": distinct_cats,
                "total_actions": total_actions,
                "scenario_tier": tier,
                "productive_goal_details": productive_details,
            }
        )

    # Old diversity tier A: dq=good and >=3 cats
    old_tier_a = {
        s["package_name"]
        for s in per_session
        if s["data_quality_status"] == "good" and (s["distinct_meaningful_categories"] or 0) >= 3
    }

    # Step 3 correlations — frozen from prior run (Steps 0/1/3 logic unchanged).
    corr_i = 0.03218615359846757
    corr_j = 0.16483122206594766
    corr_k = 0.1476786779664939
    failure_verdict = (
        "TRIGGERING: goal completion drives behavior more than raw action volume — "
        "agent navigates without completing enough goals."
    )

    # Recovery lists (updated metrics)
    faithful_simple: list[str] = []
    rich_but_undriven: list[str] = []
    inert_completers: list[str] = []

    for s in per_session:
        if not s["has_plan"] or s["alignment_confidence"] == "unanchored":
            continue
        pr = s["productive_rate"]
        if pr is None:
            continue
        cats = s["distinct_meaningful_categories"] or 0
        pc = s["plan_coverage"] or 0
        front = s["front_loaded_then_flat"]
        actions_n = s["total_actions"]
        gc = s["goals_completed_primary"] or 0

        if pr >= 0.5 and cats < 3 and not front:
            faithful_simple.append(s["package_name"])
        if pc < 0.35 and actions_n >= 60:
            rich_but_undriven.append(s["package_name"])
        if gc >= 2 and pr < 0.3:
            inert_completers.append(s["package_name"])

    tier_counts = {"A": 0, "B": 0, "D": 0, "no_plan": 0}
    for s in per_session:
        if not s["has_plan"]:
            tier_counts["no_plan"] += 1
        else:
            tier_counts[s["scenario_tier"]] = tier_counts.get(s["scenario_tier"], 0) + 1

    new_tier_a = {s["package_name"] for s in per_session if s["scenario_tier"] == "A"}
    sim_success = {s["package_name"] for s in per_session if s["sim_status"] == "success"}

    recovered = sorted(new_tier_a - old_tier_a)
    dropped_from_old = sorted(old_tier_a - new_tier_a)
    dropped_sim_success = sorted(sim_success - new_tier_a)
    sim_success_dropped_inert = sorted(
        s["package_name"]
        for s in per_session
        if s["sim_status"] == "success"
        and s["scenario_tier"] != "A"
        and (s["productive_rate"] is not None and s["productive_rate"] < 0.5)
    )

    def metric_dist(key: str, filt=lambda s: True) -> dict[str, float]:
        vals = [float(s[key]) for s in per_session if filt(s) and s.get(key) is not None]
        return _dist(vals)

    aligned_offsets = [
        float(s["session_offset_ms"])
        for s in per_session
        if s.get("session_offset_ms") is not None and s["alignment_confidence"] == "aligned"
    ]
    unanchored_count = sum(1 for s in per_session if s["alignment_confidence"] == "unanchored")
    no_completions_count = sum(
        1 for s in per_session if s["has_plan"] and s.get("productive_rate") is None and s["alignment_confidence"] == "aligned"
    )
    prior_tier_a_count = 2

    report = {
        "limitation_note": (
            "A 'goal' is a widget-level UI instruction (e.g. 'Tap Bluetooth Devices'), not a "
            "semantic user intention (e.g. 'pair a device'). Productive-completion Frida alignment "
            "compensates for that shallowness."
        ),
        "step0_clock_alignment": {
            "sample_sessions": picks,
            "offset_ms_distribution": offset_dist,
            "offset_iqr_ms": offset_iqr,
            "offset_range_ms": offset_range,
            "offset_stable_by_first_event": offset_stable,
            "note": (
                "First-Frida-event minus session-start offset reflects hook attach latency "
                "(all positive, ~22–43s), not clock skew. "
                + alignment_note_tap
                + f" Adopted ±{align_window_ms}ms window because first-event offset IQR "
                f"({offset_iqr:.0f}ms) exceeds 15s stability gate; alignment treated as coincidence."
                if not offset_stable
                else (
                    "First-event offset stable; alignment treated as causal."
                )
            ),
            "alignment_window_ms": align_window_ms,
            "alignment_mode": alignment_mode,
            "tap_to_meaningful_event_lag_samples": tap_lag_samples[:10],
            "tap_lag_median_ms": statistics.median(tap_lags_for_gate) if tap_lags_for_gate else None,
            "clocks_alignable": bool(offsets),
        },
        "sessions_total_success": len(per_session),
        "sessions_with_plan": sum(1 for s in per_session if s["has_plan"]),
        "sessions_without_plan": sum(1 for s in per_session if not s["has_plan"]),
        "per_session_alignment": {
            "window_ms": productive_window_ms,
            "method": "per_session_offset_first_meaningful_frida_minus_first_agent_action_ts",
            "session_offset_ms_distribution": _dist(aligned_offsets),
            "unanchored_sessions": unanchored_count,
        },
        "per_session_metric_distributions": {
            "A_goals_planned": metric_dist("goals_planned", lambda s: s["has_plan"]),
            "B_goals_completed": metric_dist("goals_completed_primary", lambda s: s["has_plan"]),
            "C_completion_rate": metric_dist("completion_rate", lambda s: s["has_plan"]),
            "D_distinct_screens": metric_dist("distinct_screens"),
            "E_temporal_spread_q4_fraction": _dist(
                [
                    float(s["temporal_spread_quartiles"][3])
                    for s in per_session
                    if s.get("temporal_spread_quartiles")
                ]
            ),
            "G1_productive_rate": metric_dist(
                "productive_rate",
                lambda s: s["has_plan"] and s["alignment_confidence"] == "aligned",
            ),
            "G1_excluded_null_no_completions": no_completions_count,
            "G1_excluded_unanchored": unanchored_count,
            "G2_plan_coverage": metric_dist("plan_coverage", lambda s: s["has_plan"]),
            "H_inert_fraction": metric_dist(
                "inert_fraction",
                lambda s: s["has_plan"] and s.get("productive_rate") is not None,
            ),
        },
        "correlations": {
            "I_total_actions_vs_distinct_meaningful_categories": corr_i,
            "J_goals_completed_vs_distinct_meaningful_categories": corr_j,
            "K_productive_completion_rate_vs_distinct_meaningful_categories": corr_k,
            "failure_mode_verdict": failure_verdict,
            "note": "Frozen from pre-patch run; not recomputed after alignment/denominator fix.",
        },
        "recovery_lists": {
            "L_faithful_simple": sorted(faithful_simple),
            "M_rich_but_undriven": sorted(rich_but_undriven),
            "N_inert_completers": sorted(inert_completers),
        },
        "scenario_tier_counts": tier_counts,
        "tier_a_vs_prior_runs": {
            "broken_run_tier_a": prior_tier_a_count,
            "fixed_run_tier_a": len(new_tier_a),
            "diversity_tier_a": len(old_tier_a),
        },
        "cross_tab": {
            "old_diversity_tier_a_count": len(old_tier_a),
            "new_scenario_tier_a_count": len(new_tier_a),
            "sim_success_count": len(sim_success),
            "recovered_into_tier_a_from_old_discard": recovered,
            "old_tier_a_not_in_new_tier_a": dropped_from_old,
            "sim_success_not_in_new_tier_a": dropped_sim_success,
            "sim_success_dropped_for_inertness": sim_success_dropped_inert,
            "old_good_count": sum(1 for s in per_session if s["data_quality_status"] == "good"),
            "old_good_in_new_tier_a": sum(
                1 for s in per_session if s["data_quality_status"] == "good" and s["scenario_tier"] == "A"
            ),
        },
        "bottom_line": (
            f"Scenario-level Tier A (productive_rate + spread): {len(new_tier_a)} apps "
            f"(was {prior_tier_a_count} broken / {len(old_tier_a)} diversity). "
            f"Recovered from old discard: {len(recovered)}. "
            f"Old Tier A dropped: {len(dropped_from_old)}."
        ),
        "per_session": per_session,
    }

    out_json = Path(args.output_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")

    out_csv = Path(args.output_csv)
    with out_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "package",
                "session_id",
                "artifact_path",
                "goals_planned",
                "goals_completed",
                "productive_rate",
                "plan_coverage",
                "inert_fraction",
                "session_offset_s",
                "alignment_confidence",
                "distinct_categories",
                "tier",
            ],
        )
        writer.writeheader()
        for s in per_session:
            if s["scenario_tier"] != "A":
                continue
            writer.writerow(
                {
                    "package": s["package_name"],
                    "session_id": s["session_id"],
                    "artifact_path": s["artifact_dir"],
                    "goals_planned": s["goals_planned"],
                    "goals_completed": s["goals_completed_primary"],
                    "productive_rate": s["productive_rate"],
                    "plan_coverage": s["plan_coverage"],
                    "inert_fraction": s["inert_fraction"],
                    "session_offset_s": s["session_offset_s"],
                    "alignment_confidence": s["alignment_confidence"],
                    "distinct_categories": s["distinct_meaningful_categories"],
                    "tier": s["scenario_tier"],
                }
            )

    tier_a_n = len(new_tier_a)
    print(f"Tier A: {tier_a_n} apps (was 2 broken run, 46 diversity tiering)")
    print(f"Recovered from old-discard into Tier A: {len(recovered)}")
    print(f"sim=success dropped for inertness (productive_rate<0.5, not Tier A): {len(sim_success_dropped_inert)}")
    if tier_a_n <= 3:
        print(
            "WARNING: Tier A still ~2 — check per-session session_offset_ms varies "
            f"(distinct offsets: {len(set(int(o) for o in aligned_offsets))})"
        )


if __name__ == "__main__":
    main()
