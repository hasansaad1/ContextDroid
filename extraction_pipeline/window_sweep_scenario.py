#!/usr/bin/env python3
"""Re-score existing sessions at multiple productive-alignment window widths."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluate_scenario_level import (
    _advance_goal_events,
    _distinct_meaningful_categories,
    _load_actions,
    _load_frida_events,
    _parse_final_goal_index,
    compute_productive_metrics,
)

DEFAULT_WINDOWS_MS = [4000, 6000, 8000, 10000]
MATERIAL_RATE_DELTA = 0.10
PLATEAU_DELTA = 0.02


def _median(vals: list[float]) -> float | None:
    return float(statistics.median(vals)) if vals else None


def _session_goals_completed(
    base: Path, pkg: str, actions: list[dict[str, Any]]
) -> int | None:
    final_idx, _ = _parse_final_goal_index(base / f"{pkg}_human_ux_report.json")
    adv_all = _advance_goal_events(actions, satisfied_only=False)
    goals_completed = final_idx
    if goals_completed is None:
        goals_completed = len(adv_all) if adv_all else None
    return goals_completed


def _score_index(
    index_csv: Path, windows_ms: list[int]
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    rows = [r for r in csv.DictReader(index_csv.open(encoding="utf-8")) if r.get("status") == "success"]
    per_app: list[dict[str, Any]] = []
    by_window: dict[str, dict[str, Any]] = {}

    for window_ms in windows_ms:
        rates: list[float] = []
        excluded_null = 0
        for r in rows:
            pkg = r["package_name"]
            base = Path(r["metadata_path"]).parent
            actions = _load_actions(base / f"{pkg}_llm_actions.jsonl")
            frida_events = _load_frida_events(Path(r["frida_log_path"]))
            goals_completed = _session_goals_completed(base, pkg, actions)
            prod = compute_productive_metrics(
                frida_events, actions, goals_completed, window_ms=window_ms
            )
            rate = prod["productive_rate"]
            if rate is None:
                excluded_null += 1
            else:
                rates.append(float(rate))
        by_window[str(window_ms)] = {
            "median_productive_rate_per_goal": _median(rates),
            "n_non_null": len(rates),
            "n_excluded_null": excluded_null,
            "n_total": len(rows),
        }

    for r in rows:
        pkg = r["package_name"]
        base = Path(r["metadata_path"]).parent
        actions = _load_actions(base / f"{pkg}_llm_actions.jsonl")
        frida_events = _load_frida_events(Path(r["frida_log_path"]))
        goals_completed = _session_goals_completed(base, pkg, actions)
        distinct_cats = _distinct_meaningful_categories(Path(r["frida_log_path"]))
        adv_satisfied = len(_advance_goal_events(actions, satisfied_only=True))

        windows: dict[str, dict[str, Any]] = {}
        for window_ms in windows_ms:
            prod = compute_productive_metrics(
                frida_events, actions, goals_completed, window_ms=window_ms
            )
            rate = prod["productive_rate"]
            windows[str(window_ms)] = {
                "goals_completed": goals_completed,
                "goals_completed_advance_satisfied": adv_satisfied,
                "productive_completed_goals": prod["productive_completed_goals"],
                "productive_rate_per_goal": rate,
                "session_has_any_productive": prod["session_has_any_productive"],
                "productive_count_over_goals_completed": rate,
                "inert_fraction": prod["inert_fraction"],
                "alignment_confidence": prod["alignment_confidence"],
            }

        per_app.append(
            {
                "package": pkg,
                "distinct_meaningful_categories": distinct_cats,
                "windows": windows,
            }
        )

    return per_app, by_window


def _category_gainers(
    per_app: list[dict[str, Any]], baseline_by_pkg: dict[str, int]
) -> list[dict[str, Any]]:
    gainers: list[dict[str, Any]] = []
    for row in per_app:
        pkg = row["package"]
        baseline_cat = baseline_by_pkg.get(pkg)
        engineoff_cat = row["distinct_meaningful_categories"]
        if baseline_cat is None or engineoff_cat is None:
            continue
        if engineoff_cat > baseline_cat:
            focus: dict[str, Any] = {
                "package": pkg,
                "baseline_categories": baseline_cat,
                "engineoff_categories": engineoff_cat,
                "category_delta": engineoff_cat - baseline_cat,
            }
            for wkey, wval in row["windows"].items():
                focus[f"w{wkey}_goals_completed"] = wval["goals_completed"]
                focus[f"w{wkey}_productive_completed"] = wval["productive_completed_goals"]
                focus[f"w{wkey}_productive_rate"] = wval["productive_rate_per_goal"]
            gainers.append(focus)
    return gainers


def _decide_finding(
    gainers: list[dict[str, Any]],
    by_window: dict[str, dict[str, Any]],
    windows_ms: list[int],
) -> dict[str, Any]:
    w4 = str(windows_ms[0])
    w10 = str(windows_ms[-1])
    w8 = str(windows_ms[-2]) if len(windows_ms) >= 2 else w10

    gainer_w4_rates: list[float] = []
    gainer_w10_rates: list[float] = []
    gainer_w4_productive_counts = 0
    gainer_w10_productive_counts = 0

    for g in gainers:
        r4 = g.get(f"w{w4}_productive_rate")
        r10 = g.get(f"w{w10}_productive_rate")
        pc4 = g.get(f"w{w4}_productive_completed") or 0
        pc10 = g.get(f"w{w10}_productive_completed") or 0
        gainer_w4_productive_counts += int(pc4)
        gainer_w10_productive_counts += int(pc10)
        if r4 is not None:
            gainer_w4_rates.append(float(r4))
        if r10 is not None:
            gainer_w10_rates.append(float(r10))

    med_w4 = by_window[w4]["median_productive_rate_per_goal"]
    med_w10 = by_window[w10]["median_productive_rate_per_goal"]
    med_delta = None
    if med_w4 is not None and med_w10 is not None:
        med_delta = med_w10 - med_w4

    gainer_rate_rise = False
    for g in gainers:
        r4 = g.get(f"w{w4}_productive_rate")
        r10 = g.get(f"w{w10}_productive_rate")
        pc4 = g.get(f"w{w4}_productive_completed") or 0
        pc10 = g.get(f"w{w10}_productive_completed") or 0
        low_or_null_4 = r4 is None or r4 < 0.2
        non_trivial_10 = r10 is not None and r10 >= 0.25
        count_rise = pc10 > pc4
        if low_or_null_4 and (non_trivial_10 or count_rise):
            gainer_rate_rise = True
            break

    under_crediting = (
        gainer_rate_rise
        or (med_delta is not None and med_delta >= MATERIAL_RATE_DELTA)
        or (gainer_w10_productive_counts > gainer_w4_productive_counts)
    )

    # Plateau: median rate change from w8→w10 small
    med_w8 = by_window.get(w8, {}).get("median_productive_rate_per_goal")
    plateau_at_ms: int | str | None = None
    if med_w8 is not None and med_w10 is not None:
        if abs(med_w10 - med_w8) <= PLATEAU_DELTA:
            plateau_at_ms = int(w8)
    elif med_w4 is not None and med_w10 is not None and abs(med_w10 - med_w4) <= PLATEAU_DELTA:
        plateau_at_ms = int(w4)

    if under_crediting and gainer_w10_productive_counts > gainer_w4_productive_counts:
        finding = "UNDER-CREDITING"
        recommended = f"±{plateau_at_ms // 1000}s" if plateau_at_ms else f"±{int(w10) // 1000}s"
    elif gainer_w10_productive_counts == gainer_w4_productive_counts and (
        med_delta is None or abs(med_delta) < MATERIAL_RATE_DELTA
    ):
        finding = "DECOUPLED"
        recommended = "metric not reliable, use category signal"
    elif under_crediting:
        finding = "UNDER-CREDITING"
        recommended = f"±{int(w10) // 1000}s"
    else:
        finding = "DECOUPLED"
        recommended = "metric not reliable, use category signal"

    return {
        "finding": finding,
        "recommended_standard_window": recommended,
        "plateau_at_ms": plateau_at_ms,
        "evidence": {
            "gainer_productive_completed_w4": gainer_w4_productive_counts,
            "gainer_productive_completed_w10": gainer_w10_productive_counts,
            "median_productive_rate_w4": med_w4,
            "median_productive_rate_w10": med_w10,
            "median_productive_rate_delta_w4_to_w10": med_delta,
            "n_non_null_w4": by_window[w4]["n_non_null"],
            "n_non_null_w10": by_window[w10]["n_non_null"],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", default="logs/exp_engineoff_v6/dataset_index.csv")
    parser.add_argument("--baseline", default="experiment/baseline_engineoff.json")
    parser.add_argument("--engineoff-paired", default="experiment/engineoff_result.json")
    parser.add_argument("--out", default="experiment/window_sweep_result.json")
    parser.add_argument(
        "--windows-ms",
        default=",".join(str(w) for w in DEFAULT_WINDOWS_MS),
        help="Comma-separated ±window widths in ms",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    windows_ms = [int(x.strip()) for x in args.windows_ms.split(",") if x.strip()]

    baseline = json.loads((root / args.baseline).read_text(encoding="utf-8"))
    baseline_by_pkg = {
        row["package"]: row.get("distinct_meaningful_categories")
        for row in baseline.get("per_app") or []
    }

    per_app, by_window = _score_index(root / args.index, windows_ms)
    gainers = _category_gainers(per_app, baseline_by_pkg)
    decision = _decide_finding(gainers, by_window, windows_ms)

    # 12-app table: productive_rate(a) per window
    rate_table: list[dict[str, Any]] = []
    for row in per_app:
        entry: dict[str, Any] = {"package": row["package"]}
        for window_ms in windows_ms:
            wkey = str(window_ms)
            rate = row["windows"][wkey]["productive_rate_per_goal"]
            entry[f"pm{window_ms // 1000}s"] = rate
        rate_table.append(entry)

    result = {
        "experiment": "engine_off_alignment_window_sweep",
        "index": str(root / args.index),
        "windows_ms": windows_ms,
        "method": "per_session_offset_first_meaningful_frida_minus_first_agent_action_ts",
        "numerator": "satisfied_advance_goal_events_with_meaningful_frida_in_window",
        "denominator_a": "goals_completed",
        "per_window_aggregates": by_window,
        "productive_rate_table": rate_table,
        "category_gainers": gainers,
        "decision": decision,
    }

    out_path = root / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"wrote {out_path}")
    print(f"finding: {decision['finding']}")


if __name__ == "__main__":
    main()
