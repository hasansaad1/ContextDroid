#!/usr/bin/env python3
"""Engine-off controlled experiment: baseline, comparison, aggregates."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from pathlib import Path
from typing import Any

LOW_SIGNAL = {"reflection", "lifecycle", "unknown"}
REFLECTION_API = "Method.invoke"


def _pearson(xs: list[float], ys: list[float]) -> float | None:
    if len(xs) < 2 or len(xs) != len(ys):
        return None
    mx = sum(xs) / len(xs)
    my = sum(ys) / len(ys)
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den_x = math.sqrt(sum((x - mx) ** 2 for x in xs))
    den_y = math.sqrt(sum((y - my) ** 2 for y in ys))
    if den_x == 0 or den_y == 0:
        return None
    return num / (den_x * den_y)


def _median(vals: list[float]) -> float | None:
    return float(statistics.median(vals)) if vals else None


def _method_invoke_share(frida_jsonl: Path) -> float | None:
    if not frida_jsonl.exists():
        return None
    total = 0
    invoke = 0
    for line in frida_jsonl.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type", "event") != "event":
            continue
        total += 1
        if obj.get("api") == REFLECTION_API or obj.get("category") == "reflection":
            invoke += 1
    if total == 0:
        return None
    return invoke / total


def _load_index_by_package(index_csv: Path) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    if not index_csv.exists():
        return out
    for row in csv.DictReader(index_csv.open(encoding="utf-8")):
        pkg = row.get("package_name") or ""
        if pkg:
            out[pkg] = row
    return out


def _apk_path_for_package(apk_root: Path, index_row: dict[str, str] | None, pkg: str) -> str | None:
    if index_row:
        src = index_row.get("source") or ""
        fn = index_row.get("apk_filename") or ""
        if src and fn:
            p = Path(src) / fn
            if p.exists():
                return str(p.resolve())
    # fallback: search benign tree
    matches = list(apk_root.rglob(f"*{pkg}*.apk"))
    if not matches:
        matches = [p for p in apk_root.rglob("*.apk") if pkg in p.name]
    if matches:
        return str(matches[0].resolve())
    return None


def _session_metrics_from_eval(per_session: dict[str, Any]) -> dict[str, Any]:
    pr = per_session.get("productive_rate")
    # legacy name alias if present
    pcr = per_session.get("productive_completion_rate", pr)
    return {
        "data_quality_status": per_session.get("data_quality_status"),
        "distinct_meaningful_categories": per_session.get("distinct_meaningful_categories"),
        "goals_completed": per_session.get("goals_completed_primary"),
        "plan_coverage": per_session.get("plan_coverage") or per_session.get("completion_rate"),
        "productive_completion_rate": pcr,
        "productive_rate": pr,
        "total_actions": per_session.get("total_actions"),
        "llm_simulation_status": per_session.get("sim_status"),
        "elapsed_sec": per_session.get("elapsed_sec"),
    }


def _aggregates(rows: list[dict[str, Any]]) -> dict[str, Any]:
    cats = [float(r["distinct_meaningful_categories"]) for r in rows if r.get("distinct_meaningful_categories") is not None]
    pcr = [float(r["productive_completion_rate"]) for r in rows if r.get("productive_completion_rate") is not None]
    gc = [float(r["goals_completed"] or 0) for r in rows]
    ys = [float(r["distinct_meaningful_categories"] or 0) for r in rows]
    wall = [float(r["elapsed_sec"]) for r in rows if r.get("elapsed_sec") is not None]
    return {
        "n": len(rows),
        "median_distinct_meaningful_categories": _median(cats),
        "median_productive_completion_rate": _median(pcr),
        "corr_goals_completed_categories": _pearson(gc, ys),
        "median_elapsed_sec": _median(wall),
    }


def select_test_set(scenario_json: Path, *, n: int = 12) -> list[str]:
    data = json.loads(scenario_json.read_text(encoding="utf-8"))
    rich: list[dict[str, Any]] = []
    for s in data.get("per_session") or []:
        if not s.get("has_plan"):
            continue
        pc = s.get("plan_coverage")
        if pc is None:
            pc = s.get("completion_rate")
        if pc is None:
            continue
        if float(pc) < 0.35 and int(s.get("total_actions") or 0) >= 60:
            rich.append(s)
    rich.sort(key=lambda x: -(int(x.get("total_actions") or 0)))
    priority = [
        "InfinityLoop1309.NewPipeEnhanced",
        "ac.mdiq.podcini.X",
        "ac.robinson.mediaphone",
        "app.fedilab.castlab",
        "app.fedilab.fediplan",
        "app.fedilab.mobilizon",
        "app.fedilab.nitterizeme",
    ]
    names = [s["package_name"] for s in rich]
    chosen: list[str] = []
    for p in priority:
        if p in names and p not in chosen:
            chosen.append(p)
    for s in rich:
        pkg = s["package_name"]
        if pkg not in chosen:
            chosen.append(pkg)
        if len(chosen) >= n:
            break
    return chosen[:n]


def build_baseline(
    *,
    packages: list[str],
    scenario_json: Path,
    index_csv: Path,
    apk_root: Path,
    out_path: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    data = json.loads(scenario_json.read_text(encoding="utf-8"))
    by_pkg = {s["package_name"]: s for s in data.get("per_session") or []}
    index = _load_index_by_package(index_csv)
    per_app: list[dict[str, Any]] = []
    apk_lines: list[str] = []
    for pkg in packages:
        s = by_pkg.get(pkg)
        if not s:
            raise SystemExit(f"package not in scenario eval: {pkg}")
        row = index.get(pkg)
        frida = Path(row["frida_log_path"]) if row and row.get("frida_log_path") else None
        meta_path = Path(row["metadata_path"]) if row and row.get("metadata_path") else None
        elapsed = None
        if meta_path and meta_path.exists():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            elapsed = meta.get("elapsed_sec")
        apk_path = _apk_path_for_package(apk_root, row, pkg)
        exists = bool(apk_path and Path(apk_path).exists())
        if exists:
            apk_lines.append(apk_path)
        metrics = _session_metrics_from_eval(s)
        metrics["method_invoke_share"] = _method_invoke_share(frida) if frida else None
        metrics["elapsed_sec"] = elapsed
        per_app.append(
            {
                "package": pkg,
                "apk_path": apk_path,
                "apk_exists": exists,
                **metrics,
            }
        )
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text("\n".join(apk_lines) + ("\n" if apk_lines else ""), encoding="utf-8")
    agg = _aggregates(per_app)
    report = {
        "experiment": "engine_off_diagnostic",
        "variable_changed": "CONTEXTDROID_LLM_EXECUTE_ENGINE_ONLY",
        "baseline_value": "1",
        "test_packages": packages,
        "per_app": per_app,
        "aggregates": agg,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def compare(
    *,
    baseline_path: Path,
    engineoff_scenario_json: Path,
    engineoff_index_csv: Path,
    out_path: Path,
) -> dict[str, Any]:
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    engine = json.loads(engineoff_scenario_json.read_text(encoding="utf-8"))
    by_pkg = {s["package_name"]: s for s in engine.get("per_session") or []}
    index = _load_index_by_package(engineoff_index_csv)
    paired: list[dict[str, Any]] = []
    for b in baseline["per_app"]:
        pkg = b["package"]
        e = by_pkg.get(pkg, {})
        row = index.get(pkg, {})
        frida = Path(row["frida_log_path"]) if row.get("frida_log_path") else None
        meta_path = Path(row["metadata_path"]) if row.get("metadata_path") else None
        elapsed = None
        sim = None
        if meta_path and meta_path.exists():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            elapsed = meta.get("elapsed_sec")
            sim = meta.get("llm_simulation_status")
        em = _session_metrics_from_eval(e) if e else {}
        em["method_invoke_share"] = _method_invoke_share(frida) if frida else None
        em["elapsed_sec"] = elapsed
        em["llm_simulation_status"] = sim or em.get("llm_simulation_status")
        paired.append(
            {
                "package": pkg,
                "baseline_categories": b.get("distinct_meaningful_categories"),
                "engineoff_categories": em.get("distinct_meaningful_categories"),
                "baseline_productive_rate": b.get("productive_completion_rate"),
                "engineoff_productive_rate": em.get("productive_completion_rate"),
                "baseline_goals_completed": b.get("goals_completed"),
                "engineoff_goals_completed": em.get("goals_completed"),
                "baseline_total_actions": b.get("total_actions"),
                "engineoff_total_actions": em.get("total_actions"),
                "baseline_elapsed_sec": b.get("elapsed_sec"),
                "engineoff_elapsed_sec": em.get("elapsed_sec"),
                "engineoff_sim_status": em.get("llm_simulation_status"),
            }
        )

    b_agg = baseline["aggregates"]
    e_rows = []
    for p in paired:
        e_rows.append(
            {
                "distinct_meaningful_categories": p["engineoff_categories"],
                "productive_completion_rate": p["engineoff_productive_rate"],
                "goals_completed": p["engineoff_goals_completed"],
                "elapsed_sec": p["engineoff_elapsed_sec"],
            }
        )
    e_agg = _aggregates(e_rows)

    def delta(a: float | None, b: float | None) -> float | None:
        if a is None or b is None:
            return None
        return b - a

    improved = regressed = unchanged = 0
    for p in paired:
        bpr = p["baseline_productive_rate"]
        epr = p["engineoff_productive_rate"]
        if bpr is None or epr is None:
            continue
        if epr > bpr + 0.05:
            improved += 1
        elif epr < bpr - 0.05:
            regressed += 1
        else:
            unchanged += 1

    failure_modes: dict[str, int] = {}
    for p in paired:
        st = str(p.get("engineoff_sim_status") or "")
        if st:
            failure_modes[st] = failure_modes.get(st, 0) + 1

    med_b = b_agg.get("median_productive_completion_rate")
    med_e = e_agg.get("median_productive_completion_rate")
    moved = med_b is not None and med_e is not None and (med_e - med_b) >= 0.10
    verdict = "MOVED" if moved else "FLAT"

    result = {
        "paired": paired,
        "aggregates": {
            "baseline": b_agg,
            "engineoff": e_agg,
            "delta_median_distinct_meaningful_categories": delta(
                b_agg.get("median_distinct_meaningful_categories"),
                e_agg.get("median_distinct_meaningful_categories"),
            ),
            "delta_median_productive_completion_rate": delta(
                b_agg.get("median_productive_completion_rate"),
                e_agg.get("median_productive_completion_rate"),
            ),
            "corr_goals_completed_categories_baseline": b_agg.get("corr_goals_completed_categories"),
            "corr_goals_completed_categories_engineoff": e_agg.get("corr_goals_completed_categories"),
        },
        "productive_rate_shift_counts": {
            "improved": improved,
            "unchanged": unchanged,
            "regressed": regressed,
        },
        "operational": {
            "median_elapsed_sec_baseline": b_agg.get("median_elapsed_sec"),
            "median_elapsed_sec_engineoff": e_agg.get("median_elapsed_sec"),
            "engineoff_sim_status_counts": failure_modes,
        },
        "verdict": verdict,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    p0 = sub.add_parser("baseline")
    p0.add_argument("--scenario", default="logs/bulk_llm_benign_v6/scenario_evaluation.json")
    p0.add_argument("--index", default="logs/bulk_llm_benign_v6/dataset_index.csv")
    p0.add_argument("--apk-root", default="data/apks/benign")
    p0.add_argument("--out", default="experiment/baseline_engineoff.json")
    p0.add_argument("--manifest", default="experiment/engineoff_test_manifest.txt")

    p1 = sub.add_parser("compare")
    p1.add_argument("--baseline", default="experiment/baseline_engineoff.json")
    p1.add_argument("--engineoff-scenario", default="logs/exp_engineoff_v6/scenario_evaluation.json")
    p1.add_argument("--engineoff-index", default="logs/exp_engineoff_v6/dataset_index.csv")
    p1.add_argument("--out", default="experiment/engineoff_result.json")

    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.cmd == "baseline":
        pkgs = select_test_set(root / args.scenario)
        build_baseline(
            packages=pkgs,
            scenario_json=root / args.scenario,
            index_csv=root / args.index,
            apk_root=root / args.apk_root,
            out_path=root / args.out,
            manifest_path=root / args.manifest,
        )
        print(json.dumps({"test_packages": pkgs, "out": args.out}, indent=2))
    elif args.cmd == "compare":
        compare(
            baseline_path=root / args.baseline,
            engineoff_scenario_json=root / args.engineoff_scenario,
            engineoff_index_csv=root / args.engineoff_index,
            out_path=root / args.out,
        )
        print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
