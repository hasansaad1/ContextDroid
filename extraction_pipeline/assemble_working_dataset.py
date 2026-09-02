#!/usr/bin/env python3
"""Assemble faithfulness working dataset: keep FAITHFUL+PARTIAL, drop known flailing."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluate_faithfulness import evaluate_session, _coverage_gap
from evaluate_scenario_level import _load_actions
from quality_rules import detect_suspect_flailing
from reflection_target_analysis import _after_metrics, _load_frida_events


def _meaningful_event_count(frida_jsonl: Path, package: str) -> int:
    events = _load_frida_events(frida_jsonl)
    if not events:
        return 0
    after = _after_metrics(events, package)
    # Non-framework meaningful + app/sensitive reflection kept.
    return int(after.get("meaningful_events", 0)) + int(after.get("bc_reflection_events", 0))


def _load_success_cohort(index_path: Path) -> list[dict[str, str]]:
    return [
        r
        for r in csv.DictReader(index_path.open(encoding="utf-8"))
        if r.get("status") == "success" and r.get("metadata_path")
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", default="logs/bulk_llm_benign_v6/dataset_index.csv")
    parser.add_argument("--out-csv", default="experiment/working_dataset.csv")
    parser.add_argument("--out-manifest", default="experiment/working_dataset_manifest.json")
    parser.add_argument(
        "--faithfulness-json",
        default="",
        help="Optional precomputed faithfulness JSON; if absent, judge is run inline (same code, no changes).",
    )
    parser.add_argument(
        "--skip-flailing-filter",
        action="store_true",
        help="Keep all FAITHFUL+PARTIAL sessions; do not apply SUSPECT_FLAILING removal.",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    index_path = root / args.index
    cohort = _load_success_cohort(index_path)

    judged: dict[str, dict[str, Any]] = {}
    if args.faithfulness_json:
        blob = json.loads((root / args.faithfulness_json).read_text(encoding="utf-8"))
        for row in blob.get("per_session") or []:
            sid = str(row.get("session_id") or "")
            if sid:
                judged[sid] = row

    keep_set: list[dict[str, Any]] = []
    all_verdicts: Counter[str] = Counter()

    for row in cohort:
        meta_path = Path(row["metadata_path"])
        if not meta_path.exists():
            continue
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        pkg = row["package_name"]
        base = meta_path.parent
        sid = str(meta.get("session_id") or row.get("session_id") or "")

        if sid in judged:
            faith = judged[sid]["faithfulness"]
            coverage = judged[sid].get("coverage_gap", "")
        else:
            ev = evaluate_session(base, pkg, meta)
            faith = ev["faithfulness"]
            plan_path = base / f"{pkg}_llm_ux_plan.json"
            plan = json.loads(plan_path.read_text(encoding="utf-8")) if plan_path.exists() else {}
            actions = _load_actions(base / f"{pkg}_llm_actions.jsonl")
            coverage = _coverage_gap(
                ev["app_inference"]["expected_use"], actions, plan, ev["C1_REACHED_REAL_SCREENS"]
            )
            judged[sid] = ev

        all_verdicts[faith] += 1
        if faith not in {"FAITHFUL", "PARTIAL"}:
            continue

        actions_path = base / f"{pkg}_llm_actions.jsonl"
        report_path = base / f"{pkg}_human_ux_report.json"
        frida_path = Path(str(meta.get("frida_log_path") or ""))
        actions = _load_actions(actions_path)
        report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else None

        keep_set.append(
            {
                "package": pkg,
                "session_id": sid,
                "faithfulness_verdict": faith,
                "artifact_dir": str(base),
                "frida_trace_path": str(frida_path) if frida_path.exists() else "",
                "agent_log_path": str(actions_path) if actions_path.exists() else "",
                "dynamic_metadata_path": str(meta_path),
                "meaningful_event_count": _meaningful_event_count(frida_path, pkg),
                "coverage_gap": coverage,
                "sim_status": str(meta.get("llm_simulation_status") or row.get("llm_simulation_status") or ""),
                "actions": actions,
                "report": report,
                "stratum": "",
            }
        )

    removed: list[dict[str, Any]] = []
    survivors: list[dict[str, Any]] = []

    for row in keep_set:
        if args.skip_flailing_filter:
            survivors.append(row)
            continue
        is_flail, evidence = detect_suspect_flailing(
            row["actions"],
            sim_status=row["sim_status"],
            report=row["report"],
        )
        if is_flail:
            removed.append(
                {
                    "package": row["package"],
                    "session_id": row["session_id"],
                    "faithfulness_verdict": row["faithfulness_verdict"],
                    "sim_status": row["sim_status"],
                    "artifact_dir": row["artifact_dir"],
                    "evidence": evidence,
                }
            )
        else:
            survivors.append(row)

    def per_app_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
        c = Counter(r["package"] for r in rows)
        return dict(sorted(c.items()))

    out_csv = root / args.out_csv
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "package",
        "session_id",
        "faithfulness_verdict",
        "artifact_dir",
        "frida_trace_path",
        "agent_log_path",
        "dynamic_metadata_path",
        "meaningful_event_count",
        "coverage_gap",
    ]
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in survivors:
            w.writerow({k: row[k] for k in fieldnames})

    manifest = {
        "dataset": "working_dataset",
        "source_pool": "logs/bulk_llm_benign_v6 success sessions (full v6 corpus incl. overnight)",
        "faithfulness_judge": "evaluate_faithfulness.py (75% collapsed human agreement; not re-validated here)",
        "step1_keep_set": {
            "verdicts": ["FAITHFUL", "PARTIAL"],
            "count": len(keep_set),
            "per_app": per_app_counts(keep_set),
            "verdict_breakdown_in_pool": dict(all_verdicts),
        },
        "step2_suspect_flailing_removed": {
            "count": len(removed),
            "sessions": removed,
            "skipped": bool(args.skip_flailing_filter),
        },
        "step3_survivors": {
            "count": len(survivors),
            "per_app": per_app_counts(survivors),
            "packages": len(per_app_counts(survivors)),
        },
        "summary": (
            (
                f"{len(per_app_counts(survivors))} apps, {len(survivors)} sessions "
                "(FAITHFUL+PARTIAL keep-set), curated by LLM-faithfulness (75% human-validated)."
            )
            if args.skip_flailing_filter
            else (
                f"{len(per_app_counts(survivors))} apps, {len(survivors)} faithful sessions, "
                "curated by LLM-faithfulness (75% human-validated), mechanical-flailing removed."
            )
        ),
        "outputs": {
            "working_dataset_csv": str(out_csv),
        },
    }

    out_manifest = root / args.out_manifest
    out_manifest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"pool success sessions judged: {sum(all_verdicts.values())}")
    print(f"verdicts: {dict(all_verdicts)}")
    print(f"keep-set (FAITHFUL+PARTIAL): {len(keep_set)}")
    print(f"SUSPECT_FLAILING removed: {len(removed)}")
    print(f"survivors: {len(survivors)} apps={len(per_app_counts(survivors))}")
    print(f"wrote {out_csv}")
    print(f"wrote {out_manifest}")


if __name__ == "__main__":
    main()
