#!/usr/bin/env python3
"""Validate faithfulness judge against human-labeled sessions."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluate_faithfulness import JUDGE_VERSION, evaluate_session

LABELS = ("FAITHFUL", "PARTIAL", "FAILED")


def _collapsed(label: str) -> str:
    return "keep" if label == "FAITHFUL" else "discard"


def _confusion(
    rows: list[dict[str, str]], key_h: str, key_j: str, labels: tuple[str, ...] = LABELS
) -> dict[str, dict[str, int]]:
    matrix: dict[str, dict[str, int]] = {h: {j: 0 for j in labels} for h in labels}
    for row in rows:
        matrix[row[key_h]][row[key_j]] += 1
    return matrix


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--label-sheet",
        default="experiment/faithfulness_human_label_sheet.csv",
    )
    parser.add_argument(
        "--out-json",
        default="experiment/faithfulness_human_validation.json",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    sheet_path = root / args.label_sheet
    rows_in = list(csv.DictReader(sheet_path.open(encoding="utf-8")))
    index = {
        r["package_name"]: r
        for r in csv.DictReader((root / "logs/bulk_llm_benign_v6/dataset_index.csv").open(encoding="utf-8"))
    }

    per_session: list[dict[str, Any]] = []
    for row in rows_in:
        human = str(row.get("human_label") or "").strip().upper()
        if human not in LABELS:
            continue
        pkg = row["package"]
        idx_row = index.get(pkg) or {}
        base = Path(row["artifact_path"])
        meta_path = Path(idx_row["metadata_path"]) if idx_row.get("metadata_path") else None
        if not meta_path or not meta_path.exists():
            meta_path = base / f"{pkg}_dynamic_metadata.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        result = evaluate_session(base, pkg, meta)
        judge = result["faithfulness"]
        per_session.append(
            {
                "package": pkg,
                "stratum": row.get("stratum", ""),
                "human": human,
                "judge": judge,
                "match": human == judge,
                "collapsed_match": _collapsed(human) == _collapsed(judge),
                "human_collapsed": _collapsed(human),
                "judge_collapsed": _collapsed(judge),
                "deciding_factor": result.get("deciding_factor"),
                "sim_status": result.get("session_meta", {}).get("llm_simulation_status"),
                "sim_override": result.get("session_meta", {}).get("sim_override"),
                "explore_metrics": result.get("session_meta", {}).get("explore_metrics"),
                "criteria": {
                    k: v
                    for k, v in result.items()
                    if k.startswith("C") and isinstance(v, dict)
                },
            }
        )

    n = len(per_session)
    exact = sum(1 for r in per_session if r["match"])
    collapsed = sum(1 for r in per_session if r["collapsed_match"])
    disagreements = [r for r in per_session if not r["match"]]

    out = {
        "experiment": "faithfulness_human_validation",
        "judge_version": JUDGE_VERSION,
        "sessions": n,
        "exact_agreement": exact,
        "exact_agreement_pct": round(100 * exact / n, 1) if n else 0.0,
        "collapsed_agreement": collapsed,
        "collapsed_agreement_pct": round(100 * collapsed / n, 1) if n else 0.0,
        "pass_threshold_pct": 90.0,
        "passes_threshold": (100 * collapsed / n) >= 90.0 if n else False,
        "human_summary": dict(Counter(r["human"] for r in per_session)),
        "judge_summary": dict(Counter(r["judge"] for r in per_session)),
        "confusion_matrix_exact": _confusion(per_session, "human", "judge"),
        "confusion_matrix_collapsed": _confusion(
            [{"human": r["human_collapsed"], "judge": r["judge_collapsed"]} for r in per_session],
            "human",
            "judge",
            ("keep", "discard"),
        ),
        "disagreements": disagreements,
        "per_session": per_session,
    }

    out_path = root / args.out_json
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    print(f"judge_version: {JUDGE_VERSION}")
    print(f"sessions: {n}")
    print(f"exact agreement: {exact}/{n} ({out['exact_agreement_pct']}%)")
    print(f"collapsed agreement: {collapsed}/{n} ({out['collapsed_agreement_pct']}%)")
    print(f"passes 90% threshold: {out['passes_threshold']}")
    if disagreements:
        print("\nDisagreements:")
        for d in disagreements:
            print(
                f"  {d['package']}: human={d['human']} judge={d['judge']} "
                f"(collapsed {'OK' if d['collapsed_match'] else 'MISS'}) — {d['deciding_factor']}"
            )
    print(f"\nwrote {out_path}")


if __name__ == "__main__":
    main()
