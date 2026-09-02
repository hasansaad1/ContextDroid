#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import itertools
import re
from pathlib import Path
from statistics import mean
from typing import Iterable


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compute Phase 3 comparison metrics from dataset artifacts.")
    parser.add_argument("--index", default="logs/dataset_index.csv", help="Path to dataset_index.csv")
    parser.add_argument(
        "--output-dir",
        default="logs/comparison_metrics",
        help="Directory to write comparison metric CSV files",
    )
    return parser.parse_args()


def _read_api_sequence(frida_csv_path: Path) -> list[str]:
    if not frida_csv_path.exists():
        return []
    apis: list[str] = []
    with frida_csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            api = (row.get("api") or "").strip()
            if api:
                apis.append(api)
    return apis


def _api_trigrams(api_sequence: list[str]) -> set[tuple[str, str, str]]:
    if len(api_sequence) < 3:
        return set()
    return set(zip(api_sequence, api_sequence[1:], api_sequence[2:]))


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def _write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> None:
    args = parse_args()
    index_path = Path(args.index)
    if not index_path.exists():
        raise SystemExit(f"index not found: {index_path}")

    arm_pat = re.compile(r"/dynamic/(llm|monkey)/session_(\d+)/")
    rows: list[dict[str, str]] = []
    with index_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            arm = (row.get("arm") or "").strip()
            package_name = (row.get("package_name") or "").strip()
            frida_csv = (row.get("frida_csv_path") or "").strip()
            if (not arm or arm == "unknown") and frida_csv:
                m = arm_pat.search(frida_csv)
                if m:
                    arm = m.group(1)
            if arm not in {"llm", "monkey"}:
                continue
            if not package_name or not frida_csv:
                continue
            rows.append(row)

    session_metrics: list[dict[str, object]] = []
    by_package_rows: dict[str, list[dict[str, object]]] = {}
    by_package_arm_sets: dict[tuple[str, str], list[set[str]]] = {}

    for row in rows:
        package_name = (row.get("package_name") or "").strip()
        arm = (row.get("arm") or "unknown").strip()
        frida_csv_path = Path((row.get("frida_csv_path") or "").strip())
        api_sequence = _read_api_sequence(frida_csv_path)
        unique_apis = set(api_sequence)
        trigrams = _api_trigrams(api_sequence)

        metric_row = {
            "sample_id": row.get("sample_id", ""),
            "package_name": package_name,
            "arm": arm,
            "session_id": row.get("session_id", ""),
            "status": row.get("status", ""),
            "status_detail": row.get("status_detail", ""),
            "frida_csv_path": str(frida_csv_path),
            "unique_api_count": len(unique_apis),
            "sequence_diversity_trigram": len(trigrams),
            "coverage_ratio": 0.0,  # filled after union denominator is computed
        }
        session_metrics.append(metric_row)

        by_package_rows.setdefault(package_name, []).append(metric_row)
        by_package_arm_sets.setdefault((package_name, arm), []).append(unique_apis)

    app_union_summary: list[dict[str, object]] = []
    for package_name, metric_rows in by_package_rows.items():
        union_apis: set[str] = set()
        llm_sessions = 0
        monkey_sessions = 0
        for item in metric_rows:
            item_path = Path(str(item["frida_csv_path"]))
            apis = set(_read_api_sequence(item_path))
            union_apis |= apis
            if item["arm"] == "llm":
                llm_sessions += 1
            elif item["arm"] == "monkey":
                monkey_sessions += 1
        denom = len(union_apis)
        for item in metric_rows:
            item_path = Path(str(item["frida_csv_path"]))
            unique_session_apis = set(_read_api_sequence(item_path))
            item["coverage_ratio"] = (len(unique_session_apis) / denom) if denom > 0 else 0.0
        app_union_summary.append(
            {
                "package_name": package_name,
                "union_unique_api_count_both_arms": denom,
                "llm_session_count": llm_sessions,
                "monkey_session_count": monkey_sessions,
            }
        )

    arm_summary: list[dict[str, object]] = []
    for (package_name, arm), sets_list in by_package_arm_sets.items():
        session_rows = [r for r in by_package_rows.get(package_name, []) if r["arm"] == arm]
        trigram_values = [int(r["sequence_diversity_trigram"]) for r in session_rows]
        coverage_values = [float(r["coverage_ratio"]) for r in session_rows]

        consistency = ""
        if len(sets_list) >= 2:
            pair_scores = [_jaccard(a, b) for a, b in itertools.combinations(sets_list, 2)]
            consistency = f"{mean(pair_scores):.6f}"

        arm_summary.append(
            {
                "package_name": package_name,
                "arm": arm,
                "session_count": len(session_rows),
                "mean_sequence_diversity_trigram": f"{mean(trigram_values):.6f}" if trigram_values else "0.000000",
                "mean_coverage_ratio": f"{mean(coverage_values):.6f}" if coverage_values else "0.000000",
                "consistency_jaccard": consistency,
            }
        )

    output_dir = Path(args.output_dir)
    _write_csv(
        output_dir / "session_metrics.csv",
        [
            "sample_id",
            "package_name",
            "arm",
            "session_id",
            "status",
            "status_detail",
            "frida_csv_path",
            "unique_api_count",
            "sequence_diversity_trigram",
            "coverage_ratio",
        ],
        session_metrics,
    )
    _write_csv(
        output_dir / "arm_summary.csv",
        [
            "package_name",
            "arm",
            "session_count",
            "mean_sequence_diversity_trigram",
            "mean_coverage_ratio",
            "consistency_jaccard",
        ],
        arm_summary,
    )
    _write_csv(
        output_dir / "app_union_summary.csv",
        [
            "package_name",
            "union_unique_api_count_both_arms",
            "llm_session_count",
            "monkey_session_count",
        ],
        app_union_summary,
    )

    print(f"Wrote metrics to: {output_dir}")
    print(f"- session_metrics.csv ({len(session_metrics)} rows)")
    print(f"- arm_summary.csv ({len(arm_summary)} rows)")
    print(f"- app_union_summary.csv ({len(app_union_summary)} rows)")


if __name__ == "__main__":
    main()
