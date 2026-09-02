#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path
from statistics import mean


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a thesis-friendly comparison report from Phase 3 metrics.")
    parser.add_argument(
        "--metrics-dir",
        default="logs/comparison_metrics",
        help="Directory containing arm_summary.csv and app_union_summary.csv",
    )
    parser.add_argument(
        "--output",
        default="logs/comparison_metrics/final_comparison_report.md",
        help="Output markdown report path",
    )
    return parser.parse_args()


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Missing required file: {path}")
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _to_float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def main() -> None:
    args = parse_args()
    metrics_dir = Path(args.metrics_dir)
    arm_summary = _read_csv(metrics_dir / "arm_summary.csv")
    app_union = _read_csv(metrics_dir / "app_union_summary.csv")

    by_arm: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in arm_summary:
        arm = (row.get("arm") or "unknown").strip()
        by_arm[arm].append(row)

    llm_rows = by_arm.get("llm", [])
    monkey_rows = by_arm.get("monkey", [])

    llm_div = mean([_to_float(r.get("mean_sequence_diversity_trigram", "0")) for r in llm_rows]) if llm_rows else 0.0
    monkey_div = (
        mean([_to_float(r.get("mean_sequence_diversity_trigram", "0")) for r in monkey_rows]) if monkey_rows else 0.0
    )
    llm_cov = mean([_to_float(r.get("mean_coverage_ratio", "0")) for r in llm_rows]) if llm_rows else 0.0
    monkey_cov = mean([_to_float(r.get("mean_coverage_ratio", "0")) for r in monkey_rows]) if monkey_rows else 0.0

    llm_cons = [
        _to_float(r.get("consistency_jaccard", "0"))
        for r in llm_rows
        if (r.get("consistency_jaccard") or "").strip() != ""
    ]
    monkey_cons = [
        _to_float(r.get("consistency_jaccard", "0"))
        for r in monkey_rows
        if (r.get("consistency_jaccard") or "").strip() != ""
    ]
    llm_consistency = mean(llm_cons) if llm_cons else 0.0
    monkey_consistency = mean(monkey_cons) if monkey_cons else 0.0

    union_counts = [_to_float(r.get("union_unique_api_count_both_arms", "0")) for r in app_union]
    avg_union_surface = mean(union_counts) if union_counts else 0.0

    per_pkg: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    for row in arm_summary:
        pkg = (row.get("package_name") or "").strip()
        arm = (row.get("arm") or "unknown").strip()
        if pkg:
            per_pkg[pkg][arm] = row

    improved_diversity = 0
    improved_coverage = 0
    improved_consistency = 0
    comparable_pkgs = 0
    per_app_lines: list[str] = []
    for pkg in sorted(per_pkg.keys()):
        llm = per_pkg[pkg].get("llm")
        monkey = per_pkg[pkg].get("monkey")
        if not llm or not monkey:
            continue
        comparable_pkgs += 1
        llm_d = _to_float(llm.get("mean_sequence_diversity_trigram", "0"))
        mon_d = _to_float(monkey.get("mean_sequence_diversity_trigram", "0"))
        llm_c = _to_float(llm.get("mean_coverage_ratio", "0"))
        mon_c = _to_float(monkey.get("mean_coverage_ratio", "0"))
        llm_j = _to_float(llm.get("consistency_jaccard", "0"))
        mon_j = _to_float(monkey.get("consistency_jaccard", "0"))

        if llm_d > mon_d:
            improved_diversity += 1
        if llm_c > mon_c:
            improved_coverage += 1
        if llm_j > mon_j:
            improved_consistency += 1

        per_app_lines.append(
            f"- `{pkg}`: diversity LLM={llm_d:.3f} vs Monkey={mon_d:.3f}; "
            f"coverage LLM={llm_c:.3f} vs Monkey={mon_c:.3f}; "
            f"consistency LLM={llm_j:.3f} vs Monkey={mon_j:.3f}"
        )

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Final Comparison Report",
        "",
        "## Scope",
        f"- Source metrics directory: `{metrics_dir}`",
        f"- Apps in union summary: `{len(app_union)}`",
        f"- Comparable apps with both arms: `{comparable_pkgs}`",
        "",
        "## Overall Arm Averages",
        f"- Sequence diversity (trigrams): LLM=`{llm_div:.6f}` vs Monkey=`{monkey_div:.6f}`",
        f"- Coverage ratio: LLM=`{llm_cov:.6f}` vs Monkey=`{monkey_cov:.6f}`",
        f"- Consistency (Jaccard): LLM=`{llm_consistency:.6f}` vs Monkey=`{monkey_consistency:.6f}`",
        f"- Mean per-app union API surface (both arms): `{avg_union_surface:.3f}`",
        "",
        "## Headline Counts (LLM better than Monkey)",
        f"- Higher diversity on `{improved_diversity}/{comparable_pkgs}` comparable apps",
        f"- Higher coverage on `{improved_coverage}/{comparable_pkgs}` comparable apps",
        f"- Higher consistency on `{improved_consistency}/{comparable_pkgs}` comparable apps",
        "",
        "## Per-App Comparison",
    ]
    if per_app_lines:
        lines.extend(per_app_lines)
    else:
        lines.append("- No comparable per-app rows found.")
    lines.extend(
        [
            "",
            "## Reproducibility Notes",
            "- Metrics are computed from `dataset_index.csv` and per-session `*_frida.csv` outputs.",
            "- Sequence diversity uses API-name trigrams (`N=3`).",
            "- Coverage denominator is per-app union of unique APIs across both arms.",
            "- Consistency is within-arm pairwise Jaccard over session API sets.",
        ]
    )
    text = "\n".join(lines)
    output.write_text(text + "\n", encoding="utf-8")
    print(f"Wrote report: {output}")


if __name__ == "__main__":
    main()
