#!/usr/bin/env python3
"""Append Step 3.5 sections to REPORT.md — numbers only."""

from __future__ import annotations

import json
from pathlib import Path

from paths import OUT_DIR


def load(name: str):
    p = OUT_DIR / name
    if not p.is_file():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def main() -> None:
    report = OUT_DIR / "REPORT.md"
    prev = report.read_text(encoding="utf-8") if report.is_file() else ""
    # strip prior 3.5 append if re-run
    marker = "\n## Step 3.5 — provenance and emptiness\n"
    if marker in prev:
        prev = prev.split(marker)[0].rstrip() + "\n"

    lines: list[str] = [marker.lstrip("\n")]
    lines.append("")
    lines.append("### Format decision (accepted / not accepted)")
    lines.append("")
    lines.append("- Accepted: `+through reflection` (counted as reflection_tag, not dropped)")
    lines.append("- Accepted: Jimple-quoted / non-ASCII identifiers in `<sig> -> <sig>` call lines")
    lines.append("- Accepted: ICC multi-line blocks `[ Intent sent ]` and `[ Intent received ]`")
    lines.append("- Not accepted: non-allowlisted lines → explicit drop with per-file counts")
    lines.append("")

    e = load("step3_5b_emptiness.json") or {}
    lines.append("### Allowlist aggregate dropped-line counts")
    lines.append("")
    if e:
        agg = e.get("aggregate_line_counts", {})
        lines.append("| class | total | call | reflection_tag | icc | header | **dropped** |")
        lines.append("|---|---:|---:|---:|---:|---:|---:|")
        for cls in ("benign", "malware"):
            lines.append(
                f"| {cls} | {agg.get('total',{}).get(cls)} | {agg.get('call',{}).get(cls)} | "
                f"{agg.get('reflection_tag',{}).get(cls)} | {agg.get('icc',{}).get(cls)} | "
                f"{agg.get('header',{}).get(cls)} | **{agg.get('dropped',{}).get(cls)}** |"
            )
        lines.append("")
        lines.append("Per-file dropped counts: `step3_5_per_file_allowlist.csv`")
        lines.append("")

    # 3.5a
    a = load("step3_5a_provenance.json") or {}
    lines.append("## Step 3.5a — AndroZoo provenance (hashes, not labels)")
    lines.append("")
    if a:
        lines.append(f"- index_sources: `{a.get('index_sources')}`")
        lines.append(f"- n_hashes: {a.get('n_hashes')}")
        lines.append(f"- n_found: {a.get('n_found')}")
        lines.append(f"- n_absent: `{a.get('n_absent')}`")
        lines.append(f"- absent_note: {a.get('absent_note')}")
        lines.append(f"- overlap_hashes (both classes): `{a.get('overlap_hashes')}`")
        lines.append("")
        lines.append("### Year distribution (dex_date year)")
        lines.append("")
        yd = a.get("year_distribution", {})
        years = sorted({y for c in yd.values() for y in c})
        lines.append("| year | benign | malware |")
        lines.append("|---|---:|---:|")
        for y in years:
            lines.append(f"| {y} | {yd.get('benign',{}).get(y,0)} | {yd.get('malware',{}).get(y,0)} |")
        lines.append("")
        lines.append("### vt_detection distribution")
        lines.append("")
        for cls in ("benign", "malware"):
            lines.append(f"#### {cls}")
            lines.append("")
            lines.append("| vt_detection | count |")
            lines.append("|---|---:|")
            for k, v in (a.get("vt_detection_distribution", {}).get(cls) or {}).items():
                lines.append(f"| {k} | {v} |")
            lines.append("")
        viol = a.get("paper_criteria_violations", {})
        lines.append("### Paper criteria contradiction counts")
        lines.append("")
        lines.append(f"- benign vt_detection > 0: **{viol.get('benign_vt_detection_gt_0_count')}**")
        lines.append(f"- malware vt_detection < 10: **{viol.get('malware_vt_detection_lt_10_count')}**")
        lines.append("")
        g = a.get("year_overlap_gate", {})
        lines.append("### Year-overlap GATE")
        lines.append("")
        lines.append(f"- benign_years: `{g.get('benign_years')}`")
        lines.append(f"- malware_years: `{g.get('malware_years')}`")
        lines.append(f"- intersection_years: `{g.get('intersection_years')}`")
        lines.append(f"- benign_frac_in_intersection: {g.get('benign_frac_in_intersection')}")
        lines.append(f"- malware_frac_in_intersection: {g.get('malware_frac_in_intersection')}")
        lines.append(f"- threshold_frac: {g.get('threshold_frac')}")
        lines.append(f"- **pass: `{g.get('pass')}`**")
        lines.append("")
        gate = load("step3_5_GATE.json") or {}
        lines.append(f"- STOP (no graph construction): **`{gate.get('stop')}`**")
        lines.append("")

    # 3.5b
    lines.append("## Step 3.5b — empty traces")
    lines.append("")
    if e:
        lines.append(f"- benign_zero_call_count: **{e.get('benign_zero_call_count')}**")
        lines.append(f"- malware_zero_call_count: **{e.get('malware_zero_call_count')}**")
        lines.append(f"- benign_nonzero_call_count: {e.get('benign_nonzero_call_count')}")
        lines.append(f"- malware_nonzero_call_count: {e.get('malware_nonzero_call_count')}")
        lines.append("")
        for key in ("malware_empty", "malware_nonempty", "benign_empty", "benign_nonempty"):
            d = e.get(key) or {}
            lines.append(f"### {key}")
            lines.append("")
            lines.append(f"- n: {d.get('n')}")
            lines.append(f"- file_size_bytes: `{d.get('file_size_bytes')}`")
            lines.append(f"- n_total_lines: `{d.get('n_total_lines')}`")
            lines.append(f"- n_dropped_lines: `{d.get('n_dropped_lines')}`")
            lines.append(f"- n_header_lines: `{d.get('n_header_lines')}`")
            lines.append(
                f"- n_with_any_droidfax_marker_call_icc_or_reflection: "
                f"{d.get('n_with_any_droidfax_marker_call_icc_or_reflection')}"
            )
            lines.append(f"- n_header_only: {d.get('n_header_only')}")
            lines.append(f"- n_dropped_pollution_only: {d.get('n_dropped_pollution_only')}")
            lines.append(f"- n_header_plus_dropped_no_calls: {d.get('n_header_plus_dropped_no_calls')}")
            lines.append(f"- n_truly_empty_or_whitespace_only: {d.get('n_truly_empty_or_whitespace_only')}")
            lines.append("")
    ej = load("step3_5b_emptiness_by_year_vt.json") or {}
    if ej:
        lines.append("### Empty vs non-empty year / vt (joined)")
        lines.append("")
        for k, d in ej.items():
            lines.append(f"#### {k}")
            lines.append("")
            lines.append(f"- n: {d.get('n')}")
            lines.append(f"- year_distribution: `{d.get('year_distribution')}`")
            lines.append(f"- vt_detection_distribution: `{d.get('vt_detection_distribution')}`")
            lines.append(f"- file_size_bytes_median: {d.get('file_size_bytes_median')}")
            lines.append("")

    # 3.5c
    c = load("step3_5c_archive_inventory.json") or {}
    lines.append("## Step 3.5c — 2017/2018 archive inventory")
    lines.append("")
    if c:
        lines.append("| archive | size_bytes | md5_match | top_level / dir_labels | n_apk_logcat | n_zero_call | n_nonzero_call |")
        lines.append("|---|---:|---|---|---:|---:|---:|")
        md5 = c.get("md5") or load("step3_5c_md5.json") or {}
        for name in (
            "trace-benign-2017.tar.gz",
            "trace-malware-2017.tar.gz",
            "trace-benign-2018.tar.gz",
            "trace-malware-2018.tar.gz",
        ):
            d = c.get(name) or {}
            m = md5.get(name) or {}
            lines.append(
                f"| `{name}` | {d.get('size_bytes') or m.get('size')} | {m.get('match')} | "
                f"`{d.get('top_level')}` / `{d.get('dir_labels')}` | "
                f"{d.get('n_apk_logcat')} | {d.get('n_zero_call')} | {d.get('n_nonzero_call')} |"
            )
        y19 = c.get("2019_already_extracted_comparison") or {}
        lines.append("")
        lines.append("### 2019 comparison (already extracted)")
        lines.append("")
        lines.append(f"- benign_n: {y19.get('benign_n')}, zero_call: {y19.get('benign_zero_call')}")
        lines.append(f"- malware_n: {y19.get('malware_n')}, zero_call: {y19.get('malware_zero_call')}")
        lines.append(f"- dir_labels: `{y19.get('dir_labels')}`")
        lines.append("")
    else:
        lines.append("- pending / incomplete (see step3_5c_run.log)")
        lines.append("")

    # 3.5d
    d8 = load("step3_5d_delta_continuous.json") or {}
    lines.append("## Step 3.5d — Step 8 denominator + continuous δ-retention")
    lines.append("")
    if d8:
        et = d8.get("edge_instance_totals", {})
        lines.append("### Edge-instance totals (v2)")
        lines.append("")
        lines.append(f"- total_edge_instances_k_and_delta: **{et.get('total_edge_instances_k_and_delta')}**")
        lines.append(f"- total_edge_instances_k_only: **{et.get('total_edge_instances_k_only')}**")
        lines.append(f"- aggregate_sym_diff_edge_instances: **{et.get('aggregate_sym_diff_edge_instances')}**")
        lines.append(
            f"- sym_diff_fraction_of_k_delta: **{et.get('sym_diff_fraction_of_k_delta')}** "
            f"(297 / {et.get('total_edge_instances_k_and_delta')})"
        )
        lines.append(f"- sym_diff_fraction_of_k_only: {et.get('sym_diff_fraction_of_k_only')}")
        lines.append(f"- aggregate_intersection_edge_instances: {et.get('aggregate_intersection_edge_instances')}")
        lines.append("")
        o = d8.get("overall_delta_retention", {})
        lines.append("### Overall δ-retention")
        lines.append("")
        lines.append(f"- k_candidates: {o.get('k_candidates')}")
        lines.append(f"- delta_retained: {o.get('delta_retained')}")
        lines.append(f"- delta_retention_rate: {o.get('delta_retention_rate')}")
        lines.append("")
        fit = d8.get("log_fit", {})
        lines.append("### Fitted curve: retention ≈ a + b·ln(n_events)")
        lines.append("")
        lines.append(f"- a: {fit.get('a')}")
        lines.append(f"- b: {fit.get('b')}")
        lines.append(f"- r2: {fit.get('r2')}")
        lines.append(f"- n_points: {fit.get('n')}")
        lines.append("")
        fr = d8.get("fitted_retention_clipped_0_1") or d8.get("fitted_retention") or {}
        fu = d8.get("fitted_retention_unclipped") or {}
        lines.append("### Fitted retention at target event counts")
        lines.append("")
        lines.append("| n_events | fitted (clipped [0,1]) | fitted (unclipped) |")
        lines.append("|---:|---:|---:|")
        lines.append(f"| 5000 | {fr.get('at_5k')} | {fu.get('at_5k')} |")
        lines.append(f"| 10000 | {fr.get('at_10k')} | {fu.get('at_10k')} |")
        lines.append(f"| 50000 | {fr.get('at_50k')} | {fu.get('at_50k')} |")
        lines.append("")
        lines.append("### Decile bins by n_events")
        lines.append("")
        lines.append("| bin | n_sessions | n_events_min | n_events_max | k_candidates | pooled_δ_retention |")
        lines.append("|---:|---:|---:|---:|---:|---:|")
        for b in d8.get("decile_bins_by_n_events") or []:
            lines.append(
                f"| {b['bin']} | {b['n_sessions']} | {b['n_events_min']} | {b['n_events_max']} | "
                f"{b['k_candidates']} | {b['delta_retention_rate_pooled']} |"
            )
        lines.append("")
        lines.append("- scatter points: `step3_5d_scatter.json`")
        lines.append("- scatter+fit plot: `step3_5d_scatter.svg`")
        lines.append("")

    lines.append("## Step 3.5 artifacts")
    lines.append("")
    for p in sorted(OUT_DIR.glob("step3_5*")):
        lines.append(f"- `{p.name}` ({p.stat().st_size} bytes)")
    lines.append("")

    report.write_text(prev + "\n".join(lines) + "\n", encoding="utf-8")
    print("appended Step 3.5 to", report)


if __name__ == "__main__":
    main()
