#!/usr/bin/env python3
"""Assemble REPORT.md from probe artifacts. Numbers/tables only."""

from __future__ import annotations

import json
from pathlib import Path

from paths import OUT_DIR, DATA_DIR


def load(name: str):
    p = OUT_DIR / name
    if not p.is_file():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def main() -> None:
    lines: list[str] = []
    lines.append("# AndroCT compatibility probe — REPORT")
    lines.append("")
    lines.append("Numbers and tables only. No recommendations.")
    lines.append("")

    # Step 1
    lines.append("## Step 1 — existing machinery")
    lines.append("")
    lines.append("| Item | file:symbol |")
    lines.append("|---|---|")
    lines.append(
        "| GRAPH_CATEGORY_UNIVERSE (22) | "
        "`adaptive-behavioral-graph-analysis/abrg/registry.py:GRAPH_CATEGORY_UNIVERSE` |"
    )
    lines.append(
        "| CATEGORY_UNIVERSE (25) | "
        "`adaptive-behavioral-graph-analysis/abrg/registry.py:CATEGORY_UNIVERSE` |"
    )
    lines.append(
        "| ContextDroid mirror CATEGORY_UNIVERSE | "
        "`extraction_pipeline/evaluate_corpus.py:CATEGORY_UNIVERSE` |"
    )
    lines.append(
        "| ContextDroid derived GRAPH_CATEGORY_UNIVERSE | "
        "`experiments/datasets/curate_v2_reference.py:GRAPH_CATEGORY_UNIVERSE` |"
    )
    lines.append(
        "| API/callee → category mapper | "
        "`adaptive-behavioral-graph-analysis/abrg/api_category_map.py:categorize_callee` |"
    )
    lines.append(
        "| Edge formation k=5 / δ=5s | "
        "`adaptive-behavioral-graph-analysis/abrg/graph.py:update_graph` "
        "(defaults `K_BURST`/`DELTA_SEC` from `abrg/config.py`) |"
    )
    lines.append(
        "| Node feature builder (static+dynamic) | "
        "`adaptive-behavioral-graph-analysis/abrg/features.py:graph_to_tensors` |"
    )
    lines.append("")
    lines.append("### Mapper signature (1b)")
    lines.append("")
    lines.append("```python")
    lines.append("def categorize_callee(class_name: str, method_name: str) -> set[str]:")
    lines.append("```")
    lines.append("")
    lines.append(
        "- Input: `class_name` smali (`Landroid/foo/Bar;`) or dotted (`android.foo.Bar`); "
        "`method_name` e.g. `sendTextMessage`, `<init>`."
    )
    lines.append("- Output: `set[str]` of categories (possibly empty).")
    lines.append("- Table: `HOOK_API_TO_CATEGORY` in same module (`SimpleClass.method` labels).")
    lines.append("")

    # Step 2
    lines.append("## Step 2 — acquire data")
    lines.append("")
    rec = None
    zp = DATA_DIR / "zenodo_record.json"
    if zp.is_file():
        try:
            rec = json.loads(zp.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            rec = None
    if rec:
        lines.append(f"- Zenodo record id: `{rec.get('id')}`")
        lines.append(f"- conceptrecid: `{rec.get('conceptrecid')}`")
        lines.append(f"- DOI: `{rec.get('doi')}`")
        lines.append(f"- metadata.version: `{rec.get('metadata', {}).get('version')}`")
        lines.append(f"- publication_date: `{rec.get('metadata', {}).get('publication_date')}`")
        lines.append("")
        lines.append("### MD5 verification")
        lines.append("")
        lines.append("| file | size | zenodo md5 | local md5 | match |")
        lines.append("|---|---:|---|---|---|")
        import hashlib

        want = {f["key"]: f["checksum"].split(":", 1)[1] for f in rec.get("files", [])}
        for name in ("trace-benign-2019.tar.gz", "trace-malware-2019.tar.gz"):
            p = DATA_DIR / name
            if not p.is_file():
                continue
            h = hashlib.md5()
            with p.open("rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            got = h.hexdigest()
            exp = want.get(name, "")
            lines.append(
                f"| `{name}` | {p.stat().st_size} | `{exp}` | `{got}` | {got == exp} |"
            )
        lines.append("")

    lines.append("### Version delta (concept 3632183)")
    lines.append("")
    lines.append(
        "| id | doi | version label | publication_date | created | relative_to_4470320 |"
    )
    lines.append("|---:|---|---|---|---|---|")
    versions = [
        (3632184, "10.5281/zenodo.3632184", "1.0.0", "2020-01-31", "2020-01-31", "older"),
        (3632197, "10.5281/zenodo.3632197", "1.0.0", "2020-01-31", "2020-01-31", "older"),
        (3665877, "10.5281/zenodo.3665877", "1.0.0", "2020-01-31", "2020-02-13", "older"),
        (4470320, "10.5281/zenodo.4470320", "1.0.0", "2021-01-27", "2021-01-27", "THIS"),
        (5010831, "10.5281/zenodo.5010831", "1.0.0", "2021-01-27", "2021-06-22", "NEWER"),
        (6336104, "10.5281/zenodo.6336104", "1.0.0", "2022-03-07", "2022-03-07", "NEWER"),
    ]
    for row in versions:
        lines.append(
            f"| {row[0]} | `{row[1]}` | {row[2]} | {row[3]} | {row[4]} | **{row[5]}** |"
        )
    lines.append("")
    lines.append(
        "- Newer versions exist under the same concept (`5010831`, `6336104`). "
        "Probe stayed on record `4470320` (not switched)."
    )
    lines.append("- All listed versions carry metadata.version label `1.0.0` (label not incremented).")
    lines.append("")

    inv = load("inventory.json") or {}
    scan = load("step3_corpus_scan.json") or {}
    lines.append("### Extract inventory")
    lines.append("")
    lines.append(f"- extract_dir: `{inv.get('extract_dir')}`")
    lines.append(f"- benign file count: **{inv.get('benign_n')}** (paper 2019 expected 1361)")
    lines.append(f"- malware file count: **{inv.get('malware_n')}** (paper 2019 expected 1106)")
    lines.append(f"- benign parent dirs: `{inv.get('benign_parent_dirs')}`")
    lines.append(f"- malware parent dirs: `{inv.get('malware_parent_dirs')}`")
    lines.append("- naming scheme: `{SHA256}.apk.logcat` (64-hex SHA256 + `.apk.logcat`)")
    lines.append("- one file per app: yes (`*.apk.logcat`)")
    lines.append(
        "- interior directory year labels (`benign-2016`, `2011`) do not match tarball year "
        "`2019`; file counts: benign matches paper 2019 (1361); malware 1150 ≠ 1106."
    )
    lines.append("")

    # Step 3
    lines.append("## Step 3 — format verification")
    lines.append("")
    s3 = load("step3_format.json") or {}
    lines.append(f"- **ASSERTION RESULT: `{'PASS' if s3.get('ok') else 'FAIL'}`**")
    lines.append("")
    if s3.get("errors"):
        lines.append("### Failures (truncated)")
        lines.append("")
        for e in s3["errors"][:30]:
            lines.append(f"- `{e}`")
        lines.append("")
    if scan:
        lines.append("### Corpus-wide line-kind counts")
        lines.append("")
        for cls, d in scan.items():
            lines.append(f"#### {cls}")
            lines.append("")
            lines.append(f"- n_files: {d['n_files']}")
            lines.append(f"- n_files_zero_calls: {d['n_files_zero_calls']}")
            lines.append(f"- line_kind_counts: `{json.dumps(d['line_kind_counts'])}`")
            lines.append(f"- call_lines: {d['call_lines']}")
            lines.append(
                f"- callee Jimple-quoted method names (e.g. `'from'`): "
                f"{d['callee_jimple_quoted_method_names']}"
            )
            lines.append(f"- callee unparseable: {d['callee_unparseable']}")
            lines.append(f"- `+through reflection` lines: {d['reflection_tag_lines']}")
            lines.append(f"- other_top20: `{d['other_top20']}`")
            lines.append("")
    lines.append("### Call-line form (observed)")
    lines.append("")
    lines.append("- Pattern: `<caller_sig> -> <callee_sig>`")
    lines.append("- Timestamp fields on call lines: none observed in samples")
    lines.append(
        "- Callee FQ: Jimple form `class.path.Name: retType method(params)`; "
        "method may be Jimple-quoted (`'from'`)."
    )
    lines.append("")
    lines.append("### ICC Intent blocks (observed exact format)")
    lines.append("")
    lines.append("Block begins with `[ Intent sent ]` or `[ Intent received ]`, then:")
    lines.append("")
    lines.append("```")
    lines.append("[ Intent sent ]")
    lines.append("caller=<...sig...>")
    lines.append("callsite=virtualinvoke $rN.<...>(...)")
    lines.append("\tAction=...")
    lines.append("\tPackageName=...")
    lines.append("\tDataString=...")
    lines.append("\tDataURI=...")
    lines.append("\tScheme=...")
    lines.append("\tFlags=...")
    lines.append("\tType=...")
    lines.append("\tExtras=...")
    lines.append("\tComponent=...")
    lines.append("\tCategories=N   # optional")
    lines.append("\t\tandroid.intent.category.LAUNCHER  # optional category values")
    lines.append("```")
    lines.append("")
    lines.append("- Typical field count in sent block body: 12 lines (marker + caller + callsite + 9 tab fields).")
    lines.append("")
    lines.append("### Header/metadata")
    lines.append("")
    lines.append("- Logcat headers: `--------- beginning of main|system|crash`")
    lines.append("- Extra non-call tag: `+through reflection` (not in paper’s stated line grammar)")
    lines.append("- Rare logcat pollution lines (device/SDK strings, bare URLs)")
    lines.append("")
    if s3.get("per_class"):
        for cls, d in s3["per_class"].items():
            lines.append(f"### Sampled examples — {cls}")
            lines.append("")
            lines.append(f"- line_count_dist: `{d.get('line_count_dist')}`")
            lines.append("- verbatim call examples:")
            for ex in d.get("verbatim_call_examples") or []:
                lines.append(f"  - `{ex}`")
            lines.append("")

    lines.append("### STOP")
    lines.append("")
    lines.append(
        "- Steps 4–7 **not executed**: Step 3 assertions failed "
        "(`+through reflection` / other non-call non-ICC lines; "
        "Jimple-quoted callees vs strict unquoted FQ regex in first pass)."
    )
    lines.append("- Waiting for human decision before continuing.")
    lines.append("")

    # Step 8
    s8 = load("step8_summary.json")
    lines.append("## Step 8 — v2 corpus delta retention (independent of AndroCT)")
    lines.append("")
    if s8:
        lines.append(f"- k_burst: {s8['k_burst']}")
        lines.append(f"- delta_sec: {s8['delta_sec']}")
        lines.append(f"- n_sessions: {s8['n_sessions']}")
        lines.append("")
        lines.append("### Overall delta-retention (among k≤5 candidate pairs, u≠v)")
        lines.append("")
        o = s8["overall"]
        lines.append(f"- k_candidates: {o['k_candidates']}")
        lines.append(f"- delta_retained: {o['delta_retained']}")
        lines.append(f"- delta_retention_rate: **{o['delta_retention_rate']}**")
        lines.append("")
        lines.append("### By session event-count quartile")
        lines.append("")
        lines.append("| quartile | n_sessions | event_min | event_max | k_candidates | delta_retained | rate |")
        lines.append("|---|---:|---:|---:|---:|---:|---:|")
        for q, d in s8["by_event_count_quartile"].items():
            b = d["event_count_bounds"]
            lines.append(
                f"| {q} | {d['n_sessions']} | {b['min']} | {b['max']} | "
                f"{d['k_candidates']} | {d['delta_retained']} | {d['delta_retention_rate']} |"
            )
        lines.append("")
        es = s8["edge_symmetric_difference"]
        lines.append("### Edge-set symmetric difference (k+δ vs k-only / δ=inf)")
        lines.append("")
        lines.append(
            f"- aggregate sym_diff edge-instances sum over sessions: "
            f"**{es['aggregate_sym_diff_edge_instances_sum_over_sessions']}**"
        )
        lines.append(
            f"- aggregate intersection edge-count sum: "
            f"{es['aggregate_intersection_edge_count_sum']}"
        )
        lines.append(f"- n_unique_only_in_k_disabled: {es['n_unique_only_k']}")
        lines.append(f"- n_unique_only_in_k_delta: {es['n_unique_only_kd']}")
        lines.append(f"- per_session_sym_diff_dist: `{s8['per_session_sym_diff_dist']}`")
        lines.append("")
        lines.append("#### Unique edges only in k-disabled (count = sessions containing edge)")
        lines.append("")
        lines.append("| edge | session_count |")
        lines.append("|---|---:|")
        for e, c in es["unique_edges_only_in_k_disabled"].items():
            lines.append(f"| `{e}` | {c} |")
        lines.append("")
        lines.append("Artifacts: `step8_summary.json`, `step8_per_session.csv`")
    else:
        lines.append("- missing step8_summary.json")
    lines.append("")

    lines.append("## Artifacts")
    lines.append("")
    for p in sorted(OUT_DIR.iterdir()):
        if p.name == "REPORT.md":
            continue
        lines.append(f"- `{p.name}` ({p.stat().st_size} bytes)")
    lines.append("")

    (OUT_DIR / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("wrote", OUT_DIR / "REPORT.md")


if __name__ == "__main__":
    main()
