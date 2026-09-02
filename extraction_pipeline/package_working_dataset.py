#!/usr/bin/env python3
"""Stage and zip working-dataset session artifacts for offline use."""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


FILE_GLOSSARY: dict[str, str] = {
    "*_dynamic_metadata.json": "Session run metadata: package, timing, Frida/strace paths, simulation status, UX gates, app context.",
    "*_llm_actions.jsonl": "Agent action log (one JSON per step): taps, swipes, backs, pipeline phase, screen hashes, app_state.",
    "*_frida.jsonl": "Frida hook trace (JSONL): timestamped API events with category, api, args.",
    "*_frida.csv": "Frida trace as CSV (relative_time, category, api, args_str) — same session as .jsonl.",
    "*_frida.quality.json": "Frida attach/quality summary for the session.",
    "*_strace.log": "Optional strace syscall log (if enabled for the run).",
    "*_llm_ux_plan.json": "Post-explore UX goals, screen digest, semantic navigation graph summary.",
    "*_llm_navigation_artifact.json": "BFS navigation graph: screens, transitions, tab targets visited in explore.",
    "*_human_ux_report.json": "Pipeline UX quality checks (screen diversity, direct-action ratio, etc.).",
    "*_verified_start.xml": "Accessibility hierarchy dump at verified session start (pre-agent).",
    "*_monkey.log": "Warmup/monkey log if pre-setup used random input.",
}


def _rel(repo_root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", default="experiment/working_dataset.csv")
    parser.add_argument("--manifest", default="experiment/working_dataset_manifest.json")
    parser.add_argument("--out-dir", default="experiment/working_dataset_bundle")
    parser.add_argument("--zip", default="experiment/working_dataset_v129.zip")
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[1]
    rows = list(csv.DictReader((repo / args.csv).open(encoding="utf-8")))
    manifest_path = repo / args.manifest
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    bundle_root = repo / args.out_dir
    if bundle_root.exists():
        shutil.rmtree(bundle_root)
    sessions_root = bundle_root / "sessions"
    sessions_root.mkdir(parents=True)

    copied_files = 0
    missing_dirs: list[str] = []

    for row in rows:
        sid = row["session_id"]
        pkg = row["package"]
        src_dir = Path(row["artifact_dir"])
        dest_dir = sessions_root / f"{sid}__{pkg}"
        if not src_dir.is_dir():
            missing_dirs.append(str(src_dir))
            continue
        dest_dir.mkdir(parents=True, exist_ok=True)
        for f in sorted(src_dir.iterdir()):
            if f.is_file():
                shutil.copy2(f, dest_dir / f.name)
                copied_files += 1
        # session index row for quick lookup inside bundle
        (dest_dir / "SESSION_INDEX.json").write_text(
            json.dumps(
                {
                    "package": pkg,
                    "session_id": sid,
                    "faithfulness_verdict": row["faithfulness_verdict"],
                    "meaningful_event_count": int(row.get("meaningful_event_count") or 0),
                    "coverage_gap": row.get("coverage_gap", ""),
                    "artifact_dir_in_repo": row["artifact_dir"],
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    # top-level indexes
    shutil.copy2(repo / args.csv, bundle_root / "working_dataset.csv")
    if manifest_path.exists():
        shutil.copy2(manifest_path, bundle_root / "working_dataset_manifest.json")

    verdicts = Counter(r["faithfulness_verdict"] for r in rows)
    readme = _build_readme(
        rows=rows,
        verdicts=verdicts,
        manifest=manifest,
        stamp=stamp,
        copied_files=copied_files,
        missing_dirs=missing_dirs,
        zip_name=Path(args.zip).name,
    )
    (bundle_root / "README.md").write_text(readme, encoding="utf-8")

    zip_path = repo / args.zip
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for path in sorted(bundle_root.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(bundle_root.parent))

    size_mb = zip_path.stat().st_size / (1024 * 1024)
    print(f"sessions: {len(rows)}")
    print(f"files copied: {copied_files}")
    print(f"bundle dir: {bundle_root}")
    print(f"zip: {zip_path} ({size_mb:.1f} MiB)")
    if missing_dirs:
        print(f"WARNING: missing artifact dirs: {len(missing_dirs)}")


def _build_readme(
    *,
    rows: list[dict[str, str]],
    verdicts: Counter[str],
    manifest: dict,
    stamp: str,
    copied_files: int,
    missing_dirs: list[str],
    zip_name: str,
) -> str:
    lines: list[str] = []
    lines.append("# ContextDroid Working Dataset (v129)")
    lines.append("")
    lines.append(f"Packaged: {stamp}")
    lines.append("")
    lines.append("## What this bundle is")
    lines.append("")
    lines.append(
        "Initial **faithfulness-curated** dataset from the ContextDroid `bulk_llm_benign_v6` corpus. "
        "Each row is one **successful** LLM-agent session judged **FAITHFUL** or **PARTIAL** by "
        "`extraction_pipeline/evaluate_faithfulness.py` (75% collapsed agreement with human labels on a "
        "20-session validation sheet; not re-validated in this export)."
    )
    lines.append("")
    lines.append("**No mechanical-flailing filter** was applied for this export — all 129 keep-set sessions are included.")
    lines.append("")
    lines.append("## Counts")
    lines.append("")
    lines.append(f"- **Sessions:** {len(rows)} (one per app)")
    lines.append(f"- **FAITHFUL:** {verdicts.get('FAITHFUL', 0)}")
    lines.append(f"- **PARTIAL:** {verdicts.get('PARTIAL', 0)}")
    lines.append(f"- **Source pool:** v6 success sessions (238 total in `dataset_index.csv`, incl. overnight runs)")
    lines.append(f"- **Artifact files copied:** {copied_files}")
    lines.append("")
    lines.append("## Zip layout")
    lines.append("")
    lines.append(f"Archive: `{zip_name}`")
    lines.append("")
    lines.append("```")
    lines.append("working_dataset_bundle/")
    lines.append("  README.md                    # this file")
    lines.append("  working_dataset.csv          # master index (129 rows)")
    lines.append("  working_dataset_manifest.json")
    lines.append("  sessions/")
    lines.append("    <session_id>__<package>/   # one folder per session")
    lines.append("      SESSION_INDEX.json         # quick metadata for this session")
    lines.append("      <package>_llm_actions.jsonl")
    lines.append("      <package>_frida.jsonl")
    lines.append("      <package>_frida.csv")
    lines.append("      <package>_dynamic_metadata.json")
    lines.append("      ... (other session artifacts)")
    lines.append("```")
    lines.append("")
    lines.append("## File glossary (per session folder)")
    lines.append("")
    for pattern, desc in FILE_GLOSSARY.items():
        lines.append(f"- **`{pattern}`** — {desc}")
    lines.append("")
    lines.append("## `working_dataset.csv` columns")
    lines.append("")
    lines.append("| Column | Meaning |")
    lines.append("|--------|---------|")
    lines.append("| `package` | Android package name |")
    lines.append("| `session_id` | Unique session id (apk hash prefix + `_llm_s1`) |")
    lines.append("| `faithfulness_verdict` | `FAITHFUL` or `PARTIAL` |")
    lines.append("| `artifact_dir` | Original absolute path in ContextDroid repo |")
    lines.append("| `frida_trace_path` | Path to `*_frida.jsonl` |")
    lines.append("| `agent_log_path` | Path to `*_llm_actions.jsonl` |")
    lines.append("| `dynamic_metadata_path` | Path to `*_dynamic_metadata.json` |")
    lines.append("| `meaningful_event_count` | Descriptive Frida count (framework reflection excluded; not a quality gate) |")
    lines.append("| `coverage_gap` | Judge note on unvisited planned flows |")
    lines.append("")
    lines.append("## App list (129 sessions)")
    lines.append("")
    lines.append("| # | package | session_id | verdict | meaningful_events | sim_status |")
    lines.append("|---|---------|------------|---------|-------------------|------------|")
    for i, row in enumerate(sorted(rows, key=lambda r: r["package"].lower()), 1):
        meta_path = Path(row["dynamic_metadata_path"])
        sim = ""
        if meta_path.exists():
            try:
                sim = str(json.loads(meta_path.read_text(encoding="utf-8")).get("llm_simulation_status") or "")
            except (json.JSONDecodeError, OSError):
                sim = ""
        lines.append(
            f"| {i} | `{row['package']}` | `{row['session_id']}` | {row['faithfulness_verdict']} | "
            f"{row.get('meaningful_event_count', '')} | {sim} |"
        )
    lines.append("")
    if missing_dirs:
        lines.append("## Warnings")
        lines.append("")
        for d in missing_dirs:
            lines.append(f"- Missing artifact dir: `{d}`")
        lines.append("")
    lines.append("## Faithfulness judge (reference)")
    lines.append("")
    lines.append(manifest.get("summary", "(see working_dataset_manifest.json)"))
    lines.append("")
    lines.append("Criteria axes: C1 real screens, C2 acted on them, C3 sustained engagement, C4 blocking failure, C6 coherence.")
    lines.append("This export does **not** apply Frida category-count or graph-viability gates.")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
