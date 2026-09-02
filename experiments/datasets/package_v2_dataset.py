#!/usr/bin/env python3
"""Stage and zip v2 dataset session artifacts for offline import (mirrors v1 bundle flow)."""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASETS_ROOT = Path(__file__).resolve().parent
VERSION_DIR = DATASETS_ROOT / "versions" / "v2"

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


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_artifact_dir(row: dict[str, str]) -> Path:
    raw = (row.get("artifact_dir") or "").strip()
    if not raw:
        raise FileNotFoundError(f"missing artifact_dir for {row.get('session_id')}")
    path = Path(raw)
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path


def _filter_rows(rows: list[dict[str, str]], tier: str) -> list[dict[str, str]]:
    if tier == "all":
        return rows
    return [r for r in rows if r.get("tier") == tier]


def _build_readme(
    *,
    rows: list[dict[str, str]],
    tier: str,
    stamp: str,
    copied_files: int,
    missing_dirs: list[str],
    zip_name: str,
    version_meta: dict,
) -> str:
    ref_n = sum(1 for r in rows if r.get("tier") == "reference")
    vol_n = sum(1 for r in rows if r.get("tier") == "volume")
    verdicts = Counter(r.get("faithfulness_verdict") or "" for r in rows)
    apps = len({r["package"] for r in rows})
    lines = [
        "# ContextDroid v2 Dataset Export",
        "",
        f"Packaged: {stamp}",
        "",
        "## What this bundle is",
        "",
        "Portable export of the **immutable v2 dataset** from `logs/bulk_llm_benign_v2/`. "
        "Curation rules, tiers, and tags are defined in `manifest.csv` and `version_meta.json`.",
        "",
        "**Separate generation from v1** (`working_dataset_v129.zip`): v1 used hook v2 + judge_v1_75pct "
        "on bulk_llm_benign_v6; v2 uses hook v3 + judge `faithfulness_v2_phase_aware`. "
        "Do not pool v1 and v2 in evaluation.",
        "",
        "## Counts in this export",
        "",
        f"- **Tier filter:** `{tier}`",
        f"- **Sessions:** {len(rows)}",
        f"- **Distinct apps:** {apps}",
        f"- **Reference tier rows:** {ref_n}",
        f"- **Volume tier rows:** {vol_n}",
        f"- **FAITHFUL:** {verdicts.get('FAITHFUL', 0)}",
        f"- **PARTIAL:** {verdicts.get('PARTIAL', 0)}",
        f"- **FAILED (volume):** {verdicts.get('FAILED', 0)}",
        f"- **Artifact files copied:** {copied_files}",
        "",
        "## Zip layout",
        "",
        f"Archive: `{zip_name}`",
        "",
        "```",
        "v2_dataset_bundle/",
        "  README.md",
        "  manifest.csv              # master index (paths relative to bundle)",
        "  version_meta.json",
        "  notes.md",
        "  sessions/",
        "    <session_id>__<package>/",
        "      SESSION_INDEX.json",
        "      <package>_llm_actions.jsonl",
        "      <package>_frida.jsonl",
        "      ...",
        "```",
        "",
        "## Import into another repo",
        "",
        "1. Copy or unzip this archive into the consumer repo, e.g. `data/contextdroid_v2/`.",
        "2. Use `manifest.csv` as the master index — `artifact_dir` is relative to the bundle root.",
        "3. Filter reference tier: `tier == reference` or re-apply tags from the `tags` column.",
        "4. Read session artifacts from `sessions/<session_id>__<package>/`.",
        "",
        "Example (Python):",
        "",
        "```python",
        "import csv",
        "from pathlib import Path",
        "",
        "root = Path('data/contextdroid_v2/v2_dataset_bundle')",
        "rows = list(csv.DictReader(open(root / 'manifest.csv')))",
        "ref = [r for r in rows if r['tier'] == 'reference']",
        "for r in ref:",
        "    session_dir = root / r['artifact_dir']",
        "    actions = session_dir / f\"{r['package']}_llm_actions.jsonl\"",
        "    frida = session_dir / f\"{r['package']}_frida.jsonl\"",
        "```",
        "",
        "## manifest.csv columns",
        "",
        "| Column | Meaning |",
        "|--------|---------|",
        "| `session_id` | Unique session id |",
        "| `package` | Android package name |",
        "| `app_class` | Heuristic app class (launcher, game, other, …) |",
        "| `tier` | `reference` or `volume` |",
        "| `tags` | Pipe-separated quality tags (multi, not exclusive) |",
        "| `sim_status` | LLM simulation status |",
        "| `faithfulness_verdict` | FAITHFUL / PARTIAL / FAILED |",
        "| `effective_ft` | Explore functional tap count |",
        "| `back_wait_ratio` | Explore back/wait ratio |",
        "| `meaningful_frida_22cat` | Meaningful Frida events in 22 GRAPH categories |",
        "| `coverage_gap` | Judge note on unvisited flows (regrowth targeting) |",
        "| `artifact_dir` | Bundle-relative path to session folder |",
        "",
        "## File glossary (per session folder)",
        "",
    ]
    for pattern, desc in FILE_GLOSSARY.items():
        lines.append(f"- **`{pattern}`** — {desc}")
    lines.extend(
        [
            "",
            "## Reference gate (summary)",
            "",
            version_meta.get("reference_gate_verbatim", "(see version_meta.json)"),
            "",
        ]
    )
    if missing_dirs:
        lines.extend(["## Warnings", ""])
        for d in missing_dirs:
            lines.append(f"- Missing artifact dir: `{d}`")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tier",
        choices=("reference", "volume", "all"),
        default="reference",
        help="Which manifest rows to include (default: reference tier only)",
    )
    parser.add_argument(
        "--manifest",
        default=str(VERSION_DIR / "manifest.csv"),
        help="Path to v2 manifest.csv",
    )
    parser.add_argument(
        "--out-dir",
        default="experiment/v2_dataset_bundle",
        help="Staging directory (under repo root)",
    )
    parser.add_argument(
        "--zip",
        default="",
        help="Output zip path (default: experiment/v2_<tier>_dataset.zip)",
    )
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = REPO_ROOT / manifest_path

    all_rows = list(csv.DictReader(manifest_path.open(encoding="utf-8")))
    rows = _filter_rows(all_rows, args.tier)
    if not rows:
        raise SystemExit(f"no rows for tier={args.tier}")

    version_meta_path = manifest_path.parent / "version_meta.json"
    version_meta = (
        json.loads(version_meta_path.read_text(encoding="utf-8"))
        if version_meta_path.exists()
        else {}
    )
    notes_path = manifest_path.parent / "notes.md"
    notes_text = notes_path.read_text(encoding="utf-8") if notes_path.exists() else ""

    stamp = _utc_now()
    bundle_root = REPO_ROOT / args.out_dir
    if bundle_root.exists():
        shutil.rmtree(bundle_root)
    sessions_root = bundle_root / "sessions"
    sessions_root.mkdir(parents=True)

    copied_files = 0
    missing_dirs: list[str] = []
    export_rows: list[dict[str, str]] = []

    for row in rows:
        sid = row["session_id"]
        pkg = row["package"]
        try:
            src_dir = _resolve_artifact_dir(row)
        except FileNotFoundError:
            missing_dirs.append(f"{sid} ({pkg})")
            continue
        if not src_dir.is_dir():
            missing_dirs.append(str(src_dir))
            continue

        rel_session = f"sessions/{sid}__{pkg}"
        dest_dir = bundle_root / rel_session
        dest_dir.mkdir(parents=True, exist_ok=True)
        for f in sorted(src_dir.iterdir()):
            if f.is_file():
                shutil.copy2(f, dest_dir / f.name)
                copied_files += 1

        (dest_dir / "SESSION_INDEX.json").write_text(
            json.dumps(
                {
                    "package": pkg,
                    "session_id": sid,
                    "tier": row.get("tier"),
                    "tags": row.get("tags", "").split("|") if row.get("tags") else [],
                    "app_class": row.get("app_class"),
                    "faithfulness_verdict": row.get("faithfulness_verdict"),
                    "sim_status": row.get("sim_status"),
                    "meaningful_frida_22cat": int(row.get("meaningful_frida_22cat") or 0),
                    "effective_ft": int(row.get("effective_ft") or 0),
                    "coverage_gap": row.get("coverage_gap", ""),
                    "source_run": "bulk_llm_benign_v2",
                    "hook_version": row.get("hook_version"),
                    "artifact_dir_in_contextdroid": row.get("artifact_dir"),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        export_row = dict(row)
        export_row["artifact_dir"] = rel_session
        export_row["frida_trace_path"] = f"{rel_session}/{pkg}_frida.jsonl"
        export_row["agent_log_path"] = f"{rel_session}/{pkg}_llm_actions.jsonl"
        export_rows.append(export_row)

    fieldnames = list(all_rows[0].keys()) if all_rows else []
    with (bundle_root / "manifest.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(export_rows)

    if version_meta_path.exists():
        shutil.copy2(version_meta_path, bundle_root / "version_meta.json")
    if notes_text:
        (bundle_root / "notes.md").write_text(notes_text, encoding="utf-8")

    zip_name = args.zip or f"experiment/v2_{args.tier}_dataset.zip"
    zip_path = REPO_ROOT / zip_name if not Path(zip_name).is_absolute() else Path(zip_name)
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    if zip_path.exists():
        zip_path.unlink()

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for path in sorted(bundle_root.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(bundle_root.parent))

    readme = _build_readme(
        rows=export_rows,
        tier=args.tier,
        stamp=stamp,
        copied_files=copied_files,
        missing_dirs=missing_dirs,
        zip_name=zip_path.name,
        version_meta=version_meta,
    )
    (bundle_root / "README.md").write_text(readme, encoding="utf-8")
    # Re-zip to include README written after first pass
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for path in sorted(bundle_root.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(bundle_root.parent))

    size_mb = zip_path.stat().st_size / (1024 * 1024)
    print(f"tier: {args.tier}")
    print(f"sessions exported: {len(export_rows)}")
    print(f"distinct apps: {len({r['package'] for r in export_rows})}")
    print(f"files copied: {copied_files}")
    print(f"bundle dir: {bundle_root}")
    print(f"zip: {zip_path} ({size_mb:.1f} MiB)")
    if missing_dirs:
        print(f"WARNING: missing artifact dirs: {len(missing_dirs)}")
        for d in missing_dirs[:5]:
            print(f"  - {d}")


if __name__ == "__main__":
    main()
