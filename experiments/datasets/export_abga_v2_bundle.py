#!/usr/bin/env python3
"""Export v2 reference tier as datasets/v2/ for adaptive-behavioral-graph-analysis."""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_V2 = REPO_ROOT / "experiments/datasets/versions/v2/manifest.csv"
ABGA_DATASETS_V2_ENV = "ABGA_DATASETS_V2"

ARTIFACT_SUFFIXES = (
    "_frida.jsonl",
    "_frida.csv",
    "_frida.quality.json",
    "_dynamic_metadata.json",
    "_llm_actions.jsonl",
    "_llm_ux_plan.json",
    "_llm_navigation_artifact.json",
    "_human_ux_report.json",
    "_verified_start.xml",
    "_strace.log",
    "_monkey.log",
)

PATH_KEYS_IN_METADATA = (
    "frida_log_path",
    "strace_log_path",
    "llm_action_log_path",
    "llm_step_trace_path",
    "llm_audit_log_path",
    "llm_ux_plan_path",
    "llm_navigation_artifact_path",
)

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


def _artifact_names(pkg: str) -> list[str]:
    return [f"{pkg}{suffix}" for suffix in ARTIFACT_SUFFIXES]


def _resolve_src_dir(row: dict[str, str]) -> Path:
    path = Path(row["artifact_dir"])
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path


def _rewrite_metadata_paths(meta: dict[str, Any], pkg: str) -> dict[str, Any]:
    out = dict(meta)
    for key in PATH_KEYS_IN_METADATA:
        val = out.get(key)
        if isinstance(val, str) and val.strip():
            name = Path(val).name
            if name.startswith(f"{pkg}_"):
                out[key] = name
    return out


def _load_selection(tier: str) -> list[dict[str, str]]:
    rows = list(csv.DictReader(MANIFEST_V2.open(encoding="utf-8")))
    if tier == "reference":
        return [r for r in rows if r.get("tier") == "reference"]
    if tier == "faithful_partial":
        return [
            r
            for r in rows
            if r.get("faithfulness_verdict") in {"FAITHFUL", "PARTIAL"}
        ]
    raise SystemExit(f"unknown tier selector: {tier}")


def _build_manifest_json(rows: list[dict[str, str]], per_app: Counter[str]) -> dict[str, Any]:
    faithful = sum(1 for r in rows if r["faithfulness_verdict"] == "FAITHFUL")
    partial = sum(1 for r in rows if r["faithfulness_verdict"] == "PARTIAL")
    return {
        "dataset_version": "v2",
        "dataset": "working_dataset",
        "repo_path": "datasets/v2",
        "source_pool": "logs/bulk_llm_benign_v2 analyze-success sessions (hook_apis.js v3; collection_v2, 420s)",
        "hook_script_version": "3",
        "collection_run_id": "bulk_llm_benign_v2",
        "faithfulness_judge": "faithfulness_v2_phase_aware (80% exact / 100% collapsed human agreement on 20-session sheet)",
        "selection_criteria": (
            "Reference tier from ContextDroid v2 curation: analyze_status=success, sim=success, "
            "faithfulness in {FAITHFUL,PARTIAL}, C0 explore engagement, meaningful_frida_22cat>0 "
            "(22 GRAPH categories excl. lifecycle/reflection/navigation), NOT flailing, NOT auth_gated, "
            "NOT network_degraded (best-effort). Separate generation from v1 — do not pool."
        ),
        "step1_keep_set": {
            "verdicts": ["FAITHFUL", "PARTIAL"],
            "tier": "reference",
            "count": len(rows),
            "distinct_apps": len(per_app),
            "per_app": dict(sorted(per_app.items())),
        },
        "summary": (
            f"{len(rows)} reference-tier sessions ({len(per_app)} apps) from bulk_llm_benign_v2; "
            f"{faithful} FAITHFUL, {partial} PARTIAL; hook v3; faithfulness_v2_phase_aware judge."
        ),
    }


def _build_readme(
    *,
    rows: list[dict[str, str]],
    stamp: str,
    copied_files: int,
    csv_rows: list[dict[str, str]],
) -> str:
    verdicts = Counter(r["faithfulness_verdict"] for r in rows)
    apps = len({r["package"] for r in rows})
    per_app = Counter(r["package"] for r in rows)
    lines = [
        "# Dataset v2 — ContextDroid Reference Tier (bulk_llm_benign_v2)",
        "",
        "**Repo version:** `v2` · see [`VERSION.json`](VERSION.json) and [`../CURRENT`](../CURRENT)",
        "",
        f"Packaged: {stamp}",
        "",
        "## What this bundle is",
        "",
        "**Reference-tier** sessions from ContextDroid `bulk_llm_benign_v2` (hook_apis.js **v3**, 420s sessions, ",
        "3 sessions/app with identical/identical/varied seeds). Curation uses the v2 reference gate ",
        "(sim success, faithfulness FAITHFUL/PARTIAL, explore engagement, meaningful 22-category Frida, ",
        "not flailing). **Separate generation from v1** — never pool v1 and v2 in evaluation.",
        "",
        "## Counts",
        "",
        f"- **Sessions:** {len(rows)} ({apps} distinct apps; up to {max(per_app.values())} sessions/app)",
        f"- **FAITHFUL:** {verdicts.get('FAITHFUL', 0)}",
        f"- **PARTIAL:** {verdicts.get('PARTIAL', 0)}",
        f"- **Source pool:** bulk_llm_benign_v2 analyze-success (594 at curation time; 197/284 apps completed)",
        f"- **Artifact files copied:** {copied_files} (+ {len(rows)} SESSION_INDEX.json)",
        f"- **Hook script:** hook_apis.js v3 (25 categories in trace; graph uses 22 excluding lifecycle/reflection/navigation)",
        "",
        "## Layout",
        "",
        "Archive (original export): [`archive/working_dataset_v2.zip`](archive/working_dataset_v2.zip)",
        "",
        "```",
        "datasets/v2/",
        "  VERSION.json",
        "  README.md",
        "  working_dataset.csv",
        "  working_dataset_manifest.json",
        "  sessions/",
        "    <session_id>__<package>/",
        "      SESSION_INDEX.json",
        "      <package>_frida.jsonl",
        "      ... (11 more artifact files)",
        "  archive/",
        "    working_dataset_v2.zip",
        "```",
        "",
        "## File glossary (per session folder)",
        "",
    ]
    for pattern, desc in FILE_GLOSSARY.items():
        lines.append(f"- **`{pattern}`** — {desc}")
    lines.extend(
        [
            "",
            "## Frida trace format (hook_apis.js v3)",
            "",
            "- JSONL lines: `{\"type\":\"event\",\"timestamp\":<ms>,\"api\":\"...\",\"category\":\"...\",\"args\":{...}}`",
            "- Optional `type:\"status\"` / `hook_ok` lines retained",
            "- `hook_loaded` event with `version:\"3\"`",
            "- 25 hook categories in trace (full CATEGORY_UNIVERSE); lifecycle/reflection/navigation included in raw trace",
            "",
            "## `working_dataset.csv` columns",
            "",
            "| Column | Meaning |",
            "|--------|---------|",
            "| `package` | Android package name |",
            "| `session_id` | `{apk_sha256_prefix12}_llm_sN` |",
            "| `faithfulness_verdict` | `FAITHFUL` or `PARTIAL` |",
            "| `artifact_dir` | Path relative to `datasets/v2/` → `sessions/<session_id>__<package>` |",
            "| `frida_trace_path` | `{package}_frida.jsonl` (relative to session folder) |",
            "| `agent_log_path` | `{package}_llm_actions.jsonl` |",
            "| `dynamic_metadata_path` | `{package}_dynamic_metadata.json` |",
            "| `meaningful_event_count` | Frida quality meaningful count (excl. reflection/lifecycle/unknown) |",
            "| `coverage_gap` | Judge note on unvisited flows |",
            "",
            f"## App list ({len(rows)} sessions)",
            "",
            "| # | package | session_id | verdict | meaningful_events | sim_status |",
            "|---|---------|------------|---------|-------------------|------------|",
        ]
    )
    sim_by_sid = {}
    for r in rows:
        meta_path = _resolve_src_dir(r) / f"{r['package']}_dynamic_metadata.json"
        sim = r.get("sim_status") or ""
        if meta_path.exists():
            try:
                sim = str(json.loads(meta_path.read_text(encoding="utf-8")).get("llm_simulation_status") or sim)
            except (json.JSONDecodeError, OSError):
                pass
        sim_by_sid[r["session_id"]] = sim

    for i, row in enumerate(sorted(csv_rows, key=lambda r: (r["package"].lower(), r["session_id"])), 1):
        lines.append(
            f"| {i} | `{row['package']}` | `{row['session_id']}` | {row['faithfulness_verdict']} | "
            f"{row['meaningful_event_count']} | {sim_by_sid.get(row['session_id'], '')} |"
        )
    lines.append("")
    return "\n".join(lines)


def export_bundle(*, target_dir: Path, tier: str = "reference") -> dict[str, Any]:
    rows = _load_selection(tier)
    if not rows:
        raise SystemExit(f"no sessions selected for tier={tier}")

    if target_dir.exists():
        shutil.rmtree(target_dir)
    sessions_root = target_dir / "sessions"
    archive_root = target_dir / "archive"
    sessions_root.mkdir(parents=True)
    archive_root.mkdir(parents=True)

    stamp = _utc_now()
    copied_files = 0
    csv_rows: list[dict[str, str]] = []
    per_app: Counter[str] = Counter()
    missing: list[str] = []

    for row in rows:
        pkg = row["package"]
        sid = row["session_id"]
        src_dir = _resolve_src_dir(row)
        names = _artifact_names(pkg)
        missing_files = [n for n in names if not (src_dir / n).exists()]
        if missing_files:
            missing.append(f"{sid}__{pkg}: {missing_files}")
            continue

        folder = f"{sid}__{pkg}"
        rel_artifact_dir = f"sessions/{folder}"
        dest_dir = target_dir / rel_artifact_dir
        dest_dir.mkdir(parents=True, exist_ok=True)

        for name in names:
            shutil.copy2(src_dir / name, dest_dir / name)
            copied_files += 1
            if name.endswith("_dynamic_metadata.json"):
                meta = json.loads((dest_dir / name).read_text(encoding="utf-8"))
                meta = _rewrite_metadata_paths(meta, pkg)
                (dest_dir / name).write_text(json.dumps(meta, indent=2), encoding="utf-8")

        meaningful = 0
        qpath = dest_dir / f"{pkg}_frida.quality.json"
        if qpath.exists():
            meaningful = int(json.loads(qpath.read_text(encoding="utf-8")).get("meaningful_events") or 0)

        session_index = {
            "package": pkg,
            "session_id": sid,
            "faithfulness_verdict": row["faithfulness_verdict"],
            "meaningful_event_count": meaningful,
            "coverage_gap": row.get("coverage_gap") or "",
            "artifact_dir_in_repo": row.get("artifact_dir") or "",
        }
        (dest_dir / "SESSION_INDEX.json").write_text(
            json.dumps(session_index, indent=2), encoding="utf-8"
        )

        csv_rows.append(
            {
                "package": pkg,
                "session_id": sid,
                "faithfulness_verdict": row["faithfulness_verdict"],
                "artifact_dir": rel_artifact_dir,
                "frida_trace_path": f"{pkg}_frida.jsonl",
                "agent_log_path": f"{pkg}_llm_actions.jsonl",
                "dynamic_metadata_path": f"{pkg}_dynamic_metadata.json",
                "meaningful_event_count": str(meaningful),
                "coverage_gap": row.get("coverage_gap") or "",
            }
        )
        per_app[pkg] += 1

    if missing:
        raise SystemExit(f"abort: {len(missing)} sessions missing required artifacts, e.g. {missing[0]}")

    csv_fields = [
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
    with (target_dir / "working_dataset.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=csv_fields)
        w.writeheader()
        w.writerows(sorted(csv_rows, key=lambda r: (r["package"].lower(), r["session_id"])))

    manifest = _build_manifest_json(csv_rows, per_app)
    (target_dir / "working_dataset_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    faithful = sum(1 for r in csv_rows if r["faithfulness_verdict"] == "FAITHFUL")
    partial = sum(1 for r in csv_rows if r["faithfulness_verdict"] == "PARTIAL")
    version = {
        "dataset_version": "v2",
        "label": "benign_reference_tier_v2",
        "session_count": len(csv_rows),
        "faithful_count": faithful,
        "partial_count": partial,
        "distinct_apps": len(per_app),
        "source_pool": "ContextDroid bulk_llm_benign_v2",
        "hook_script_version": "3",
        "collection_run_id": "bulk_llm_benign_v2",
        "packaged_at": stamp,
        "archive": "archive/working_dataset_v2.zip",
        "index_csv": "working_dataset.csv",
        "manifest_json": "working_dataset_manifest.json",
        "sessions_dir": "sessions",
    }
    (target_dir / "VERSION.json").write_text(json.dumps(version, indent=2), encoding="utf-8")

    readme = _build_readme(rows=csv_rows, stamp=stamp, copied_files=copied_files, csv_rows=csv_rows)
    (target_dir / "README.md").write_text(readme, encoding="utf-8")

    zip_path = archive_root / "working_dataset_v2.zip"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for path in sorted(sessions_root.rglob("*")):
            if path.is_file():
                zf.write(path, f"working_dataset_v2/sessions/{path.relative_to(sessions_root)}")
        zf.writestr("working_dataset_v2/working_dataset.csv", (target_dir / "working_dataset.csv").read_text())
        zf.writestr(
            "working_dataset_v2/working_dataset_manifest.json",
            (target_dir / "working_dataset_manifest.json").read_text(),
        )
        zf.writestr("working_dataset_v2/VERSION.json", (target_dir / "VERSION.json").read_text())
        zf.writestr("working_dataset_v2/README.md", readme)

    return {
        "target_dir": str(target_dir),
        "sessions": len(csv_rows),
        "apps": len(per_app),
        "faithful": faithful,
        "partial": partial,
        "zip_mb": zip_path.stat().st_size / (1024 * 1024),
        "stamp": stamp,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        type=Path,
        default=None,
        help=f"ABGA datasets/v2 output directory (or set {ABGA_DATASETS_V2_ENV})",
    )
    parser.add_argument("--tier", default="reference", choices=("reference",))
    parser.add_argument(
        "--update-current",
        type=Path,
        default=None,
        help="Write datasets/CURRENT pointer to this path (default: <target>/../CURRENT)",
    )
    args = parser.parse_args()

    target = args.target
    if target is None:
        env_val = os.environ.get(ABGA_DATASETS_V2_ENV, "").strip()
        if env_val:
            target = Path(env_val)
    if target is None:
        parser.error(f"--target is required (or set {ABGA_DATASETS_V2_ENV} to the ABGA datasets/v2 path)")

    update_current = args.update_current
    if update_current is None:
        update_current = target.parent / "CURRENT"

    stats = export_bundle(target_dir=target, tier=args.tier)
    if update_current:
        update_current.write_text("v2\n", encoding="utf-8")

    print(f"exported {stats['sessions']} sessions ({stats['apps']} apps) -> {stats['target_dir']}")
    print(f"FAITHFUL={stats['faithful']} PARTIAL={stats['partial']}")
    print(f"archive: {stats['target_dir']}/archive/working_dataset_v2.zip ({stats['zip_mb']:.1f} MiB)")
    if update_current:
        print(f"CURRENT -> {update_current}")


if __name__ == "__main__":
    main()
