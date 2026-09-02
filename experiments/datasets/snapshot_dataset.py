#!/usr/bin/env python3
"""Snapshot and diff immutable working-dataset versions under experiments/datasets/."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASETS_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT / "extraction_pipeline"))

from assemble_working_dataset import detect_suspect_flailing  # noqa: E402
from evaluate_scenario_level import _load_actions  # noqa: E402

JUDGE_VERSION = "judge_v1_75pct"
DEFAULT_SOURCE_RUN = "bulk_llm_benign_v6"

MANIFEST_FIELDS = [
    "session_uid",
    "package",
    "source_run",
    "session_id",
    "artifact_dir",
    "frida_trace_path",
    "agent_log_path",
    "faithfulness_verdict",
    "judge_version",
    "inclusion_status",
    "inclusion_reason",
    "quality_tag",
    "meaningful_event_count",
    "coverage_gap",
    "human_label",
    "notes",
]

REGISTRY_FIELDS = [
    "version_id",
    "created_at",
    "parent_version",
    "n_sessions",
    "n_apps",
    "n_faithful_validated",
    "n_flailing_suspect",
    "judge_version",
    "description",
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rel(path: str | Path) -> str:
    p = Path(path)
    if not str(path).strip():
        return ""
    try:
        return str(p.resolve().relative_to(REPO_ROOT.resolve()))
    except ValueError:
        return str(p)


def _source_run_from_path(path: str) -> str:
    parts = Path(path).parts
    for i, part in enumerate(parts):
        if part == "logs" and i + 1 < len(parts):
            return parts[i + 1]
    return DEFAULT_SOURCE_RUN


def _session_uid(package: str, source_run: str, session_id: str) -> str:
    return f"{package}__{source_run}__{session_id}"


def _load_human_labels(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for row in csv.DictReader(path.open(encoding="utf-8")):
        sid = str(row.get("session_id") or "").strip()
        label = str(row.get("human_label") or "").strip()
        if sid and label:
            out[sid] = label
    return out


def _load_sim_status(artifact_dir: Path, package: str) -> str:
    meta_path = artifact_dir / f"{package}_dynamic_metadata.json"
    if not meta_path.exists():
        return ""
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        return str(meta.get("llm_simulation_status") or "")
    except (json.JSONDecodeError, OSError):
        return ""


def _quality_tag(
    *,
    is_flailing: bool,
    verdict: str,
    human_label: str,
) -> str:
    if is_flailing:
        return "FLAILING_SUSPECT"
    if verdict == "PARTIAL":
        return "LOW_CONFIDENCE"
    if human_label and human_label != verdict:
        return "LOW_CONFIDENCE"
    return "FAITHFUL_VALIDATED"


def _inclusion_reason(*, verdict: str, is_flailing: bool, retain_flailing: bool, excluded: bool) -> str:
    if excluded:
        if is_flailing:
            return "excluded-flailing"
        if verdict == "FAILED":
            return "excluded-degenerate"
        return "excluded-stalled"
    if is_flailing and retain_flailing:
        return "flailing-retained-for-volume"
    if verdict == "PARTIAL":
        return "partial"
    return "faithful"


def build_manifest_rows(
    working_rows: list[dict[str, str]],
    *,
    human_labels: dict[str, str],
    retain_flailing: bool,
    judge_version: str = JUDGE_VERSION,
) -> list[dict[str, str]]:
    manifest: list[dict[str, str]] = []

    for row in working_rows:
        package = row["package"]
        session_id = row["session_id"]
        artifact_dir = Path(row["artifact_dir"])
        source_run = _source_run_from_path(row["artifact_dir"])
        verdict = row["faithfulness_verdict"]
        human_label = human_labels.get(session_id, "")

        actions_path = artifact_dir / f"{package}_llm_actions.jsonl"
        report_path = artifact_dir / f"{package}_human_ux_report.json"
        actions = _load_actions(actions_path) if actions_path.exists() else []
        report = None
        if report_path.exists():
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                report = None

        sim_status = _load_sim_status(artifact_dir, package)
        is_flailing, flail_evidence = detect_suspect_flailing(
            actions, sim_status=sim_status, report=report
        )

        excluded = is_flailing and not retain_flailing
        inclusion_status = "EXCLUDED" if excluded else "INCLUDED"
        quality = _quality_tag(
            is_flailing=is_flailing and retain_flailing,
            verdict=verdict,
            human_label=human_label,
        )
        reason = _inclusion_reason(
            verdict=verdict,
            is_flailing=is_flailing,
            retain_flailing=retain_flailing,
            excluded=excluded,
        )

        notes_parts: list[str] = []
        if flail_evidence:
            notes_parts.append("flailing: " + "; ".join(flail_evidence))
        if human_label and human_label != verdict:
            notes_parts.append(f"human_label={human_label} vs judge={verdict}")

        manifest.append(
            {
                "session_uid": _session_uid(package, source_run, session_id),
                "package": package,
                "source_run": source_run,
                "session_id": session_id,
                "artifact_dir": _rel(artifact_dir),
                "frida_trace_path": _rel(row.get("frida_trace_path") or ""),
                "agent_log_path": _rel(row.get("agent_log_path") or ""),
                "faithfulness_verdict": verdict,
                "judge_version": judge_version,
                "inclusion_status": inclusion_status,
                "inclusion_reason": reason,
                "quality_tag": quality if inclusion_status == "INCLUDED" else "",
                "meaningful_event_count": str(row.get("meaningful_event_count") or 0),
                "coverage_gap": row.get("coverage_gap") or "",
                "human_label": human_label,
                "notes": " | ".join(notes_parts),
            }
        )

    manifest.sort(key=lambda r: (r["package"].lower(), r["session_id"]))
    return manifest


def _included(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [r for r in rows if r["inclusion_status"] == "INCLUDED"]


def _counts(rows: list[dict[str, str]]) -> dict[str, Any]:
    inc = _included(rows)
    return {
        "total_rows": len(rows),
        "included": len(inc),
        "excluded": len(rows) - len(inc),
        "by_inclusion_status": dict(Counter(r["inclusion_status"] for r in rows)),
        "by_quality_tag": dict(Counter(r["quality_tag"] for r in inc if r["quality_tag"])),
        "by_faithfulness_verdict": dict(Counter(r["faithfulness_verdict"] for r in inc)),
        "distinct_apps": len({r["package"] for r in inc}),
        "by_source_run": dict(Counter(r["source_run"] for r in inc)),
    }


def _registry_row(
    version_id: str,
    created_at: str,
    parent_version: str,
    description: str,
    rows: list[dict[str, str]],
    judge_version: str,
) -> dict[str, str]:
    inc = _included(rows)
    return {
        "version_id": version_id,
        "created_at": created_at,
        "parent_version": parent_version,
        "n_sessions": str(len(inc)),
        "n_apps": str(len({r["package"] for r in inc})),
        "n_faithful_validated": str(sum(1 for r in inc if r["quality_tag"] == "FAITHFUL_VALIDATED")),
        "n_flailing_suspect": str(sum(1 for r in inc if r["quality_tag"] == "FLAILING_SUSPECT")),
        "judge_version": judge_version,
        "description": description,
    }


def _append_registry(registry_path: Path, row: dict[str, str]) -> None:
    exists = registry_path.exists()
    with registry_path.open("a", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=REGISTRY_FIELDS)
        if not exists:
            w.writeheader()
        w.writerow(row)


def _read_manifest(version_id: str) -> list[dict[str, str]]:
    path = DATASETS_ROOT / "versions" / version_id / "manifest.csv"
    if not path.exists():
        raise FileNotFoundError(f"manifest not found: {path}")
    return list(csv.DictReader(path.open(encoding="utf-8")))


def cmd_snapshot(args: argparse.Namespace) -> None:
    version_id = args.version_id
    version_dir = DATASETS_ROOT / "versions" / version_id
    if version_dir.exists():
        raise SystemExit(f"refusing to overwrite existing version: {version_dir}")

    working_csv = REPO_ROOT / args.working_csv
    working_rows = list(csv.DictReader(working_csv.open(encoding="utf-8")))
    human_labels = _load_human_labels(REPO_ROOT / args.human_labels)

    manifest = build_manifest_rows(
        working_rows,
        human_labels=human_labels,
        retain_flailing=args.retain_flailing,
        judge_version=args.judge_version,
    )

    created_at = _utc_now()
    counts = _counts(manifest)
    source_runs = sorted({r["source_run"] for r in _included(manifest)})

    version_dir.mkdir(parents=True)
    with (version_dir / "manifest.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=MANIFEST_FIELDS)
        w.writeheader()
        w.writerows(manifest)

    meta = {
        "version_id": version_id,
        "created_at": created_at,
        "parent_version": args.parent_version or None,
        "description": args.description,
        "source_runs": source_runs,
        "judge_version": args.judge_version,
        "curation_rules": args.curation_rules,
        "counts": counts,
        "reproduction": {
            "commands": [
                "python3 extraction_pipeline/assemble_working_dataset.py "
                "--skip-flailing-filter "
                "--faithfulness-json experiment/faithfulness_full_pool.json",
                f"python3 experiments/datasets/snapshot_dataset.py snapshot "
                f"--version-id {version_id} "
                f"--parent-version {args.parent_version or ''} "
                f"--description \"{args.description}\" "
                f"--working-csv {args.working_csv} "
                f"--faithfulness-json {args.faithfulness_json} "
                f"--human-labels {args.human_labels} "
                f"--judge-version {args.judge_version} "
                f"--curation-rules \"{args.curation_rules}\" "
                + ("--retain-flailing" if args.retain_flailing else "--exclude-flailing"),
            ],
            "inputs": {
                "working_csv": _rel(working_csv),
                "faithfulness_json": _rel(REPO_ROOT / args.faithfulness_json),
                "human_labels": _rel(REPO_ROOT / args.human_labels),
                "dataset_index": "logs/bulk_llm_benign_v6/dataset_index.csv",
            },
        },
        "known_limitations": args.known_limitations,
    }
    (version_dir / "version_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    if args.notes_file:
        notes_src = Path(args.notes_file)
        notes_text = notes_src.read_text(encoding="utf-8") if notes_src.exists() else ""
    else:
        notes_text = _default_notes(version_id, args, counts, human_labels)
    (version_dir / "notes.md").write_text(notes_text, encoding="utf-8")

    reg_row = _registry_row(
        version_id, created_at, args.parent_version or "", args.description, manifest, args.judge_version
    )
    _append_registry(DATASETS_ROOT / "registry.csv", reg_row)

    inc = _included(manifest)
    print(f"version {version_id} written to {version_dir}")
    print(f"counts: total_rows={counts['total_rows']} included={counts['included']} apps={counts['distinct_apps']}")
    print(
        f"quality_tag: FAITHFUL_VALIDATED={counts['by_quality_tag'].get('FAITHFUL_VALIDATED', 0)} "
        f"FLAILING_SUSPECT={counts['by_quality_tag'].get('FLAILING_SUSPECT', 0)} "
        f"LOW_CONFIDENCE={counts['by_quality_tag'].get('LOW_CONFIDENCE', 0)}"
    )
    print(f"verdict: {counts['by_faithfulness_verdict']}")
    print("registry row:")
    print(", ".join(f"{k}={reg_row[k]}" for k in REGISTRY_FIELDS))


def _default_notes(
    version_id: str,
    args: argparse.Namespace,
    counts: dict[str, Any],
    human_labels: dict[str, str],
) -> str:
    lines = [
        f"# {version_id}",
        "",
        args.description,
        "",
        "## Curation",
        "",
        args.curation_rules,
        "",
        "## Counts",
        "",
        f"- Included sessions: {counts['included']}",
        f"- Distinct apps: {counts['distinct_apps']}",
        f"- By quality_tag: {counts['by_quality_tag']}",
        f"- By verdict: {counts['by_faithfulness_verdict']}",
        "",
        "## Human labels",
        "",
        f"{len(human_labels)} sessions in human label sheet; filled in manifest where session is present.",
        "",
        "## Known limitations",
        "",
    ]
    for lim in args.known_limitations:
        lines.append(f"- {lim}")
    lines.append("")
    return "\n".join(lines)


def cmd_diff(args: argparse.Namespace) -> None:
    va, vb = args.versions
    rows_a = {r["session_uid"]: r for r in _read_manifest(va)}
    rows_b = {r["session_uid"]: r for r in _read_manifest(vb)}

    uids_a = set(rows_a)
    uids_b = set(rows_b)
    added = sorted(uids_b - uids_a)
    removed = sorted(uids_a - uids_b)

    compare_fields = ("faithfulness_verdict", "quality_tag", "inclusion_status", "inclusion_reason")
    changed: list[tuple[str, dict[str, tuple[str, str]]]] = []
    for uid in sorted(uids_a & uids_b):
        diffs: dict[str, tuple[str, str]] = {}
        for field in compare_fields:
            old = rows_a[uid].get(field, "")
            new = rows_b[uid].get(field, "")
            if old != new:
                diffs[field] = (old, new)
        if diffs:
            changed.append((uid, diffs))

    print(f"diff {va} -> {vb}")
    print(f"added ({len(added)}):")
    for uid in added:
        r = rows_b[uid]
        print(f"  + {uid} [{r['inclusion_status']}] {r['quality_tag']} {r['faithfulness_verdict']}")
    print(f"removed ({len(removed)}):")
    for uid in removed:
        r = rows_a[uid]
        print(f"  - {uid} [{r['inclusion_status']}] {r['quality_tag']} {r['faithfulness_verdict']}")
    print(f"changed ({len(changed)}):")
    for uid, diffs in changed:
        parts = ", ".join(f"{k}: {v[0]!r}->{v[1]!r}" for k, v in diffs.items())
        print(f"  ~ {uid}: {parts}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    snap = sub.add_parser("snapshot", help="Create a new immutable dataset version")
    snap.add_argument("--version-id", required=True)
    snap.add_argument("--parent-version", default="")
    snap.add_argument("--description", required=True)
    snap.add_argument("--working-csv", default="experiment/working_dataset.csv")
    snap.add_argument("--faithfulness-json", default="experiment/faithfulness_full_pool.json")
    snap.add_argument("--human-labels", default="experiment/faithfulness_human_label_sheet.csv")
    snap.add_argument("--judge-version", default=JUDGE_VERSION)
    snap.add_argument(
        "--curation-rules",
        default=(
            "FAITHFUL+PARTIAL kept; flailing RETAINED tagged FLAILING_SUSPECT; "
            "sparse kept; nothing gated on category count or graph viability"
        ),
    )
    snap.add_argument(
        "--known-limitation",
        action="append",
        dest="known_limitations",
        default=[
            "Faithfulness judge at 75% collapsed agreement with 20-session human validation (below 90% threshold).",
            "Flailing sessions included for pipeline-build volume, not reference-quality.",
            "meaningful_event_count and Frida category counts are descriptive only, not inclusion gates.",
        ],
    )
    snap.add_argument("--notes-file", default="")
    flail = snap.add_mutually_exclusive_group()
    flail.add_argument("--retain-flailing", action="store_true", default=True)
    flail.add_argument("--exclude-flailing", action="store_true")
    snap.set_defaults(func=cmd_snapshot)

    diff = sub.add_parser("diff", help="Compare two dataset versions")
    diff.add_argument("versions", nargs=2, metavar=("VA", "VB"))
    diff.set_defaults(func=cmd_diff)

    args = parser.parse_args()
    if getattr(args, "exclude_flailing", False):
        args.retain_flailing = False
    args.func(args)


if __name__ == "__main__":
    main()
