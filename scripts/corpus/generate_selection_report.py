#!/usr/bin/env python3
"""Generate selection_report.md from benign profile + candidates (Phase 2.5)."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import Counter
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROFILE = REPO_ROOT / "manifest" / "benign_profile.json"
DEFAULT_CANDIDATES = REPO_ROOT / "manifest" / "candidates.csv"
DEFAULT_OUT = REPO_ROOT / "manifest" / "selection_report.md"


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--candidates", type=Path, default=DEFAULT_CANDIDATES)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--index-header", default="", help="Comma-separated header fields for report")
    parser.add_argument("--index-file", default="", help="Frozen index filename")
    parser.add_argument("--index-sha256", default="", help="Frozen index sha256")
    parser.add_argument("--labelled-candidates", type=Path, default=None, help="Optional labelled candidates CSV")
    parser.add_argument("--label-source-report", type=Path, default=None, help="Optional source match-count JSON")
    args = parser.parse_args(argv)

    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    candidates = load_csv(args.candidates) if args.candidates.is_file() else []

    b_apk = profile["apk_size_bytes"]
    b_dex = profile["dex_size_bytes"]
    b_perm = profile["permission_count"]
    b_dex_date = profile["dex_date"]

    c_apk = [float(r["apk_size"]) for r in candidates if r.get("apk_size")]
    c_dex = [float(r["dex_size"]) for r in candidates if r.get("dex_size")]
    c_vt = [int(r["vt_detection"]) for r in candidates if r.get("vt_detection")]
    labelled_rows = load_csv(args.labelled_candidates) if args.labelled_candidates and args.labelled_candidates.is_file() else candidates
    labelled_only = [r for r in labelled_rows if (r.get("family_source") or "none") != "none" and (r.get("family") or "")]
    fam_col = Counter((r.get("family") or "").strip() for r in labelled_only if (r.get("family") or "").strip())
    source_col = Counter((r.get("family_source") or "none") for r in labelled_rows)

    lines = [
        "# Malware candidate selection report (Phase 2A)",
        "",
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')} UTC",
        "",
        "## AndroZoo index header (observed — parse by name, not legacy column order)",
        "",
        "```",
        args.index_header or "(not supplied — re-run with --index-header from inspect)",
        "```",
        "",
        "**Note:** Older AndroZoo docs list columns in a different order and sometimes omit",
        "that a header row exists. The live `latest.csv.gz` (2026-07-27) includes a header",
        "row; fields include `vt_detection` but **no family / AVClass column**.",
        "",
        "## Pinned metadata index",
        "",
        f"- Frozen index file: `{args.index_file or '(not supplied)'}`",
        f"- Frozen index SHA256: `{args.index_sha256 or '(not supplied)'}`",
        "- Full `latest.csv.gz` cache remains truncated locally (~243MB/3.3GB); this run uses a pinned frozen snapshot file for deterministic reruns.",
        "",
        "## Benign profile summary (`manifest/benign_profile.json`)",
        "",
        f"- APK count: **{profile['apk_count']}**",
        f"- APK size (bytes): min={b_apk['min']:.0f}, Q1={b_apk['q1']:.0f}, median={b_apk['median']:.0f}, Q3={b_apk['q3']:.0f}, max={b_apk['max']:.0f}",
        f"- DEX size (bytes): min={b_dex['min']:.0f}, Q1={b_dex['q1']:.0f}, median={b_dex['median']:.0f}, Q3={b_dex['q3']:.0f}, max={b_dex['max']:.0f}",
        f"- Permission count: min={b_perm['min']:.0f}, median={b_perm['median']:.0f}, max={b_perm['max']:.0f}",
        f"- Local DEX dates contain ZIP sentinels (`1980/1981`): **{b_dex_date.get('sentinel_1980_1981_count')} / {profile['apk_count']}**",
        "- Benign date axis is excluded from matching and overlay; if needed later, use AndroZoo `dex_date` joined by benign SHA256, not local ZIP headers.",
        "",
        "## Candidate pool (this run)",
        "",
        f"- Candidates written: **{len(candidates)}** (pre-label over-selection target ~=150)",
        f"- VT detection (candidates): min={min(c_vt) if c_vt else 'n/a'}, max={max(c_vt) if c_vt else 'n/a'}, median={statistics.median(c_vt) if c_vt else 'n/a'}",
        "",
        "### APK size — benign vs candidates",
        "",
        "| Tier | min | median | max |",
        "|---|---:|---:|---:|",
        f"| Benign | {b_apk['min']:.0f} | {b_apk['median']:.0f} | {b_apk['max']:.0f} |",
        f"| Candidates | {min(c_apk) if c_apk else 0:.0f} | {statistics.median(c_apk) if c_apk else 0:.0f} | {max(c_apk) if c_apk else 0:.0f} |",
        "",
        "**Selection filter:** candidates restricted to benign APK-size IQR "
        f"[{profile['selection_iqr']['apk_size_low']:.0f}, {profile['selection_iqr']['apk_size_high']:.0f}].",
        "",
        "### Family histogram (labelled subset only)",
        "",
    ]
    lines.append(f"- Labelled rows: **{len(labelled_only)} / {len(labelled_rows)}**")
    lines.append(f"- Source matches: malradar={source_col.get('malradar', 0)}, amd={source_col.get('amd', 0)}, drebin={source_col.get('drebin', 0)}, none={source_col.get('none', 0)}")
    ge3 = sum(1 for _, n in fam_col.items() if n >= 3)
    lines.append(f"- Families with >=3 samples (labelled subset): **{ge3}**")
    lines.append("- Holdout planning note: choose zero-day held-out families only from this `>=3 samples` set once real labels are available.")
    if fam_col:
        for fam, n in fam_col.most_common():
            lines.append(f"- `{fam}`: {n}")
    else:
        lines.append("- _(no labelled matches; histogram empty)_")

    lines.extend(
        [
            "",
            "## Tier mismatch / validity threats",
            "",
        ]
    )

    mismatches = []
    if c_apk and (max(c_apk) > b_apk["q3"] * 1.5 or min(c_apk) < b_apk["q1"] * 0.5):
        mismatches.append("APK size tail may differ despite IQR filter (check edge cases).")
    if not fam_col:
        mismatches.append(
            "**Family diversity not yet satisfiable** because labelled subset is empty from available hash lists/sources."
        )
    if not mismatches:
        lines.append("- No major size/date mismatch flagged beyond pending family decision.")
    else:
        for m in mismatches:
            lines.append(f"- {m}")

    lines.extend(
        [
            "",
            "## Family labelling provenance and access",
            "",
            "- MalRadar Zenodo record: restricted access (`access_right=restricted`), files API returns empty file list without grant.",
            "- AMD published source does not expose a public sha256-family list in this environment; no direct downloadable hash list located.",
            "- Drebin is optional and narrow-era; included only if explicitly provided/available.",
            "- Package-name proxy was **not** used.",
            "",
            "**API key / download scope:** Metadata CSV is public (no key). APK download via AndroZoo API",
            "requires an approved API key; malware-tier samples may need explicit scope approval before 2B.",
            "This agent shell has **no `ANDROZOO_API_KEY` set** — confirm your key and scope before fetch.",
            "",
        ]
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
