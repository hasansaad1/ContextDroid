#!/usr/bin/env python3
"""Assign malware families by hash cross-reference only (no proxies)."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def load_candidates(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def load_hash_family_map(path: Path, sha_col: str, family_col: str, source: str) -> dict[str, tuple[str, str]]:
    if not path.is_file():
        return {}
    out: dict[str, tuple[str, str]] = {}
    with path.open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            sha = (row.get(sha_col) or "").strip().lower()
            family = (row.get(family_col) or "").strip()
            if len(sha) == 64 and family:
                out[sha] = (family, source)
    return out


def apply_labels(
    candidates: list[dict[str, str]],
    *,
    malradar: dict[str, tuple[str, str]],
    amd: dict[str, tuple[str, str]],
    drebin: dict[str, tuple[str, str]],
) -> tuple[list[dict[str, str]], dict]:
    out: list[dict[str, str]] = []
    counts = {"malradar": 0, "amd": 0, "drebin": 0, "none": 0}
    family_hist: dict[str, int] = {}
    for row in candidates:
        sha = (row.get("sha256") or "").strip().lower()
        family = ""
        source = "none"
        if sha in malradar:
            family, source = malradar[sha]
        elif sha in amd:
            family, source = amd[sha]
        elif sha in drebin:
            family, source = drebin[sha]
        counts[source] += 1
        r = dict(row)
        r["family"] = family
        r["family_source"] = source
        r["family_confidence"] = "high" if source != "none" else "none"
        out.append(r)
        if family and source != "none":
            family_hist[family] = family_hist.get(family, 0) + 1
    report = {
        "counts_by_source": counts,
        "labelled_rows": sum(1 for r in out if r["family_source"] != "none"),
        "total_rows": len(out),
        "families_ge_3": sum(1 for n in family_hist.values() if n >= 3),
        "family_histogram_labelled_subset": dict(sorted(family_hist.items(), key=lambda kv: (-kv[1], kv[0]))),
    }
    return out, report


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Label candidates by sha256 cross-reference only")
    parser.add_argument("--candidates", type=Path, required=True, help="CSV containing candidate sha256 column")
    parser.add_argument("--out-csv", type=Path, required=True)
    parser.add_argument("--out-json", type=Path, required=True)

    parser.add_argument("--malradar-file", type=Path, default=None)
    parser.add_argument("--malradar-sha-col", default="sha256")
    parser.add_argument("--malradar-family-col", default="family")

    parser.add_argument("--amd-file", type=Path, default=None)
    parser.add_argument("--amd-sha-col", default="sha256")
    parser.add_argument("--amd-family-col", default="family")

    parser.add_argument("--drebin-file", type=Path, default=None)
    parser.add_argument("--drebin-sha-col", default="sha256")
    parser.add_argument("--drebin-family-col", default="family")
    args = parser.parse_args()

    candidates = load_candidates(args.candidates)
    if not candidates:
        raise SystemExit("candidates CSV is empty")

    malradar = (
        load_hash_family_map(args.malradar_file, args.malradar_sha_col, args.malradar_family_col, "malradar")
        if args.malradar_file
        else {}
    )
    amd = load_hash_family_map(args.amd_file, args.amd_sha_col, args.amd_family_col, "amd") if args.amd_file else {}
    drebin = (
        load_hash_family_map(args.drebin_file, args.drebin_sha_col, args.drebin_family_col, "drebin")
        if args.drebin_file
        else {}
    )

    labelled, report = apply_labels(candidates, malradar=malradar, amd=amd, drebin=drebin)
    write_csv(args.out_csv, labelled)
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
