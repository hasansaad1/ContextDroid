#!/usr/bin/env python3
"""Summarize CONTEXTDROID_LLM_AUDIT_SESSION output (*_llm_step_audit.jsonl).

Usage:
  python3 extraction_pipeline/report_llm_audit.py logs/.../org.example_pkg_llm_step_audit.jsonl
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate LLM step audit codes.")
    parser.add_argument("audit_jsonl", type=Path, help="Path to *_llm_step_audit.jsonl")
    parser.add_argument("--top", type=int, default=30, help="Max distinct codes to print")
    args = parser.parse_args()

    path = args.audit_jsonl
    if not path.is_file():
        raise SystemExit(f"Not a file: {path}")

    code_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    steps = 0
    highs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("audit_schema"):
            continue
        steps += 1
        asm = row.get("assessment") or {}
        sev = str(asm.get("severity") or "info")
        severity_counts[sev] += 1
        for c in asm.get("codes") or []:
            code_counts[str(c)] += 1
        if sev == "high":
            highs.append(row.get("step"))

    print(f"Audit file: {path}")
    print(f"Planner steps (records): {steps}")
    print(f"Unique screens explored (last row metric): {_last_unique_screens(path)}")
    print("\nSeverity tally:")
    for k, v in severity_counts.most_common():
        print(f"  {k}: {v}")
    print("\nAssessment codes (frequency):")
    for code, n in code_counts.most_common(args.top):
        print(f"  {code}: {n}")
    if highs:
        print(f"\nSteps flagged high severity (sample): {highs[:25]}")


def _last_unique_screens(path: Path) -> str:
    lines = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    for ln in reversed(lines):
        try:
            row = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if row.get("audit_schema"):
            continue
        v = row.get("unique_screen_hashes_seen")
        if v is not None:
            return str(v)
    return "n/a"


if __name__ == "__main__":
    main()
