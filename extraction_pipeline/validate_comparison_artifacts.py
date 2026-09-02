#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Validate LLM/Monkey artifact parity in dataset_index.csv.")
    p.add_argument("--index", default="logs/dataset_index.csv", help="Path to dataset_index.csv")
    p.add_argument("--expected-sessions", type=int, default=3, help="Expected sessions per app per arm")
    p.add_argument(
        "--package",
        default="",
        help="If set, only validate this package_name (e.g. org.example.app).",
    )
    return p.parse_args()


def _dedupe_latest_session_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Keep one row per session_id (latest analysis_timestamp wins)."""
    best: dict[str, tuple[str, dict[str, str]]] = {}
    for row in rows:
        sid = (row.get("session_id") or "").strip()
        if not sid:
            continue
        ts = (row.get("analysis_timestamp") or "").strip()
        if sid not in best or ts >= best[sid][0]:
            best[sid] = (ts, row)
    return [pair[1] for pair in sorted(best.values(), key=lambda p: p[0])]


def main() -> None:
    args = parse_args()
    index_path = Path(args.index)
    if not index_path.exists():
        raise SystemExit(f"index not found: {index_path}")

    by_app_arm: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    arm_pat = re.compile(r"/dynamic/(llm|monkey)/session_(\d+)/")
    with index_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            pkg = (row.get("package_name") or "").strip()
            arm = (row.get("arm") or "").strip()
            if not arm or arm == "unknown":
                m = arm_pat.search((row.get("frida_csv_path") or "").strip())
                if m:
                    arm = m.group(1)
            arm = arm or "unknown"
            if not pkg:
                continue
            by_app_arm[(pkg, arm)].append(row)

    failures: list[str] = []
    packages = sorted({pkg for pkg, _ in by_app_arm.keys()})
    if (args.package or "").strip():
        want = args.package.strip()
        packages = [p for p in packages if p == want]
        if not packages:
            raise SystemExit(f"no rows for --package {want!r}")

    for pkg in packages:
        for arm in ("llm", "monkey"):
            rows = _dedupe_latest_session_rows(by_app_arm.get((pkg, arm), []))
            if len(rows) < args.expected_sessions:
                failures.append(f"{pkg} arm={arm}: expected {args.expected_sessions}, found {len(rows)}")
            for row in rows:
                status = (row.get("status") or "").strip().lower()
                for field in ("metadata_path",):
                    value = (row.get(field) or "").strip()
                    if not value or not Path(value).exists():
                        failures.append(f"{pkg} arm={arm} session={row.get('session_id','?')}: missing {field}")
                if status == "success":
                    for field in ("frida_log_path", "frida_csv_path", "frida_quality_path"):
                        value = (row.get(field) or "").strip()
                        if not value or not Path(value).exists():
                            failures.append(f"{pkg} arm={arm} session={row.get('session_id','?')}: missing {field}")

    if failures:
        print("comparison validation FAILED")
        for item in failures:
            print(f"- {item}")
        raise SystemExit(2)
    print("comparison validation OK")
    print(f"checked packages: {len(packages)}")


if __name__ == "__main__":
    main()
