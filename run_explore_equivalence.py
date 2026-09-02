#!/usr/bin/env python3
"""Run Step 5 explore equivalence corpus and print pass/fail per snapshot."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "extraction_pipeline"))

from llm_agent.explore_equivalence import run_snapshot
from llm_agent.explore_snapshot_corpus import build_equivalence_snapshot_corpus


def main() -> int:
    corpus = build_equivalence_snapshot_corpus()
    reports = [run_snapshot(s) for s in corpus]
    passed = sum(1 for r in reports if r.passed)
    failed = [r for r in reports if not r.passed]

    print(f"Explore equivalence: {passed}/{len(reports)} snapshots passed\n")
    by_cat: dict[str, list] = {}
    for r in reports:
        by_cat.setdefault(r.category, []).append(r)

    for cat in sorted(by_cat):
        print(f"## {cat}")
        for r in by_cat[cat]:
            mark = "PASS" if r.passed else "FAIL"
            print(f"  [{mark}] {r.snapshot_id}")
            if not r.passed:
                for err in r.errors:
                    print(f"         {err}")
            elif r.legacy_action.get("action_type"):
                a = r.legacy_action
                print(
                    f"         action={a.get('action_type')} reason={a.get('reason')} "
                    f"target=({a.get('x')},{a.get('y')})"
                )
        print()

    if failed:
        print("FAILED snapshots:")
        for r in failed:
            print(f"  - {r.snapshot_id}: {r.errors}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
