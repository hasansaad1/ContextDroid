#!/usr/bin/env python3
"""Print summary for *_human_ux_report.json from run_llm_agent_session."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: report_human_ux.py <*_human_ux_report.json>", file=sys.stderr)
        sys.exit(2)
    path = Path(sys.argv[1])
    data = json.loads(path.read_text(encoding="utf-8"))
    ver = data.get("criteria_version", "?")
    print(f"Human UX criteria ({ver})")
    if data.get("note"):
        print(f"  note: {data['note']}")
    print(f"  mechanistic_pass: {data.get('human_ux_mechanistic_pass')}")
    print(f"  session_strict:   {data.get('human_ux_session_pass')} (llm_status == success)")
    print(f"  pragmatic_recovery: {data.get('human_ux_pragmatic_recovery')}")
    print(f"  overall_pass:     {data.get('human_ux_overall_pass')}")
    for c in data.get("checks", []):
        mark = "PASS" if c.get("passed") else "FAIL"
        print(f"  [{mark}] {c.get('id')}: {c.get('detail', '')}")


if __name__ == "__main__":
    main()
