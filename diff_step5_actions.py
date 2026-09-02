#!/usr/bin/env python3
"""Diff Step 5 before/after llm_actions.jsonl (behavioral equivalence check)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TARGETS = [
    "ch.famoser.mensa",
    "ch.protonvpn.android",
    "app.govroam.getgovroam",
    "at.krixec.ied",
    "code.alimiracle.image_meta_cleaner",
]

SKIP_KEYS = frozenset({"ts_epoch_ms", "planner_turn", "batch_index"})


def find_log(phase: str, pkg: str) -> Path | None:
    base = ROOT / "logs/step5_verify" / phase / pkg.replace(".", "_")
    hits = [p for p in base.glob(f"**/{pkg}_llm_actions.jsonl") if p.stat().st_size > 0]
    return sorted(hits, key=lambda p: p.stat().st_mtime, reverse=True)[0] if hits else None


def load_actions(path: Path) -> list[dict]:
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def step_signature(row: dict) -> dict:
    pa = row.get("parsed_action") or {}
    counts = (row.get("explore_candidate_counts") or {}) if row.get("pipeline_phase") == "explore" else {}
    sig = {
        "step": row.get("step"),
        "phase": row.get("pipeline_phase"),
        "action_type": pa.get("action_type"),
        "reason": pa.get("reason"),
        "target_resource_id": pa.get("target_resource_id"),
        "target_content_desc": pa.get("target_content_desc"),
        "text": pa.get("text"),
        "x": pa.get("x"),
        "y": pa.get("y"),
        "action_success": row.get("action_success"),
        "screen_hash": row.get("screen_hash"),
        "screen_hash_after": row.get("screen_hash_after"),
    }
    if counts:
        sig["buckets"] = {
            k: counts.get(k)
            for k in ("nav_cands", "other_cands", "expand_cands", "tab_cands", "skipped_interactive")
        }
    return sig


def compare_pkg(pkg: str) -> list[str]:
    before = find_log("before", pkg)
    after = find_log("after", pkg)
    lines: list[str] = []
    if before is None or after is None:
        lines.append(f"{pkg}: MISSING before={before} after={after}")
        return lines
    b = load_actions(before)
    a = load_actions(after)
    if len(b) != len(a):
        lines.append(f"{pkg}: step count {len(b)} vs {len(a)}")
    n = max(len(b), len(a))
    diffs = 0
    for i in range(n):
        sb = step_signature(b[i]) if i < len(b) else None
        sa = step_signature(a[i]) if i < len(a) else None
        if sb != sa:
            diffs += 1
            lines.append(f"{pkg} step {i+1}:")
            lines.append(f"  before: {json.dumps(sb, sort_keys=True)}")
            lines.append(f"  after:  {json.dumps(sa, sort_keys=True)}")
    if diffs == 0 and len(b) == len(a):
        lines.append(f"{pkg}: IDENTICAL ({len(b)} steps)")
    return lines


def main() -> int:
    all_lines: list[str] = []
    failed = False
    for pkg in TARGETS:
        pkg_lines = compare_pkg(pkg)
        all_lines.extend(pkg_lines)
        if any("IDENTICAL" not in ln for ln in pkg_lines if pkg in ln and "MISSING" not in ln):
            if any("step " in ln for ln in pkg_lines):
                failed = True
        if any("MISSING" in ln for ln in pkg_lines):
            failed = True
    report = ROOT / "logs/step5_verify/diff_report.txt"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("\n".join(all_lines) + "\n", encoding="utf-8")
    print("\n".join(all_lines))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
