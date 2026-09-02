#!/usr/bin/env python3
"""Offline heuristic evaluation of one LLM session (llm_actions.jsonl + optional metadata).

Emits JSON with per-step labels (good / mixed / poor) and aggregates for tuning loops.
This is not a UX oracle — rules favor observable progress and penalize obvious stall patterns.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _find_actions_path(session_dir: Path) -> Path:
    matches = sorted(session_dir.rglob("*_llm_actions.jsonl"))
    if not matches:
        raise SystemExit(f"No *_llm_actions.jsonl under {session_dir}")
    return matches[0]


def _load_metadata(session_dir: Path) -> dict[str, Any]:
    metas = sorted(session_dir.rglob("*_dynamic_metadata.json"))
    if not metas:
        return {}
    try:
        return json.loads(metas[0].read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _label_step(ev: dict[str, Any], prev_hash: str) -> tuple[str, list[str]]:
    pa = ev.get("parsed_action") or {}
    at = str(pa.get("action_type") or "wait")
    ok = ev.get("action_success")
    stagnant = int(ev.get("stagnant_after_dump") or 0)
    hb = str(ev.get("screen_hash") or "")
    ha = str(ev.get("screen_hash_after") or "")
    reasons: list[str] = []
    changed = bool(ha and hb and ha != hb)

    if at == "advance_goal" and ok:
        return "good", ["advance_goal_ok"]
    if at == "swipe" and ok and changed:
        return "good", ["swipe_screen_changed"]
    if at == "tap" and ok and changed:
        return "good", ["tap_screen_changed"]
    if at == "input" and ok:
        return "good" if changed else "mixed", ["input_ok"] + ([] if changed else ["input_no_hash_delta"])

    if at == "wait":
        if stagnant >= 4:
            return "poor", [f"wait_under_high_stagnant={stagnant}"]
        if stagnant >= 2:
            return "mixed", [f"wait_stagnant={stagnant}"]
        return "mixed", ["wait_low_stagnant"]

    if at == "back" and ok:
        return "mixed", ["back"]

    if ok is False:
        return "poor", [f"{at}_failed"]

    if at == "tap" and ok and not changed:
        return "mixed", ["tap_no_screen_change"]

    return "mixed", ["default"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("session_dir", type=Path, help="Directory containing session artifacts (recursive search)")
    ap.add_argument("--out", type=Path, default=None, help="Write JSON report here (default: session_dir/llm_eval_report.json)")
    args = ap.parse_args()
    root = args.session_dir.resolve()
    actions_path = _find_actions_path(root)
    meta = _load_metadata(root)

    events: list[dict[str, Any]] = []
    for line in actions_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        events.append(json.loads(line))

    prev_hash = ""
    steps: list[dict[str, Any]] = []
    for ev in events:
        label, reasons = _label_step(ev, prev_hash)
        pa = ev.get("parsed_action") or {}
        steps.append(
            {
                "step": ev.get("step"),
                "label": label,
                "reasons": reasons,
                "action_type": pa.get("action_type"),
                "phase": ev.get("pipeline_phase"),
                "ok": ev.get("action_success"),
                "stagnant_after": ev.get("stagnant_after_dump"),
            }
        )
        ha = ev.get("screen_hash_after")
        if isinstance(ha, str) and ha:
            prev_hash = ha
        else:
            prev_hash = str(ev.get("screen_hash") or prev_hash)

    def _count(lab: str) -> int:
        return sum(1 for s in steps if s["label"] == lab)

    hashes = {str(e.get("screen_hash") or "") for e in events if e.get("screen_hash")}
    hashes.discard("")
    goal_indices = [e.get("ux_goal_index") for e in events if "ux_goal_index" in e]
    last_goal_idx = max(goal_indices) if goal_indices else None

    report = {
        "actions_path": str(actions_path),
        "llm_status": meta.get("llm_status", ""),
        "analysis_status": meta.get("analysis_status", ""),
        "elapsed_sec": meta.get("elapsed_sec"),
        "llm_actions_count": meta.get("llm_actions_count", len(events)),
        "primary_ux_reason": meta.get("llm_primary_ux_fallback_reason", ""),
        "aggregates": {
            "steps": len(steps),
            "good": _count("good"),
            "mixed": _count("mixed"),
            "poor": _count("poor"),
            "distinct_screen_hashes": len(hashes),
            "last_ux_goal_index_observed": last_goal_idx,
        },
        "steps": steps,
    }
    out_path = args.out or (root / "llm_eval_report.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(out_path)


if __name__ == "__main__":
    main()
