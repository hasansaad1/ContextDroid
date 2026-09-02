#!/usr/bin/env python3
"""Build one Markdown file summarizing an LLM nav-first session for external review (e.g. Claude).

Reads (when present) in the session directory:
  - *_llm_actions.jsonl       — per-step phases, actions, outcomes, screen hashes
  - *_dynamic_metadata.json  — run summary, llm_status, paths, UX goals snippet
  - *_llm_ux_plan.json       — post-explore goals + screen_digest + primary_ux_fallback
  - *_llm_navigation_artifact.json — discovered screens + transitions
  - *_human_ux_report.json   — human UX rubric
  - *_llm_step_audit.jsonl   — optional: proposal vs executed, assessment (large)

Usage:
  python3 extraction_pipeline/export_llm_session_for_claude.py \\
    logs/985f5181d48b_org.fdroid.fdroid/dynamic/llm/session_1

  python3 extraction_pipeline/export_llm_session_for_claude.py SESSION_DIR -o my_report.md

Default output: <SESSION_DIR>/claude_session_report.md
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def _find_one(parent: Path, suffix: str) -> Path | None:
    matches = sorted(parent.glob(f"*{suffix}"))
    return matches[0] if matches else None


def _short_hash(h: str | None, n: int = 12) -> str:
    if not h:
        return ""
    return h[:n] + ("…" if len(h) > n else "")


def _action_one_line(pa: dict[str, Any]) -> str:
    if not pa:
        return ""
    at = str(pa.get("action_type") or "?")
    parts = [at]
    rid = str(pa.get("target_resource_id") or "").strip()
    if rid:
        parts.append(rid.split("/")[-1][:48])
    cd = str(pa.get("target_content_desc") or "").strip()
    if cd:
        parts.append(cd[:40])
    tx = pa.get("text")
    if tx is not None and str(tx).strip():
        parts.append(f"text={str(tx).strip()[:32]}")
    r = str(pa.get("reason") or "").strip()
    if r:
        parts.append(r[:48])
    return " · ".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Export LLM session to a single Markdown report.")
    parser.add_argument("session_dir", type=Path, help="Directory containing *_llm_actions.jsonl (e.g. .../session_1)")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Output Markdown path (default: <session_dir>/claude_session_report.md)",
    )
    parser.add_argument(
        "--max-raw-chars",
        type=int,
        default=1200,
        help="Max chars per audit raw_response_preview block (0=omit audit body)",
    )
    args = parser.parse_args()
    session_dir = args.session_dir.resolve()
    if not session_dir.is_dir():
        raise SystemExit(f"Not a directory: {session_dir}")

    actions_path = _find_one(session_dir, "_llm_actions.jsonl")
    if not actions_path:
        raise SystemExit(f"No *_llm_actions.jsonl under {session_dir}")

    meta_path = _find_one(session_dir, "_dynamic_metadata.json")
    plan_path = _find_one(session_dir, "_llm_ux_plan.json")
    nav_path = _find_one(session_dir, "_llm_navigation_artifact.json")
    human_path = _find_one(session_dir, "_human_ux_report.json")
    audit_path = _find_one(session_dir, "_llm_step_audit.jsonl")

    meta: dict[str, Any] = {}
    if meta_path:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    plan: dict[str, Any] = {}
    if plan_path:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    nav: dict[str, Any] = {}
    if nav_path:
        nav = json.loads(nav_path.read_text(encoding="utf-8"))
    human: dict[str, Any] = {}
    if human_path:
        human = json.loads(human_path.read_text(encoding="utf-8"))

    events: list[dict[str, Any]] = []
    for line in actions_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    by_phase: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        ph = str(ev.get("pipeline_phase") or "unknown")
        by_phase[ph].append(ev)

    out_path = args.output
    if out_path is None:
        out_path = session_dir / "claude_session_report.md"
    else:
        out_path = out_path.resolve()

    lines: list[str] = []
    pkg = meta.get("package_name", actions_path.stem.split("_")[0] if "_" in actions_path.stem else "?")

    lines.append(f"# LLM session report: `{pkg}`")
    lines.append("")
    lines.append("## Paths")
    lines.append(f"- Session directory: `{session_dir}`")
    lines.append(f"- Actions: `{actions_path}`")
    if meta_path:
        lines.append(f"- Metadata: `{meta_path}`")
    if plan_path:
        lines.append(f"- UX plan: `{plan_path}`")
    if nav_path:
        lines.append(f"- Navigation artifact: `{nav_path}`")
    if human_path:
        lines.append(f"- Human UX: `{human_path}`")
    if audit_path:
        lines.append(f"- Step audit: `{audit_path}`")
    lines.append("")

    lines.append("## Run summary (metadata)")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    for key in (
        "duration_sec",
        "analysis_status",
        "analysis_exit_code",
        "llm_status",
        "llm_actions_count",
        "elapsed_sec",
        "planner_model",
        "llm_primary_ux_fallback_reason",
        "frida_lines",
        "human_ux_overall_pass",
        "human_ux_mechanistic_pass",
        "session_id",
    ):
        lines.append(f"| {key} | {meta.get(key, '')} |")
    if meta.get("llm_primary_ux_fallback_spec"):
        spec = str(meta["llm_primary_ux_fallback_spec"])
        lines.append("")
        lines.append("### Primary UX mission (metadata)")
        lines.append(spec[:4000] + ("…" if len(spec) > 4000 else ""))
    lines.append("")

    if human:
        criteria_version = str(human.get("criteria_version") or "unknown")
        lines.append(f"## Human UX rubric (`{criteria_version}`)")
        lines.append(f"- **overall_pass:** {human.get('human_ux_overall_pass')}")
        lines.append(f"- **mechanistic_pass:** {human.get('human_ux_mechanistic_pass')}")
        lines.append(f"- **behavior_pass:** {human.get('human_ux_behavior_pass')}")
        lines.append(f"- **session_pass:** {human.get('human_ux_session_pass')}")
        lines.append("")
        lines.append("| Check | Passed | Detail |")
        lines.append("| --- | --- | --- |")
        for c in human.get("checks", []):
            lines.append(
                f"| {c.get('id', '')} | {c.get('passed', '')} | {str(c.get('detail', '')).replace('|', '\\|')} |"
            )
        lines.append("")

    goals = plan.get("goals") or meta.get("llm_ux_goals") or []
    if goals:
        lines.append("## Post-explore UX goals")
        for i, g in enumerate(goals, start=1):
            lines.append(f"{i}. {g}")
        lines.append("")

    digest = plan.get("screen_digest") or {}
    if isinstance(digest, dict) and digest:
        lines.append("## Screen digest (hash prefix → hint)")
        for h in sorted(digest.keys()):
            lines.append(f"- `{_short_hash(h, 16)}` → {digest[h]}")
        lines.append("")

    if nav.get("transitions"):
        lines.append("## Navigation transitions (first 40)")
        lines.append("| Step | From | To | Action | OK |")
        lines.append("| --- | --- | --- | --- | --- |")
        for tr in nav["transitions"][:40]:
            act = tr.get("action") or {}
            al = _action_one_line(act) if isinstance(act, dict) else str(act)
            lines.append(
                f"| {tr.get('step', '')} | `{_short_hash(str(tr.get('from') or ''), 12)}` | "
                f"`{_short_hash(str(tr.get('to') or ''), 12)}` | {al.replace('|', '\\|')} | {tr.get('ok', '')} |"
            )
        lines.append("")

    phase_order = ["explore", "execute", "primary_ux", "legacy", "unknown"]
    lines.append("## Per-phase step log")
    lines.append("")
    for ph in phase_order:
        rows = by_phase.get(ph, [])
        if not rows:
            continue
        ok = sum(1 for r in rows if r.get("action_success"))
        lines.append(f"### Phase: `{ph}` ({len(rows)} steps, {ok} success)")
        lines.append("")
        lines.append(
            "| # | step | planner_turn | action | success | outcome | screen_before | screen_after | notes |"
        )
        lines.append("| --- | ---: | ---: | --- | --- | --- | --- | --- | --- |")
        for i, ev in enumerate(rows, start=1):
            pa = ev.get("parsed_action") or {}
            notes = []
            if ev.get("ux_goal_index") is not None:
                notes.append(f"goal_idx={ev.get('ux_goal_index')}")
            if ev.get("ux_goal_active"):
                notes.append(str(ev.get("ux_goal_active"))[:40])
            if ev.get("batch_size", 1) and ev.get("batch_size", 1) > 1:
                notes.append(f"batch {int(ev.get('batch_index', 0)) + 1}/{ev.get('batch_size')}")
            line = (
                f"| {i} | {ev.get('step', '')} | {ev.get('planner_turn', '')} | "
                f"{_action_one_line(pa).replace('|', '\\|')} | {ev.get('action_success', '')} | "
                f"{str(ev.get('action_outcome', '') or '')[:80].replace('|', '\\|')} | "
                f"`{_short_hash(str(ev.get('screen_hash') or ''), 12)}` | "
                f"`{_short_hash(str(ev.get('screen_hash_after') or ''), 12)}` | "
                f"{'; '.join(notes).replace('|', '\\|')} |"
            )
            lines.append(line)
        lines.append("")

    if audit_path and args.max_raw_chars > 0:
        lines.append("## Audit excerpts (execute / primary_ux only, truncated)")
        lines.append("")
        n = 0
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("audit_schema"):
                continue
            ph = str(row.get("pipeline_phase") or "")
            if ph not in ("execute", "primary_ux"):
                continue
            prev = str(row.get("raw_response_preview") or "")
            if not prev:
                continue
            if len(prev) > args.max_raw_chars:
                prev = prev[: args.max_raw_chars] + "\n… [truncated]"
            lines.append(f"### Audit step {row.get('step')} ({ph})")
            lines.append("**Proposal vs executed**")
            lines.append("```json")
            lines.append(json.dumps({"proposal": row.get("model_proposal"), "executed": row.get("executed_action")}, indent=2)[:8000])
            lines.append("```")
            lines.append("**Raw model preview**")
            lines.append("```")
            lines.append(prev)
            lines.append("```")
            lines.append("")
            n += 1
            if n >= 25:
                lines.append("*… further audit rows omitted (cap 25).*")
                break

    lines.append("---")
    lines.append("*Generated by `extraction_pipeline/export_llm_session_for_claude.py`.*")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(out_path)


if __name__ == "__main__":
    main()
