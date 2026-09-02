#!/usr/bin/env python3
"""Summarize one LLM audit run for the 10-iteration debug loop."""
from __future__ import annotations

import json
import sys
from pathlib import Path


def latest_session_dir(logs_root: Path) -> Path | None:
    candidates = list(logs_root.glob("*_org.fdroid.fdroid/dynamic/llm/session_1"))
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime_ns, reverse=True)
    return candidates[0]


def summarize(session_dir: Path) -> dict:
    pkg = "org.fdroid.fdroid"
    meta_path = session_dir / f"{pkg}_dynamic_metadata.json"
    human_path = session_dir / f"{pkg}_human_ux_report.json"
    actions_path = session_dir / f"{pkg}_llm_actions.jsonl"

    out: dict = {"session_dir": str(session_dir)}
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        out.update(
            {
                "llm_status": meta.get("llm_status"),
                "simulation_status": meta.get("llm_simulation_status"),
                "simulation_detail": meta.get("llm_simulation_status_detail"),
                "human_ux_pass": meta.get("human_ux_overall_pass"),
                "actions_count": meta.get("llm_actions_count"),
                "frida_lines": meta.get("frida_lines"),
                "handoff_ok": (meta.get("llm_root_handoff") or {}).get("result", {}).get("ok"),
                "handoff_reason": (meta.get("llm_root_handoff") or {}).get("result", {}).get("reason"),
                "final_goals": meta.get("llm_ux_goals"),
            }
        )
        rh = meta.get("llm_root_handoff") or {}
        out["final_goal_index_hint"] = (rh.get("result") or {}).get("reason")

    if human_path.exists():
        human = json.loads(human_path.read_text(encoding="utf-8"))
        out["human_ux_overall_pass"] = human.get("human_ux_overall_pass")
        failed = [c["id"] for c in human.get("checks", []) if not c.get("passed")]
        out["failed_checks"] = failed

    phases: dict[str, int] = {}
    goal_idxs: dict[str, int] = {}
    kinds: dict[str, int] = {}
    contract_steps = 0
    route_steps = 0
    if actions_path.exists():
        for line in actions_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            ev = json.loads(line)
            ph = str(ev.get("pipeline_phase") or "none")
            phases[ph] = phases.get(ph, 0) + 1
            gi = ev.get("ux_goal_index")
            if gi is not None:
                goal_idxs[str(gi)] = goal_idxs.get(str(gi), 0) + 1
            kind = str(ev.get("execution_kind") or "none")
            kinds[kind] = kinds.get(kind, 0) + 1
            reason = str((ev.get("parsed_action") or {}).get("reason") or "")
            if reason.startswith("planner_contract_"):
                contract_steps += 1
            if reason.startswith("engine_route_"):
                route_steps += 1
        out["phases"] = phases
        out["goal_idxs"] = goal_idxs
        out["execution_kinds"] = kinds
        out["contract_steps"] = contract_steps
        out["route_steps"] = route_steps
        if goal_idxs:
            out["max_goal_index"] = max(int(k) for k in goal_idxs)

    return out


def main() -> None:
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
    logs = base / "logs"
    session = latest_session_dir(logs)
    if not session:
        print(json.dumps({"error": "no session found"}, indent=2))
        sys.exit(1)
    print(json.dumps(summarize(session), indent=2))


if __name__ == "__main__":
    main()
