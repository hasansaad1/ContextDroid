from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import IO, Any, Optional

from protocol_config import (
    ACTION_HISTORY_WINDOW,
    LLM_TEMPERATURE,
    MAX_AGENT_XML_TOKENS,
    OLLAMA_DEAD_AFTER_CONSECUTIVE_STEPS,
    OLLAMA_GENERATE_RETRIES,
    OLLAMA_GENERATE_RETRY_BASE_SEC,
    PARTIAL_AGENT_STUCK,
    PARTIAL_OLLAMA_UNAVAILABLE,
    REPETITION_THRESHOLD,
    REPETITION_WINDOW,
    STAGNATION_CONSECUTIVE_FOR_BACK,
    STAGNATION_CONSECUTIVE_FOR_BAILOUT,
    SESSION_TIMEOUT_MULTIPLIER,
)

from .actions import _effective_submit_search
from .goals import (
    _goal_needs_text_entry_field,
    _is_degenerate_transitions_goal,
    _single_typing_goal_substantiated,
)
from .config import (
    _FOREGROUND_DIALOG_PACKAGES,
    _FOREGROUND_TRANSIENT_PACKAGES,
    _STEP_DEBUG_PROMPT,
)

HUMAN_UX_CRITERIA_VERSION = "human_ux_v3"


def _severity_merge(sev_a: str, sev_b: str) -> str:
    order = {"info": 0, "medium": 1, "high": 2}
    return sev_a if order.get(sev_a, 0) >= order.get(sev_b, 0) else sev_b

def _compute_audit_assessment(
    *,
    pkg: str,
    foreground_pkg: Optional[str],
    proposal: dict[str, Any],
    executed: dict[str, Any],
    ok: bool,
    outcome: str,
    hash_before: str,
    hash_after: str,
    n_before: int,
    n_after: int,
) -> dict[str, Any]:
    """App-agnostic heuristic labels for offline review (not a ground-truth oracle)."""
    codes: list[str] = []
    sev = "info"
    prop_json = json.dumps(proposal, sort_keys=True, ensure_ascii=False)
    exec_json = json.dumps(executed, sort_keys=True, ensure_ascii=False)
    prop_reason = str(proposal.get("reason") or "")
    exec_reason = str(executed.get("reason") or "")
    engine_route_override = (
        exec_reason.startswith(
            ("engine_route_", "engine_fallback_", "engine_prose_spiral_", "engine_goal_")
        )
        or exec_reason == "engine_goal_status_satisfied"
    ) and prop_reason.startswith("planner_contract_")
    primary_controller_override = (
        exec_reason.startswith("engine_primary_")
        and prop_reason.startswith("planner_contract_")
    )
    if prop_json != exec_json and (primary_controller_override or engine_route_override):
        codes.append("engine_replaced_planner_contract_failure")
    elif prop_json != exec_json:
        codes.append("guard_modified_planner_output")

    if foreground_pkg and foreground_pkg != pkg:
        transient_ok = foreground_pkg in (
            _FOREGROUND_DIALOG_PACKAGES | _FOREGROUND_TRANSIENT_PACKAGES
        )
        if not transient_ok:
            codes.append("foreground_package_differs_from_target")
            sev = _severity_merge(sev, "medium")

    reason = str(executed.get("reason") or "")
    et = str(executed.get("action_type") or "wait")

    if reason == "unparseable_llm_output" or reason.startswith("planner_contract_"):
        codes.append("planner_returned_unusable_structure")
        sev = "high"
    if reason.startswith("guard_"):
        codes.append(reason)
        sev = _severity_merge(sev, "medium")
    if reason == "ollama_error":
        codes.append("planner_backend_error")
        sev = "high"
    if reason == "repetition_guard":
        codes.append("repetition_guard_triggered")
        sev = _severity_merge(sev, "medium")
    if reason == "skip_repeat_failed_action":
        codes.append("repeat_failed_action_skipped")

    if not ok:
        codes.append("action_execution_failed")
        sev = _severity_merge(sev, "high")
        if "target_not_found" in outcome or "tap_xy_failed" in outcome:
            codes.append("widget_missing_or_overlay_changed")

    if ok:
        if et == "tap" and hash_before == hash_after:
            codes.append("tap_ok_but_no_screen_delta")
            sev = _severity_merge(sev, "medium")
        if et == "swipe" and hash_before == hash_after:
            codes.append("swipe_ok_but_no_screen_delta")
            sev = _severity_merge(sev, "medium")
        if et == "input" and hash_before == hash_after and "text:" in outcome:
            codes.append("input_ok_but_no_screen_delta_maybe_keyboard_or_lazy_refresh")
        if et == "back":
            codes.append("back_nav_executed")

    if et == "wait" and reason != "ollama_error" and not reason.startswith("planner_contract_"):
        codes.append("no_direct_action_step")

    if et == "advance_goal":
        codes.append("goal_marker_advance_goal")

    if n_after == 0 and n_before > 0:
        codes.append("post_action_empty_interactive_list")

    return {"codes": codes, "severity": sev}

def _action_signature_for_guard(act: dict[str, Any]) -> str:
    payload: dict[str, Any] = {
        "action_type": act.get("action_type"),
        "target_resource_id": act.get("target_resource_id"),
        "target_content_desc": act.get("target_content_desc"),
        "x": act.get("x"),
        "y": act.get("y"),
    }
    if act.get("action_type") == "swipe":
        payload["x1"] = act.get("x1", act.get("x"))
        payload["y1"] = act.get("y1")
        payload["x2"] = act.get("x2", act.get("x"))
        payload["y2"] = act.get("y2")
        payload["duration_ms"] = act.get("duration_ms")
    if act.get("action_type") == "input":
        payload["text"] = act.get("text")
        # Signature reflects likely Enter behavior so repetition_guard catches retry-loops.
        es, _ = _effective_submit_search(act, [])
        payload["submit_search"] = es
    return json.dumps(payload, sort_keys=True)

def _json_equivalent(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return json.dumps(a or {}, sort_keys=True, ensure_ascii=False) == json.dumps(
        b or {}, sort_keys=True, ensure_ascii=False
    )


def _is_intentional_controller_execution(reason: str) -> bool:
    """Engine/primary-UX controller output is direct execution, not planner repair."""
    if reason.startswith("tap_repair_"):
        return False
    return reason.startswith(("engine_", "primary_ux_"))


def _execution_kind_for_step(
    *,
    pipeline_phase: str,
    proposal: dict[str, Any],
    executed: dict[str, Any],
    ok: bool,
    outcome: str,
) -> str:
    """Classify whether a step represents planner intent, repair, recovery, or blocked non-execution."""
    reason = str(executed.get("reason") or "")
    at = str(executed.get("action_type") or "wait")
    if pipeline_phase == "explore":
        if reason == "bfs_system_dialog_dismiss":
            return "dialog"
        if reason in (
            "bfs_return_to_hub",
            "bfs_avoid_back_loop",
            "bfs_leave_permission_overlay",
            "dialog_policy_recover_to_target",
        ):
            return "recovery"
        return "exploration"
    if reason in (
        "planner_target_not_visible",
        "guard_foreign_rid",
        "guard_invisible_tap_target",
        "guard_no_tap_target",
        "skip_repeat_failed_action",
        "repetition_guard",
        "unparseable_llm_output",
    ):
        return "blocked"
    if reason.startswith("planner_contract_"):
        return "blocked"
    if reason.startswith("guard_"):
        return "blocked"
    if reason.startswith("tap_repair_"):
        return "repaired"
    if _is_intentional_controller_execution(reason):
        return "direct"
    if at == "wait" and not ok:
        return "blocked"
    if "target_not_found" in str(outcome or "") or "fallback_rid_missing" in str(outcome or ""):
        return "blocked" if not ok else "repaired"
    if proposal and not _json_equivalent(proposal, executed):
        return "repaired"
    return "direct"

def _effective_execution_kind(ev: dict[str, Any]) -> str:
    """Recompute execution_kind from stored proposal/execute fields when available."""
    executed = ev.get("parsed_action") or {}
    if executed:
        return _execution_kind_for_step(
            pipeline_phase=str(ev.get("pipeline_phase") or ""),
            proposal=ev.get("model_proposal") or {},
            executed=executed,
            ok=bool(ev.get("action_success")),
            outcome=str(ev.get("action_outcome") or ""),
        )
    return str(ev.get("execution_kind") or "")


def _execution_counts_as_ux_progress(ev: dict[str, Any]) -> bool:
    kind = _effective_execution_kind(ev)
    if kind not in ("direct", "dialog"):
        return False
    pa = ev.get("parsed_action") or {}
    at = str(pa.get("action_type") or "")
    return at in ("tap", "input", "back", "swipe", "advance_goal") and bool(ev.get("action_success"))

def _event_progress_score(ev: dict[str, Any]) -> int:
    """Heuristic per-step progress score for loop quality gating."""
    if not _execution_counts_as_ux_progress(ev) and _effective_execution_kind(ev) not in ("exploration",):
        return 0
    pa = ev.get("parsed_action") or {}
    at = str(pa.get("action_type") or "wait")
    ok = bool(ev.get("action_success"))
    out = str(ev.get("action_outcome") or "")
    st = int(ev.get("stagnant_after_dump") or 0)
    if not ok:
        return 0
    if at == "advance_goal":
        return 3
    if at in ("tap", "input", "swipe"):
        # Penalize clearly mechanical/failed-move outcomes.
        bad = (
            "target_not_found" in out
            or "repetition_guard" in out
            or "skip_repeat_failed_action" in out
        )
        if bad:
            return 0
        # Low stagnation means the action stream is still producing movement.
        return 2 if st <= 1 else 1
    if at == "back":
        return 1 if st <= 1 else 0
    return 0

def _recent_progress_score(events: list[dict[str, Any]], *, window: int = 6) -> int:
    if not events:
        return 0
    return sum(_event_progress_score(ev) for ev in events[-window:])

def _required_goal_index_for_human_ux_pass(goal_count: int) -> int:
    """Minimum active-goal index that indicates more than token goal progress."""
    if goal_count <= 1:
        return 0
    if goal_count <= 3:
        return 1
    return min(goal_count - 1, max(2, (goal_count + 2) // 3))

def _is_intentional_controller_recovery(ev: dict[str, Any]) -> bool:
    """Successful engine/primary-UX substitutions are designed recovery, not guard failures."""
    if not ev.get("action_success"):
        return False
    pa = ev.get("parsed_action") or {}
    reason = str(pa.get("reason") or "")
    if reason.startswith(
        (
            "engine_route_",
            "engine_primary_",
            "engine_goal_",
            "engine_prose_spiral_",
            "engine_fallback_",
            "engine_all_wait_",
            "engine_empty_state_",
            "primary_ux_",
        )
    ):
        return True
    audit = ev.get("audit_assessment") or {}
    codes = {str(c) for c in (audit.get("codes") or [])}
    return "engine_replaced_planner_contract_failure" in codes


def _is_guard_or_planner_contract_issue(ev: dict[str, Any]) -> bool:
    if _is_intentional_controller_recovery(ev):
        return False
    kind = _effective_execution_kind(ev)
    pa = ev.get("parsed_action") or {}
    reason = str(pa.get("reason") or "")
    outcome = str(ev.get("action_outcome") or "")
    audit = ev.get("audit_assessment") or {}
    codes = {str(c) for c in (audit.get("codes") or [])}
    if reason in {
        "planner_target_not_visible",
        "guard_invisible_tap_target",
        "guard_foreign_widget_target",
        "unparseable_llm_output",
        "repetition_guard",
        "skip_repeat_failed_action",
    }:
        return True
    if reason.startswith("planner_contract_"):
        return True
    if reason.startswith("guard_"):
        return True
    if "target_not_found" in outcome or "fallback_rid_missing" in outcome:
        return True
    if kind == "blocked":
        return True
    if kind == "recovery":
        phase = str(ev.get("pipeline_phase") or "")
        return phase in ("execute", "primary_ux", "legacy")
    if kind == "repaired":
        if reason.startswith(("guard_", "planner_contract_", "planner_target_")):
            return True
        if str(pa.get("action_type") or "") == "wait":
            return True
        return bool(
            codes
            & {
                "guard_invisible_tap_target",
                "planner_returned_unusable_structure",
            }
        )
    return bool(
        codes
        & {
            "guard_invisible_tap_target",
            "planner_returned_unusable_structure",
        }
    )

def _human_ux_scored_events(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ux_events = [
        ev
        for ev in actions
        if str(ev.get("pipeline_phase") or "") in ("execute", "primary_ux", "legacy")
    ]
    return ux_events if ux_events else actions

def _human_ux_evaluate(
    *,
    actions: list[dict[str, Any]],
    ux_goals: list[str] | None,
    final_ux_goal_idx: int,
    llm_status: str,
) -> dict[str, Any]:
    """Post-session checks for human-plausible UX in simulation (heuristic, not usability lab)."""
    checks: list[dict[str, Any]] = []

    max_run = 0
    cur_run = 0
    last_sig: str | None = None
    for ev in actions:
        pa = ev.get("parsed_action") or {}
        if str(pa.get("action_type")) != "input":
            cur_run = 0
            last_sig = None
            continue
        sig = _action_signature_for_guard(pa)
        if sig == last_sig:
            cur_run += 1
        else:
            cur_run = 1
            last_sig = sig
        max_run = max(max_run, cur_run)
    # Modest repeats: repaired fallback query + lazy list refresh with small LLMs.
    no_excessive_repeat = max_run <= 4
    checks.append(
        {
            "id": "no_input_excessive_repeat",
            "passed": no_excessive_repeat,
            "detail": f"max_consecutive_identical_input={max_run} (fail if >4)",
        }
    )

    hashes: set[str] = set()
    for ev in actions:
        for key in ("screen_hash", "screen_hash_after"):
            h = ev.get(key)
            if h:
                hashes.add(str(h))
    n_act = len(actions)
    min_div_required = n_act >= 10
    explore_ok = len(hashes) >= 3 if min_div_required else True
    checks.append(
        {
            "id": "min_screen_diversity",
            "passed": explore_ok,
            "detail": f"unique_hashes={len(hashes)} actions={n_act}"
            + ("" if min_div_required else " (skipped_lt_10_steps)"),
        }
    )

    if ux_goals and len(ux_goals) == 1 and n_act >= 8:
        lone = ux_goals[0]
        if _is_degenerate_transitions_goal(lone):
            gp_ok = False
            gp_detail = f"degenerate_single_goal={lone!r}"
        elif _goal_needs_text_entry_field(lone) and not _single_typing_goal_substantiated(lone, actions):
            gp_ok = False
            gp_detail = "single_typing_goal_without_input_event"
        elif final_ux_goal_idx <= 0:
            gp_ok = False
            gp_detail = f"single_goal_unadvanced index={final_ux_goal_idx}"
        else:
            gp_ok = True
            gp_detail = f"single_goal_advanced index={final_ux_goal_idx}"
    elif ux_goals and len(ux_goals) > 1 and n_act >= 8:
        gp_ok = final_ux_goal_idx >= 1
        gp_detail = f"final_goal_index={final_ux_goal_idx} of {len(ux_goals)}"
    else:
        gp_ok = True
        gp_detail = "skipped_insufficient_goals_or_steps"
    checks.append({"id": "goal_plan_advances_legacy", "passed": gp_ok, "detail": gp_detail})

    scored_events = _human_ux_scored_events(actions)
    scored_count = len(scored_events)
    execution_kind_counts: dict[str, int] = {}
    for ev in scored_events:
        kind = _effective_execution_kind(ev) or "unclassified"
        execution_kind_counts[kind] = execution_kind_counts.get(kind, 0) + 1
    if ux_goals and len(ux_goals) == 1 and n_act >= 8:
        lone = ux_goals[0]
        if _is_degenerate_transitions_goal(lone):
            goal_progress_ok = False
            goal_progress_detail = f"degenerate_single_goal={lone!r}"
        elif _goal_needs_text_entry_field(lone) and not _single_typing_goal_substantiated(lone, actions):
            goal_progress_ok = False
            goal_progress_detail = "single_typing_goal_without_input_event"
        elif final_ux_goal_idx <= 0:
            goal_progress_ok = False
            goal_progress_detail = f"single_goal_unadvanced index={final_ux_goal_idx}"
        else:
            goal_progress_ok = True
            goal_progress_detail = f"single_goal_advanced index={final_ux_goal_idx}"
    elif ux_goals and len(ux_goals) > 1 and n_act >= 8:
        required_goal_idx = _required_goal_index_for_human_ux_pass(len(ux_goals))
        goal_progress_ok = final_ux_goal_idx >= required_goal_idx
        goal_progress_detail = (
            f"final_goal_index={final_ux_goal_idx} of {len(ux_goals)} "
            f"(required>={required_goal_idx})"
        )
    else:
        goal_progress_ok = True
        goal_progress_detail = "skipped_insufficient_goals_or_steps"
    checks.append(
        {
            "id": "meaningful_goal_progress",
            "passed": goal_progress_ok,
            "detail": goal_progress_detail,
        }
    )

    direct_action_types = {"tap", "input", "back", "swipe"}
    direct_actions = [
        ev
        for ev in scored_events
        if str((ev.get("parsed_action") or {}).get("action_type") or "") in direct_action_types
        and _execution_counts_as_ux_progress(ev)
    ]
    if scored_count >= 8:
        direct_ratio = len(direct_actions) / max(1, scored_count)
        direct_action_ok = direct_ratio >= 0.35
        direct_action_detail = (
            f"successful_direct_actions={len(direct_actions)} scored_events={scored_count} "
            f"ratio={direct_ratio:.2f} (required>=0.35)"
        )
    else:
        direct_action_ok = True
        direct_action_detail = "skipped_lt_8_scored_events"
    checks.append(
        {
            "id": "direct_action_ratio",
            "passed": direct_action_ok,
            "detail": direct_action_detail,
        }
    )

    guard_issue_count = sum(1 for ev in scored_events if _is_guard_or_planner_contract_issue(ev))
    if scored_count >= 8:
        guard_ratio = guard_issue_count / max(1, scored_count)
        guard_ok = guard_ratio <= 0.25
        guard_detail = (
            f"guard_or_contract_issues={guard_issue_count} scored_events={scored_count} "
            f"ratio={guard_ratio:.2f} (allowed<=0.25)"
        )
    else:
        guard_ok = True
        guard_detail = "skipped_lt_8_scored_events"
    checks.append(
        {
            "id": "guard_intervention_rate",
            "passed": guard_ok,
            "detail": guard_detail,
        }
    )

    unparseable_count = sum(
        1
        for ev in scored_events
        if (reason := str((ev.get("parsed_action") or {}).get("reason") or ""))
        and reason != "ollama_error"
        and (reason == "unparseable_llm_output" or reason.startswith("planner_contract_"))
    )
    parse_contract_ok = unparseable_count == 0
    checks.append(
        {
            "id": "planner_action_contract",
            "passed": parse_contract_ok,
            "detail": f"unparseable_action_steps={unparseable_count}",
        }
    )

    stuck_status = f"partial:{PARTIAL_AGENT_STUCK}"
    stuck = llm_status == stuck_status
    # Local models may hit stagnation bailout while still producing useful UX, but only with real task progress.
    pragmatic_recovery = (
        stuck
        and goal_progress_ok
        and direct_action_ok
        and guard_ok
        and parse_contract_ok
        and len(hashes) >= 3
        and n_act >= 15
    )
    session_clean = llm_status == "success"
    ux_sim_ok = session_clean or pragmatic_recovery
    checks.append(
        {
            "id": "ux_simulation_outcome",
            "passed": ux_sim_ok,
            "detail": (
                f"status={llm_status} strict_success={session_clean} "
                f"pragmatic_recovery={pragmatic_recovery}"
            ),
        }
    )

    mechanistic_pass = no_excessive_repeat and explore_ok
    behavior_pass = (
        gp_ok
        and goal_progress_ok
        and direct_action_ok
        and guard_ok
        and parse_contract_ok
    )
    overall_pass = mechanistic_pass and behavior_pass and ux_sim_ok

    return {
        "criteria_version": HUMAN_UX_CRITERIA_VERSION,
        "note": (
            "human_ux_overall_pass requires clean mechanics, meaningful goal progress, "
            "low guard intervention, valid planner action structure, and either full session success "
            "or pragmatic recovery."
        ),
        "checks": checks,
        "execution_kind_counts": dict(sorted(execution_kind_counts.items())),
        "human_ux_mechanistic_pass": mechanistic_pass,
        "human_ux_behavior_pass": behavior_pass,
        "human_ux_session_pass": session_clean,
        "human_ux_pragmatic_recovery": pragmatic_recovery,
        "human_ux_overall_pass": overall_pass,
    }

def _append_step_trace(
    handle: IO[str],
    *,
    step: int,
    elapsed: float,
    stagnant: int,
    element_count: int,
    screen_hash: str,
    prompt_hash: str,
    prompt: str,
    raw: str,
    action: dict[str, Any],
    ok: bool,
    outcome: str,
    planner_turn: int = 0,
    batch_index: int = 0,
    batch_size: int = 1,
    pipeline_phase: str = "",
    execution_kind: str = "",
) -> None:
    dash = "=" * 78
    h_short = screen_hash[:16] + ("..." if len(screen_hash) > 16 else "")
    raw_preview = raw if len(raw) <= 12000 else raw[:12000] + "\n... [truncated raw_response]"
    batch_note = ""
    if batch_size > 1 or planner_turn or pipeline_phase:
        batch_note = (
            f"  planner_turn={planner_turn}  batch={batch_index + 1}/{batch_size}"
            + (f"  phase={pipeline_phase}" if pipeline_phase else "")
            + (f"  execution_kind={execution_kind}" if execution_kind else "")
        )
    lines = [
        dash,
        f"STEP {step}  elapsed_sec={elapsed:.2f}  stagnant={stagnant}  "
        f"interactive_elements={element_count}  screen_hash={h_short}{batch_note}",
        f"prompt_sha256={prompt_hash}",
    ]
    if _STEP_DEBUG_PROMPT:
        lines.extend(["--- PROMPT ---", prompt if prompt else "<empty>", "--- END PROMPT ---"])
    lines.extend(
        [
            "--- raw model text ---",
            raw_preview,
            "--- parsed_action ---",
            json.dumps(action, ensure_ascii=False, indent=2),
            "--- execute ---",
            f"success={ok} outcome={outcome}",
            dash + "\n",
        ]
    )
    handle.write("\n".join(lines))
    handle.flush()
