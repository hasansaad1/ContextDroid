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

from .action_model import _action_signature_for_candidate, _nav_target_key
from .actions import _execute_action, _guard_planner_action, _primary_ux_controller_action, _repair_input_action_for_execution, _repair_tap_action_for_execution, _sanitize_primary_ux_action, _structured_execute_target_rejection
from .audit import _action_signature_for_guard, _append_step_trace, _compute_audit_assessment, _execution_counts_as_ux_progress, _execution_kind_for_step, _human_ux_evaluate, _recent_progress_score
from .device import (
    _attempt_foreground_recovery_before_abort,
    _bring_target_foreground,
    _foreground_package,
    _foreground_acceptable,
    _hierarchy_dominant_foreign_package,
    _recover_foreground_if_needed,
    _should_recover_from_foreign_app,
    _try_dismiss_permission_overlay,
    foreground_mismatch_limit,
    strict_foreground_enabled,
)
from pipeline_errors import AnalysisFailure
from .dialogs import (
    _action_is_permission_risk,
    _bfs_mark_permission_risk_if_triggered,
    _hierarchy_shows_permission_dialog,
    _package_is_permission_dialog_surface,
)
from .explore_policy import DEFAULT_EXPLORE_STRATEGY, ExploreState, ExploreTurnInput
from .explore_instrumentation import (
    build_explore_candidate_instrumentation,
    explore_input_effective_after_action,
    explore_tier_index_for_reason,
    frida_log_byte_offset,
    is_explore_recovery_action,
)
from .goals import (
    _action_nav_token,
    _derive_app_screen_state,
    _finalize_post_explore_goals,
    _goal_execute_status,
    _goal_is_forward,
    _goal_needs_text_entry_field,
    _is_degenerate_transitions_goal,
    _plan_ux_goals,
    _single_typing_goal_substantiated,
    _typing_goal_recently_satisfied,
)
from .handoff import _capture_execute_root_reference, _recover_empty_execute_screen, _restore_execute_root_screen, _root_handoff_recovery_actions, _screen_is_valid_execute_root
from .navigation import (
    _action_is_search_like,
    _bfs_tap_triggers_interior_expand,
    _build_navigation_artifact,
    _build_route_aware_goals,
    _format_navigation_digest,
    _nav_graph_record_transition,
    _plan_execution_goals_from_digest,
    _tap_goals_from_nav_graph,
    _text_entry_probe_field_key,
)
from .planner import _ollama_generate_with_retries, _parse_actions_list
from .prompts import _build_explore_prompt, _build_primary_ux_prompt, _build_prompt, _derive_primary_ux_micro_intent, _merge_primary_ux_into_plan, _plan_primary_app_ux
from .routing import _execute_engine_fallback_action, _route_controller_action_for_goal
from .screen import _allowed_resource_ids_from_elements, _filter_widgets_for_target, _screen_digest_hint, _screen_hash, _screen_is_empty_state, _screen_root_signature, dump_clean_screen
from .config import (
    PARTIAL_BAD_HANDOFF,
    PARTIAL_EMPTY_EXECUTE,
    PARTIAL_EXPLORE_NON_NAVIGABLE,
    _AUDIT_POST_ACTION_SLEEP_SEC,
    _AUDIT_SESSION,
    _BATCH_ACTIONS_MAX,
    _BFS_INTERIOR_EXPAND_BUDGET,
    _BFS_EXPAND_STALL_LIMIT_PER_SCREEN,
    _DEFAULT_PRIMARY_UX_TEXT,
    _DIALOG_STUCK_RECOVERY_STREAK,
    _EMPTY_EXECUTE_RECOVERY_ATTEMPTS,
    _EXECUTE_ENGINE_ONLY,
    _EXECUTE_UX_BATCH_MAX,
    _EXPLORE_RATIO,
    _EXPLORE_NON_NAVIGABLE_STREAK_LIMIT,
    _FOREGROUND_STUCK_SURFACES,
    _LLM_TEMPERATURE_RUNTIME,
    _NAV_DIGEST_MAX_SCREENS,
    _NAV_FIRST_PIPELINE,
    _OLLAMA_GENERATE_TIMEOUT_SEC,
    _POST_ACTION_SETTLE_SEC,
    _POST_EXPLORE_GOALS_MAX,
    _PRIMARY_UX_BLEND_AFTER_GOAL_INDEX,
    _PRIMARY_UX_BLEND_AFTER_POST_NAV_MIN_SEC,
    _PRIMARY_UX_BLEND_AFTER_POST_NAV_RATIO,
    _PRIMARY_UX_BLEND_MIN_GOAL_INDEX_FOR_TIME,
    _PRIMARY_UX_SPARSE_GOALS_THRESHOLD,
    _PRIMARY_UX_FALLBACK,
    _PRIMARY_UX_MIN_WINDOW_SEC,
    _REPETITION_GUARD_USE_BACK,
    _REP_THR,
    _REP_WIN,
    _ROOT_HANDOFF_FORCE_STOP,
    _ROOT_HANDOFF_RELAUNCH,
    _SESSION_TIMEOUT_MULTIPLIER,
    _SLIM_ACTION_LOG,
    _STAGNATION_INJECT_BACK,
    _STAG_BACK,
    _STAG_BAILOUT,
    _STEP_DEBUG,
    _STICKY_FOREGROUND,
    _USE_GOAL_PLAN,
    _effective_primary_blend_after_sec,
    _effective_primary_blend_goal_index,
    _explore_until_seconds,
    _primary_blend_after_sec_for_goals,
)
from safety.device_guard import raise_if_watchdog_failed


def run_llm_agent_session(
    adb_bin: str,
    app_context: dict[str, Any],
    output_dir: Path,
    duration_sec: int,
    ollama_model: str,
    ollama_endpoint: str,
    timeout_sec: int | None = None,
    healthcheck_cb: Any | None = None,
) -> dict[str, Any]:
    action_log = output_dir / f"{app_context['package_name']}_llm_actions.jsonl"
    session_wall_started = time.time()
    actions: list[dict[str, Any]] = []
    last_failed_signature = ""
    failed_once = set()
    stagnant = 0
    last_hash = ""
    status = "success"
    action_model = ollama_model
    planner_model = os.environ.get("CONTEXTDROID_LLM_PLANNER_MODEL", "").strip() or action_model
    max_runtime = timeout_sec if timeout_sec is not None else duration_sec * _SESSION_TIMEOUT_MULTIPLIER
    login_cue_steps = 0
    webview_dominant = False
    ollama_fail_steps = 0
    primary_fallback_active = False
    primary_ux_tap_pick_index = 0
    primary_fallback_spec = ""
    primary_fallback_reason = ""
    primary_micro_intent: dict[str, Any] = {}
    primary_stuck_escape_used = False
    all_ux_goals_done = False
    ux_goal_routes: list[dict[str, Any]] = []
    goal_blocked_turns = 0
    explore_non_navigable_streak = 0
    post_nav_execute_started: float | None = None
    root_screen_hash = ""
    root_screen_signature = ""
    root_screen_hint = ""
    root_screen_source = ""
    root_handoff_info: dict[str, Any] = {}
    root_handoff_done = False
    empty_execute_recovery_count = 0
    invalid_target_count = 0
    execute_planner_failure_streak = 0
    last_active_nav_token = ""
    simulation_status = "not_started"
    simulation_status_detail = "no_execute_actions"
    data_quality_status = "pending_parse_quality_gate"

    model_info = {}
    try:
        req = urllib.request.Request(
            ollama_endpoint.rstrip("/") + "/api/show",
            data=json.dumps({"model": action_model}).encode("utf-8"),
            method="POST",
        )
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=30) as resp:
            model_info = json.loads(resp.read().decode("utf-8", errors="ignore"))
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        model_info = {"model": action_model}
    planner_model_info = model_info
    if planner_model != ollama_model:
        try:
            req = urllib.request.Request(
                ollama_endpoint.rstrip("/") + "/api/show",
                data=json.dumps({"model": planner_model}).encode("utf-8"),
                method="POST",
            )
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=30) as resp:
                planner_model_info = json.loads(resp.read().decode("utf-8", errors="ignore"))
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
            planner_model_info = {"model": planner_model}

    pkg = str(app_context["package_name"])
    frida_log_path = output_dir / f"{pkg}_frida.jsonl"
    ux_goals: list[str] | None = None
    ux_goal_idx = 0
    execute_replan_alert = ""
    ux_plan_path: Path | None = None
    if _USE_GOAL_PLAN or _NAV_FIRST_PIPELINE:
        ux_plan_path = output_dir / f"{app_context['package_name']}_llm_ux_plan.json"

    if _USE_GOAL_PLAN and not _NAV_FIRST_PIPELINE:
        ux_goals = _plan_ux_goals(app_context, planner_model, ollama_endpoint)
        assert ux_plan_path is not None
        ux_plan_path.write_text(
            json.dumps({"goals": ux_goals, "pipeline": "pre_plan"}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logging.info("UX goal plan (%d goals): %s", len(ux_goals), ux_goals)

    exploration_digest: dict[str, str] = {}
    nav_visited_counts: dict[str, int] = {}
    nav_transitions: list[dict[str, Any]] = []
    explore_state = ExploreState()
    explore_strategy = DEFAULT_EXPLORE_STRATEGY
    nav_graph = explore_state.nav_graph
    bfs_expand_stall_by_screen: dict[str, int] = {}
    nav_plan_ready = not _NAV_FIRST_PIPELINE
    explore_until_sec = _explore_until_seconds(duration_sec)
    primary_blend_after_sec = _effective_primary_blend_after_sec(duration_sec)
    planner_turn_id = 0
    if _NAV_FIRST_PIPELINE:
        logging.info(
            "Nav-first timing: duration_sec=%s explore_until_sec=%.1f (ratio=%s, EXECUTE_RESERVE env optional); "
            "primary_ux_blend_after_goal_index=%s blend_after_post_nav_sec=%s "
            "blend_min_goal_index_for_time=%s post_explore_goals_max=%s "
            "blend_after_post_nav_ratio=%s blend_after_post_nav_min_sec=%s primary_ux_min_window_sec=%s",
            duration_sec,
            explore_until_sec,
            _EXPLORE_RATIO,
            _PRIMARY_UX_BLEND_AFTER_GOAL_INDEX,
            primary_blend_after_sec,
            _PRIMARY_UX_BLEND_MIN_GOAL_INDEX_FOR_TIME,
            _POST_EXPLORE_GOALS_MAX,
            _PRIMARY_UX_BLEND_AFTER_POST_NAV_RATIO,
            _PRIMARY_UX_BLEND_AFTER_POST_NAV_MIN_SEC,
            _PRIMARY_UX_MIN_WINDOW_SEC,
        )

    trace_path_obj: Path | None = None
    trace_f: IO[str] | None = None
    if _STEP_DEBUG:
        trace_path_obj = output_dir / f"{app_context['package_name']}_llm_step_trace.txt"
        trace_f = trace_path_obj.open("w", encoding="utf-8")
        trace_f.write(
            "# LLM step-by-step trace (CONTEXTDROID_LLM_STEP_DEBUG=1)\n"
            f"# action_model={ollama_model} planner_model={planner_model} endpoint={ollama_endpoint} duration_sec={duration_sec}\n"
            f"# Pair with JSONL: {action_log.name}\n"
            "# Set CONTEXTDROID_LLM_STEP_DEBUG_PROMPT=1 to embed full prompts (large).\n\n"
        )
        trace_f.flush()

    pkg = app_context["package_name"]
    nav_artifact_path = output_dir / f"{pkg}_llm_navigation_artifact.json"
    step_idx = 0
    foreground_recoveries = 0
    max_foreground_recoveries = 48
    foreign_dialog_streak = 0
    foreground_mismatch_streak = 0
    seen_hashes: set[str] = set()
    audit_path_obj: Path | None = None
    audit_f: IO[str] | None = None
    if _AUDIT_SESSION:
        audit_path_obj = output_dir / f"{pkg}_llm_step_audit.jsonl"
        audit_f = audit_path_obj.open("w", encoding="utf-8")
        audit_f.write(
            json.dumps(
                {
                    "audit_schema": "contextdroid_llm_step_audit_v1",
                    "package_name": pkg,
                    "note": "Heuristic assessment codes — offline review only, not a UX oracle.",
                },
                ensure_ascii=False,
            )
            + "\n"
        )
        audit_f.flush()

    root_reference = _capture_execute_root_reference(adb_bin, pkg)
    simulation_started = time.time()
    infra_setup_sec = simulation_started - session_wall_started
    logging.info(
        "Simulation timer started after root capture (infra_setup_sec=%.1f).",
        infra_setup_sec,
    )
    if root_reference.get("ok"):
        root_screen_hash = str(root_reference.get("screen_hash") or "")
        root_screen_signature = str(root_reference.get("root_signature") or "")
        root_screen_hint = str(root_reference.get("root_hint") or "")
        root_screen_source = "launcher_root_start"
        logging.info(
            "Captured canonical navigation root hash=%s signature=%s hint=%s",
            root_screen_hash[:16],
            root_screen_signature[:16],
            root_screen_hint[:180],
        )
    else:
        logging.warning(
            "Could not capture canonical navigation root before explore (%s); "
            "execute handoff will use no-reference validation.",
            root_reference.get("reason") or "unknown",
        )

    try:
        with action_log.open("w", encoding="utf-8") as out:
            while True:
                elapsed = time.time() - simulation_started
                if elapsed >= duration_sec:
                    break
                if time.time() - session_wall_started >= max_runtime:
                    status = "partial:timeout"
                    break
                now = time.time()
                raise_if_watchdog_failed()
                if healthcheck_cb is not None:
                    # Healthcheck failures are part of session quality semantics.
                    # Let caller-defined callback raise so the run can be classified
                    # explicitly rather than silently continuing with dead telemetry.
                    healthcheck_cb()
                if (
                    _STICKY_FOREGROUND
                    and foreground_recoveries < max_foreground_recoveries
                    and _recover_foreground_if_needed(adb_bin, pkg)
                ):
                    foreground_recoveries += 1
                    foreground_mismatch_streak = 0
                    stagnant = 0
                    last_hash = ""
                fg_now = _foreground_package(adb_bin)
                if strict_foreground_enabled():
                    if not _foreground_acceptable(pkg, fg_now):
                        recovered_fg = False
                        if (
                            _STICKY_FOREGROUND
                            and foreground_recoveries < max_foreground_recoveries
                        ):
                            recovered_fg = _attempt_foreground_recovery_before_abort(
                                adb_bin, pkg, fg=fg_now
                            )
                            if recovered_fg:
                                foreground_recoveries += 1
                                foreground_mismatch_streak = 0
                                stagnant = 0
                                last_hash = ""
                                continue
                        foreground_mismatch_streak += 1
                        if foreground_mismatch_streak >= foreground_mismatch_limit():
                            logging.error(
                                "Foreground mismatch persisted (%s steps, fg=%s target=%s); stopping session.",
                                foreground_mismatch_streak,
                                fg_now or "<unknown>",
                                pkg,
                            )
                            status = "partial:foreground_mismatch"
                            break
                    else:
                        foreground_mismatch_streak = 0
                if (
                    fg_now
                    and fg_now != pkg
                    and _package_is_permission_dialog_surface(fg_now)
                    and _try_dismiss_permission_overlay(adb_bin, pkg)
                ):
                    stagnant = 0
                    last_hash = ""
                    continue
                if fg_now in _FOREGROUND_STUCK_SURFACES and fg_now != pkg:
                    foreign_dialog_streak += 1
                else:
                    foreign_dialog_streak = 0
                if (
                    _STICKY_FOREGROUND
                    and fg_now is not None
                    and fg_now in _FOREGROUND_STUCK_SURFACES
                    and fg_now != pkg
                    and foreign_dialog_streak >= _DIALOG_STUCK_RECOVERY_STREAK
                    and foreground_recoveries < max_foreground_recoveries
                ):
                    logging.warning(
                        "Foreign surface %s persisted for %d turns; force-returning to target %s.",
                        fg_now,
                        foreign_dialog_streak,
                        pkg,
                    )
                    _bring_target_foreground(adb_bin, pkg)
                    foreground_recoveries += 1
                    foreground_mismatch_streak = 0
                    foreign_dialog_streak = 0
                    stagnant = 0
                    last_hash = ""
                elements, _, raw_xml = dump_clean_screen(adb_bin)
                elements = _filter_widgets_for_target(elements, pkg)
                if (
                    _STICKY_FOREGROUND
                    and foreground_recoveries < max_foreground_recoveries
                ):
                    hier_pkg = _hierarchy_dominant_foreign_package(raw_xml, pkg)
                    if hier_pkg and _should_recover_from_foreign_app(pkg, hier_pkg):
                        logging.warning(
                            "Window hierarchy dominated by %s while target is %s; re-launching target "
                            "(dumpsys focus can lag behind Settings / system UI).",
                            hier_pkg,
                            pkg,
                        )
                        _bring_target_foreground(adb_bin, pkg)
                        foreground_recoveries += 1
                        foreground_mismatch_streak = 0
                        foreign_dialog_streak = 0
                        stagnant = 0
                        last_hash = ""
                        elements, _, raw_xml = dump_clean_screen(adb_bin)
                        elements = _filter_widgets_for_target(elements, pkg)
                screen_hash = _screen_hash(elements)
                if not root_screen_hash and not actions:
                    root_ok, _root_reason = _screen_is_valid_execute_root(
                        elements, raw_xml=raw_xml, target_pkg=pkg
                    )
                    if root_ok:
                        root_screen_hash = screen_hash
                        root_screen_signature = _screen_root_signature(elements, pkg)
                        root_screen_hint = _screen_digest_hint(elements)
                        root_screen_source = "initial_observation"
                        logging.info(
                            "Captured execute root/home screen from initial observation hash=%s "
                            "signature=%s hint=%s",
                            root_screen_hash[:16],
                            root_screen_signature[:16],
                            root_screen_hint[:180],
                        )
                if (
                    screen_hash
                    and screen_hash not in exploration_digest
                    and len(exploration_digest) < _NAV_DIGEST_MAX_SCREENS
                ):
                    exploration_digest[screen_hash] = _screen_digest_hint(elements)
                if screen_hash:
                    nav_visited_counts[screen_hash] = nav_visited_counts.get(screen_hash, 0) + 1
                if _AUDIT_SESSION and not actions:
                    seen_hashes.add(screen_hash)
                if elements:
                    webview_count = sum(1 for e in elements if "webview" in e.get("class_name", "").lower())
                    if webview_count / max(1, len(elements)) >= 0.6:
                        webview_dominant = True
                    login_cues = 0
                    for e in elements:
                        text_blob = " ".join(
                            [
                                e.get("text", ""),
                                e.get("content_desc", ""),
                                e.get("resource_id", ""),
                            ]
                        ).lower()
                        if any(k in text_blob for k in ("login", "sign in", "sign-in", "password", "create account")):
                            login_cues += 1
                    if login_cues >= 2:
                        login_cue_steps += 1
                    else:
                        login_cue_steps = max(0, login_cue_steps - 1)

                if screen_hash == last_hash and screen_hash:
                    stagnant += 1
                else:
                    stagnant = 0
                last_hash = screen_hash

                if login_cue_steps >= 4:
                    status = "skip:login_required"
                    break

                if (
                    _PRIMARY_UX_FALLBACK
                    and not primary_fallback_active
                    and nav_plan_ready
                    and all_ux_goals_done
                    and ux_goals is not None
                    and len(ux_goals) > 0
                    and (time.time() - simulation_started) < duration_sec - 5
                ):
                    digest_txt_plan = _format_navigation_digest(exploration_digest)
                    primary_fallback_spec = _plan_primary_app_ux(
                        app_context, digest_txt_plan, planner_model, ollama_endpoint
                    )
                    primary_fallback_reason = "ux_goals_complete"
                    primary_fallback_active = True
                    stagnant = 0
                    last_hash = ""
                    _merge_primary_ux_into_plan(ux_plan_path, primary_fallback_spec, primary_fallback_reason)
                    logging.info(
                        "Primary UX fallback after structured goals finished (reason=%s): %s",
                        primary_fallback_reason,
                        (primary_fallback_spec[:280] + "…")
                        if len(primary_fallback_spec) > 280
                        else primary_fallback_spec,
                    )

                if _STAGNATION_INJECT_BACK and stagnant >= _STAG_BACK:
                    subprocess.run([adb_bin, "shell", "input", "keyevent", "4"], check=False)
                if stagnant >= _STAG_BAILOUT:
                    # Allow productive main-UX loops (e.g., browse/open/back) to continue briefly even if hash
                    # repeats, but keep hard bailout for clearly mechanical dead loops.
                    if _recent_progress_score(actions, window=6) >= 6:
                        logging.info(
                            "Stagnation bailout deferred due to recent productive loop score; stagnant=%d.",
                            stagnant,
                        )
                        stagnant = max(0, _STAG_BACK - 1)
                        continue
                    if (
                        _PRIMARY_UX_FALLBACK
                        and not primary_fallback_active
                        and not primary_stuck_escape_used
                        and nav_plan_ready
                        and (time.time() - simulation_started) < duration_sec - 10
                    ):
                        primary_stuck_escape_used = True
                        stagnant = 0
                        last_hash = ""
                        digest_txt_plan = _format_navigation_digest(exploration_digest)
                        primary_fallback_spec = _plan_primary_app_ux(
                            app_context, digest_txt_plan, planner_model, ollama_endpoint
                        )
                        primary_fallback_reason = "stagnation_during_goal_execution"
                        primary_fallback_active = True
                        _merge_primary_ux_into_plan(ux_plan_path, primary_fallback_spec, primary_fallback_reason)
                        logging.info(
                            "Primary UX fallback after stagnation bailout (reason=%s): %s",
                            primary_fallback_reason,
                            (primary_fallback_spec[:280] + "…")
                            if len(primary_fallback_spec) > 280
                            else primary_fallback_spec,
                        )
                        continue
                    status = f"partial:{PARTIAL_AGENT_STUCK}"
                    break

                if _NAV_FIRST_PIPELINE and not nav_plan_ready and elapsed >= explore_until_sec:
                    nav_obj = _build_navigation_artifact(
                        pkg=pkg,
                        discovered=exploration_digest,
                        transitions=nav_transitions,
                        visited_counts=nav_visited_counts,
                        nav_graph=nav_graph,
                    )
                    nav_artifact_path.write_text(json.dumps(nav_obj, indent=2, ensure_ascii=False), encoding="utf-8")
                    digest_txt_plan = _format_navigation_digest(exploration_digest)
                    plan_slack_sec = elapsed - explore_until_sec
                    if plan_slack_sec > 20.0:
                        logging.info(
                            "Post-explore goal planning skipped (%.1fs past explore budget); using digest templates.",
                            plan_slack_sec,
                        )
                        ux_goals = _finalize_post_explore_goals(
                            [],
                            digest_txt_plan,
                            supplemental_goals=_tap_goals_from_nav_graph(nav_graph),
                        )
                    else:
                        ux_goals = _plan_execution_goals_from_digest(
                            app_context,
                            digest_txt_plan
                            + "\n\nTRANSITIONS:\n"
                            + json.dumps(nav_transitions[-120:], ensure_ascii=False),
                            planner_model,
                            ollama_endpoint,
                            nav_graph=nav_graph,
                        )
                    ux_goal_routes = _build_route_aware_goals(ux_goals, nav_graph, exploration_digest)
                    nav_plan_ready = True
                    if ux_plan_path is not None:
                        ux_plan_path.write_text(
                            json.dumps(
                                {
                                    "goals": ux_goals,
                                    "goal_routes": ux_goal_routes,
                                    "pipeline": "nav_first_post_explore",
                                    "explore_ratio": _EXPLORE_RATIO,
                                    "explore_until_sec": explore_until_sec,
                                    "screen_digest": exploration_digest,
                                    "semantic_graph_summary": nav_graph,
                                },
                                indent=2,
                                ensure_ascii=False,
                            ),
                            encoding="utf-8",
                        )
                    logging.info("Post-explore plan (%d goals): %s", len(ux_goals), ux_goals)
                    root_handoff_info = _restore_execute_root_screen(
                        adb_bin,
                        pkg,
                        expected_root_hash=root_screen_hash,
                        expected_root_signature=root_screen_signature,
                        root_recovery_actions=_root_handoff_recovery_actions(
                            nav_transitions,
                            expected_root_hash=root_screen_hash,
                            target_pkg=pkg,
                        ),
                        nav_visited_counts=nav_visited_counts,
                    )
                    root_handoff_done = True
                    if root_handoff_info.get("ok"):
                        elements = list(root_handoff_info.get("elements") or [])
                        raw_xml = str(root_handoff_info.get("raw_xml") or "")
                        screen_hash = str(root_handoff_info.get("screen_hash") or _screen_hash(elements))
                        stagnant = 0
                        last_hash = ""
                        logging.info(
                            "Root/home handoff before execute succeeded (%s): hash=%s elements=%d.",
                            root_handoff_info.get("reason"),
                            screen_hash[:16],
                            len(elements),
                        )
                    else:
                        status = f"partial:{PARTIAL_BAD_HANDOFF}"
                        simulation_status = "failed:bad_handoff"
                        simulation_status_detail = str(root_handoff_info.get("reason") or "root_handoff_failed")
                        logging.warning(
                            "Root/home handoff before execute failed (%s); ending LLM session.",
                            simulation_status_detail,
                        )
                        break
                    if (
                        screen_hash
                        and screen_hash not in exploration_digest
                        and len(exploration_digest) < _NAV_DIGEST_MAX_SCREENS
                    ):
                        exploration_digest[screen_hash] = _screen_digest_hint(elements)
                    if ux_plan_path is not None:
                        try:
                            plan_obj = json.loads(ux_plan_path.read_text(encoding="utf-8"))
                        except json.JSONDecodeError:
                            plan_obj = {"goals": ux_goals}
                        plan_obj["root_handoff"] = {
                            "enabled": _ROOT_HANDOFF_RELAUNCH,
                            "force_stop": _ROOT_HANDOFF_FORCE_STOP,
                            "root_screen_hash": root_screen_hash,
                            "root_screen_signature": root_screen_signature,
                            "root_screen_hint": root_screen_hint,
                            "root_screen_source": root_screen_source,
                            "root_recovery_actions": _root_handoff_recovery_actions(
                                nav_transitions,
                                expected_root_hash=root_screen_hash,
                                target_pkg=pkg,
                            ),
                            "result": {
                                k: v
                                for k, v in root_handoff_info.items()
                                if k not in ("elements", "raw_xml")
                            },
                        }
                        ux_plan_path.write_text(
                            json.dumps(plan_obj, indent=2, ensure_ascii=False),
                            encoding="utf-8",
                        )

                exploring_phase = _NAV_FIRST_PIPELINE and elapsed < explore_until_sec
                batch_limit = _BATCH_ACTIONS_MAX if (_NAV_FIRST_PIPELINE or primary_fallback_active) else 1
                if (
                    ux_goals
                    and nav_plan_ready
                    and not exploring_phase
                    and not primary_fallback_active
                ):
                    cap = max(1, min(3, _EXECUTE_UX_BATCH_MAX))
                    batch_limit = min(batch_limit, cap)
                if (
                    nav_plan_ready
                    and not exploring_phase
                    and not primary_fallback_active
                    and not elements
                ):
                    recovered = False
                    while empty_execute_recovery_count < _EMPTY_EXECUTE_RECOVERY_ATTEMPTS:
                        rec = _recover_empty_execute_screen(
                            adb_bin,
                            pkg,
                            attempts_used=empty_execute_recovery_count,
                        )
                        empty_execute_recovery_count += 1
                        logging.warning(
                            "Execute saw empty hierarchy; recovery attempt %d/%d via %s -> %s (ok=%s elements=%d).",
                            empty_execute_recovery_count,
                            _EMPTY_EXECUTE_RECOVERY_ATTEMPTS,
                            rec.get("reason"),
                            rec.get("screen_reason"),
                            rec.get("ok"),
                            len(rec.get("elements") or []),
                        )
                        if rec.get("ok") and rec.get("elements"):
                            elements = list(rec.get("elements") or [])
                            raw_xml = str(rec.get("raw_xml") or "")
                            screen_hash = str(rec.get("screen_hash") or _screen_hash(elements))
                            stagnant = 0
                            last_hash = ""
                            recovered = True
                            empty_execute_recovery_count = 0
                            simulation_status_detail = "empty_execute_recovered"
                            if (
                                screen_hash
                                and screen_hash not in exploration_digest
                                and len(exploration_digest) < _NAV_DIGEST_MAX_SCREENS
                            ):
                                exploration_digest[screen_hash] = _screen_digest_hint(elements)
                            break
                    if not recovered:
                        status = f"partial:{PARTIAL_EMPTY_EXECUTE}"
                        simulation_status = "failed:empty_execute_hierarchy"
                        simulation_status_detail = "empty_execute_recovery_exhausted"
                        logging.warning(
                            "Execute hierarchy remained empty after %d recovery attempts; ending session.",
                            _EMPTY_EXECUTE_RECOVERY_ATTEMPTS,
                        )
                        break
                elif elements:
                    empty_execute_recovery_count = 0
                digest_txt = _format_navigation_digest(exploration_digest)
                app_state = _derive_app_screen_state(
                    elements,
                    pkg,
                    foreground_pkg=fg_now,
                    previous_nav_token=last_active_nav_token,
                )
                if app_state.get("active_nav_token"):
                    last_active_nav_token = str(app_state["active_nav_token"])
                goal_feasible_now = True
                goal_status = "feasible"
                empty_state_now = _screen_is_empty_state(elements)
                if ux_goals and not primary_fallback_active and 0 <= ux_goal_idx < len(ux_goals):
                    goal_status = _goal_execute_status(
                        ux_goals[ux_goal_idx],
                        elements,
                        actions,
                        app_state=app_state,
                        target_pkg=pkg,
                    )
                    goal_feasible_now = goal_status == "feasible"
                    if empty_state_now:
                        goal_feasible_now = False
                        goal_status = "blocked"
                    if goal_status == "blocked":
                        goal_blocked_turns += 1
                    else:
                        goal_blocked_turns = 0
                else:
                    goal_blocked_turns = 0

                if (
                    _NAV_FIRST_PIPELINE
                    and _PRIMARY_UX_FALLBACK
                    and not primary_fallback_active
                    and nav_plan_ready
                    and not exploring_phase
                    and ux_goals
                    and len(ux_goals) > 0
                    and not all_ux_goals_done
                    and (time.time() - simulation_started) < duration_sec - 5
                ):
                    if post_nav_execute_started is None:
                        post_nav_execute_started = time.time()
                    pn_elapsed = time.time() - post_nav_execute_started
                    forward_goal_count = sum(1 for g in ux_goals if _goal_is_forward(g))
                    blend_goal_index = _effective_primary_blend_goal_index(forward_goal_count)
                    blend_after_sec = _primary_blend_after_sec_for_goals(
                        duration_sec, forward_goal_count
                    )
                    goal_hit = ux_goal_idx >= blend_goal_index
                    time_hit = blend_after_sec > 0 and pn_elapsed >= blend_after_sec
                    if (
                        time_hit
                        and ux_goal_idx < _PRIMARY_UX_BLEND_MIN_GOAL_INDEX_FOR_TIME
                    ):
                        time_hit = False
                    remaining_sec = max(0.0, float(duration_sec) - (time.time() - simulation_started))
                    if (goal_hit or time_hit) and remaining_sec < _PRIMARY_UX_MIN_WINDOW_SEC:
                        goal_hit = False
                        time_hit = False
                    if goal_hit or time_hit:
                        digest_txt_plan = _format_navigation_digest(exploration_digest)
                        primary_fallback_spec = _plan_primary_app_ux(
                            app_context, digest_txt_plan, planner_model, ollama_endpoint
                        )
                        bits: list[str] = []
                        if forward_goal_count < _PRIMARY_UX_SPARSE_GOALS_THRESHOLD:
                            bits.append(f"sparse_goals<{_PRIMARY_UX_SPARSE_GOALS_THRESHOLD}")
                        if goal_hit:
                            bits.append(f"goal_index>={blend_goal_index}")
                        if time_hit:
                            bits.append(f"post_nav_sec>={blend_after_sec:.0f}")
                        primary_fallback_reason = (
                            "post_nav_realism_blend:" + "+".join(bits) if bits else "post_nav_realism_blend"
                        )
                        primary_fallback_active = True
                        stagnant = 0
                        last_hash = ""
                        _merge_primary_ux_into_plan(ux_plan_path, primary_fallback_spec, primary_fallback_reason)
                        logging.info(
                            "Primary UX blend after post-nav structured phase (%s): %s",
                            primary_fallback_reason,
                            (primary_fallback_spec[:280] + "…")
                            if len(primary_fallback_spec) > 280
                            else primary_fallback_spec,
                        )

                # Deterministic BFS-style navigation (no LLM control) during explore phase.
                if exploring_phase and not primary_fallback_active:
                    explore_pick = explore_strategy.pick_action(
                        ExploreTurnInput(
                            elements=elements,
                            pkg=pkg,
                            screen_hash=screen_hash,
                            fg_now=fg_now,
                        ),
                        explore_state,
                    )
                    explore_state = explore_pick.state
                    chosen = explore_pick.action
                    nav_cands = explore_pick.nav_cands
                    other_cands = explore_pick.other_cands
                    expand_cands = explore_pick.expand_cands
                    tab_cands = explore_pick.tab_cands
                    dialog_token = explore_pick.dialog_token
                    nav_key_to_action = explore_state.nav_key_to_action
                    tab_key_to_action = explore_state.tab_key_to_action

                    chosen_reason_pre = str(chosen.get("reason") or "") if chosen else ""
                    chosen_at_pre = str(chosen.get("action_type") or "") if chosen else ""
                    is_empty_hierarchy = (
                        not elements
                        or str(app_state.get("screen_role") or "") == "empty_hierarchy"
                    )
                    is_recovery_step = chosen_at_pre in {"back", "wait"} and chosen_reason_pre in {
                        "bfs_return_to_hub",
                        "bfs_avoid_back_loop",
                    }
                    if is_recovery_step and is_empty_hierarchy:
                        explore_non_navigable_streak += 1
                        if explore_non_navigable_streak >= _EXPLORE_NON_NAVIGABLE_STREAK_LIMIT:
                            status = f"partial:{PARTIAL_EXPLORE_NON_NAVIGABLE}"
                            simulation_status = "failed:explore_non_navigable"
                            simulation_status_detail = (
                                f"empty_hierarchy_recovery_streak={explore_non_navigable_streak} "
                                f"at_explore_step={step_idx + 1}"
                            )
                            logging.warning(
                                "Explore non-navigable: %d consecutive empty-hierarchy recovery steps "
                                "(limit=%d); aborting session for %s.",
                                explore_non_navigable_streak,
                                _EXPLORE_NON_NAVIGABLE_STREAK_LIMIT,
                                pkg,
                            )
                            break
                    elif not is_recovery_step or not is_empty_hierarchy:
                        explore_non_navigable_streak = 0

                    sig = _action_signature_for_candidate(chosen)
                    frida_pre_offset = frida_log_byte_offset(frida_log_path)
                    action_start_ms = int(time.time() * 1000)
                    ok, outcome = _execute_action(adb_bin, chosen, elements)
                    if (
                        str(chosen.get("reason") or "") in ("bfs_system_dialog_dismiss", "dialog_policy_recover_to_target")
                        and dialog_token
                        and ok
                    ):
                        explore_state.bfs_dialog_dismissed_tokens.add(dialog_token)
                    if str(chosen.get("reason") or "") in ("bfs_system_dialog_dismiss", "dialog_policy_recover_to_target"):
                        if _AUDIT_POST_ACTION_SLEEP_SEC > 0:
                            time.sleep(_AUDIT_POST_ACTION_SLEEP_SEC)
                        if ok:
                            _bring_target_foreground(adb_bin, pkg)
                            for act in list(tab_key_to_action.values()) + list(nav_key_to_action.values()):
                                if _action_is_permission_risk(act):
                                    explore_state.bfs_permission_risk_keys_attempted.add(_nav_target_key(act))
                        else:
                            subprocess.run(
                                [adb_bin, "shell", "input", "keyevent", "KEYCODE_BACK"],
                                check=False,
                                capture_output=True,
                                timeout=8,
                            )
                    # After hub/tab entry, drill N turns into interior content before cycling tabs again.
                    if chosen is not None and _bfs_tap_triggers_interior_expand(chosen):
                        explore_state.pending_interior_expand = _BFS_INTERIOR_EXPAND_BUDGET
                    if str(chosen.get("action_type")) == "back":
                        explore_state.bfs_back_streak += 1
                    else:
                        explore_state.bfs_back_streak = 0
                    if not ok:
                        failed_once.add(sig)
                    if _POST_ACTION_SETTLE_SEC > 0:
                        time.sleep(_POST_ACTION_SETTLE_SEC)
                    el_after, _, _ = dump_clean_screen(adb_bin)
                    el_after = _filter_widgets_for_target(el_after, pkg)
                    hash_after = _screen_hash(el_after)
                    action_nav_token = _action_nav_token(chosen)
                    if ok and action_nav_token and not _action_is_search_like(chosen):
                        last_active_nav_token = action_nav_token
                    app_state_after = _derive_app_screen_state(
                        el_after,
                        pkg,
                        foreground_pkg=fg_now,
                        previous_nav_token=last_active_nav_token,
                    )
                    if app_state_after.get("active_nav_token"):
                        last_active_nav_token = str(app_state_after["active_nav_token"])
                    _bfs_mark_permission_risk_if_triggered(
                        chosen,
                        ok=ok,
                        screen_hash_before=screen_hash,
                        screen_hash_after=hash_after,
                        elements_after=el_after,
                        target_pkg=pkg,
                        attempted=explore_state.bfs_permission_risk_keys_attempted,
                    )
                    chosen_reason_early = str(chosen.get("reason") or "")
                    if chosen_reason_early == "bfs_text_entry_probe":
                        explore_state.bfs_text_entry_probed_keys.add(
                            _text_entry_probe_field_key(screen_hash, chosen)
                        )
                    bfs_expand_stall_event: dict[str, Any] | None = None
                    if chosen_reason_early.startswith("bfs_expand_"):
                        if ok and hash_after and hash_after != screen_hash:
                            bfs_expand_stall_by_screen.pop(screen_hash, None)
                        else:
                            stalls = bfs_expand_stall_by_screen.get(screen_hash, 0) + 1
                            if stalls >= _BFS_EXPAND_STALL_LIMIT_PER_SCREEN:
                                tried = explore_state.bfs_expand_tried_on_screen.setdefault(screen_hash, set())
                                stalled_key = _nav_target_key(chosen)
                                tried.add(stalled_key)
                                keys_marked = 1
                                bfs_expand_stall_by_screen[screen_hash] = 0
                                bfs_expand_stall_event = {
                                    "screen_hash": screen_hash,
                                    "stall_count": stalls,
                                    "keys_marked": keys_marked,
                                    "marked_keys": [stalled_key],
                                    "expand_cands_on_screen": len(expand_cands),
                                    "mark_mode": "tried_key_only",
                                }
                                logging.info(
                                    "BFS expand stall limit on screen %s (stall=%d); marked 1 tried key, "
                                    "%d expand cands remain eligible.",
                                    screen_hash[:16],
                                    stalls,
                                    len(expand_cands),
                                )
                            else:
                                bfs_expand_stall_by_screen[screen_hash] = stalls
                    if hash_after and hash_after not in exploration_digest and len(exploration_digest) < _NAV_DIGEST_MAX_SCREENS:
                        exploration_digest[hash_after] = _screen_digest_hint(el_after)
                    chosen_key = _nav_target_key(chosen)
                    chosen_reason = str(chosen.get("reason") or "")
                    if chosen_reason == "bfs_system_dialog_dismiss":
                        nav_candidate_kind = "dialog"
                    elif chosen_reason == "dialog_policy_recover_to_target":
                        nav_candidate_kind = "recovery"
                    elif chosen_key in tab_key_to_action or "tab" in chosen_reason:
                        nav_candidate_kind = "tab"
                    elif chosen_key in nav_key_to_action or "nav" in chosen_reason:
                        nav_candidate_kind = "nav"
                    else:
                        nav_candidate_kind = "expand"
                    nav_target_key = _nav_graph_record_transition(
                        nav_graph,
                        from_hash=screen_hash,
                        to_hash=hash_after,
                        action=chosen,
                        ok=ok,
                        candidate_kind=nav_candidate_kind,
                    )
                    execution_kind = _execution_kind_for_step(
                        pipeline_phase="explore",
                        proposal=chosen,
                        executed=chosen,
                        ok=ok,
                        outcome=outcome,
                    )
                    nav_transitions.append(
                        {
                            "step": step_idx + 1,
                            "from": screen_hash,
                            "to": hash_after,
                            "action": chosen,
                            "ok": ok,
                            "outcome": outcome,
                            "execution_kind": execution_kind,
                            "nav_target_key": nav_target_key,
                        }
                    )
                    step_idx += 1
                    recovery_step = is_explore_recovery_action(chosen)
                    explore_instrumentation = build_explore_candidate_instrumentation(
                        elements,
                        nav_cands,
                        other_cands,
                        expand_cands,
                        tab_cands,
                        screen_hash=screen_hash,
                        recovery_step=recovery_step,
                    )
                    explore_tier_index = explore_tier_index_for_reason(str(chosen.get("reason") or ""))
                    event = {
                        "step": step_idx,
                        "ts_epoch_ms": int(time.time() * 1000),
                        "prompt_hash": "bfs_navigation_phase",
                        "temperature": _LLM_TEMPERATURE_RUNTIME,
                        "planner_model": action_model,
                        "planner_model_info": {"model": str(planner_model_info.get("model", planner_model))},
                        "raw_response": "{\"engine\":\"deterministic_bfs_navigation\"}",
                        "parsed_action": chosen,
                        "action_success": ok,
                        "action_outcome": outcome,
                        "screen_hash": screen_hash,
                        "screen_hash_after": hash_after,
                        "app_state": app_state,
                        "app_state_after": app_state_after,
                        "stagnant_after_dump": stagnant,
                        "interactive_element_count": len(elements),
                        "interactive_element_count_after": len(el_after),
                        "planner_turn": planner_turn_id,
                        "pipeline_phase": "explore",
                        "execution_kind": execution_kind,
                        "nav_target_key": nav_target_key,
                        "batch_index": 0,
                        "batch_size": 1,
                    }
                    event.update(explore_instrumentation)
                    if explore_tier_index is not None:
                        event["explore_tier_index"] = explore_tier_index
                    if bfs_expand_stall_event is not None:
                        event["bfs_expand_stall_event"] = bfs_expand_stall_event
                    if str(chosen.get("action_type") or "") == "input":
                        event["explore_input_effective"] = explore_input_effective_after_action(
                            action_success=ok,
                            screen_hash=screen_hash,
                            screen_hash_after=hash_after,
                            frida_log_path=frida_log_path,
                            frida_pre_offset=frida_pre_offset,
                            action_start_ms=action_start_ms,
                        )
                    out.write(json.dumps(event, ensure_ascii=False) + "\n")
                    out.flush()
                    actions.append(event)
                    time.sleep(0.4)
                    continue

                if primary_fallback_active:
                    pipeline_phase = "primary_ux"
                    primary_micro_intent = _derive_primary_ux_micro_intent(
                        primary_mission=primary_fallback_spec or _DEFAULT_PRIMARY_UX_TEXT,
                        app_state=app_state,
                        elements=elements,
                        recent_actions=actions,
                        stagnant=stagnant,
                    )
                    prompt = _build_primary_ux_prompt(
                        app_context,
                        elements,
                        actions,
                        primary_mission=primary_fallback_spec or _DEFAULT_PRIMARY_UX_TEXT,
                        stagnant=stagnant,
                        navigation_digest_text=digest_txt,
                        app_state=app_state,
                        primary_micro_intent=primary_micro_intent,
                        batch_limit=batch_limit,
                    )
                elif exploring_phase:
                    pipeline_phase = "explore"
                    prompt = _build_explore_prompt(
                        app_context,
                        elements,
                        actions,
                        stagnant=stagnant,
                        navigation_digest_text=digest_txt,
                        batch_limit=batch_limit,
                    )
                else:
                    pipeline_phase = "execute" if _NAV_FIRST_PIPELINE else "legacy"
                    active_goal_route = (
                        ux_goal_routes[ux_goal_idx]
                        if 0 <= ux_goal_idx < len(ux_goal_routes)
                        else None
                    )
                    prompt = _build_prompt(
                        app_context,
                        elements,
                        actions,
                        ux_goals=ux_goals,
                        ux_goal_index=ux_goal_idx,
                        ux_goal_feasible_now=goal_feasible_now,
                        ux_goal_status=goal_status,
                        goal_blocked_turns=goal_blocked_turns,
                        stagnant=stagnant,
                        navigation_context=digest_txt if _NAV_FIRST_PIPELINE else None,
                        app_state=app_state,
                        ux_goal_route=active_goal_route,
                        batch_limit=batch_limit,
                        replan_alert=execute_replan_alert,
                    )

                active_goal_route_for_controller = (
                    ux_goal_routes[ux_goal_idx]
                    if ux_goals and 0 <= ux_goal_idx < len(ux_goal_routes)
                    else None
                )
                raw = ""
                batch_actions: list[dict[str, Any]] = []
                engine_planned_execute = False
                if (
                    pipeline_phase == "execute"
                    and ux_goals
                    and not primary_fallback_active
                    and nav_plan_ready
                    and 0 <= ux_goal_idx < len(ux_goals)
                ):
                    if goal_status == "satisfied":
                        batch_actions = [
                            {
                                "action_type": "advance_goal",
                                "reason": "engine_goal_status_satisfied",
                            }
                        ]
                        raw = json.dumps({"actions": batch_actions}, ensure_ascii=False)
                        engine_planned_execute = True
                    elif execute_planner_failure_streak >= 2:
                        route_pre = _route_controller_action_for_goal(
                            active_goal_route_for_controller,
                            nav_graph,
                            app_state,
                            elements,
                            pkg,
                            recent_actions=actions,
                        )
                        if route_pre is None and goal_blocked_turns >= 2:
                            route_pre = {
                                "action_type": "advance_goal",
                                "reason": "engine_prose_spiral_skip_blocked",
                            }
                        if route_pre is None:
                            route_pre = {
                                "action_type": "advance_goal",
                                "reason": "engine_prose_spiral_skip_unroutable",
                            }
                        if route_pre is not None:
                            logging.info(
                                "Skipping Ollama execute turn after %d planner failures; using %s.",
                                execute_planner_failure_streak,
                                route_pre.get("reason"),
                            )
                            batch_actions = [route_pre]
                            raw = json.dumps({"actions": batch_actions}, ensure_ascii=False)
                            engine_planned_execute = True
                            execute_planner_failure_streak = 0
                    else:
                        route_pre = _route_controller_action_for_goal(
                            active_goal_route_for_controller,
                            nav_graph,
                            app_state,
                            elements,
                            pkg,
                            recent_actions=actions,
                        )
                        if route_pre is not None:
                            batch_actions = [route_pre]
                            raw = json.dumps({"actions": batch_actions}, ensure_ascii=False)
                            engine_planned_execute = True
                        elif (
                            _NAV_FIRST_PIPELINE
                            and _EXECUTE_ENGINE_ONLY
                        ):
                            active_goal = (
                                ux_goals[ux_goal_idx]
                                if 0 <= ux_goal_idx < len(ux_goals)
                                else ""
                            )
                            route_pre = _execute_engine_fallback_action(
                                active_goal_route_for_controller,
                                active_goal,
                                nav_graph,
                                app_state,
                                elements,
                                pkg,
                                goal_status=goal_status,
                                goal_blocked_turns=goal_blocked_turns,
                                recent_actions=actions,
                            )
                            logging.info(
                                "Execute engine-only fallback (no Ollama): %s",
                                route_pre.get("reason"),
                            )
                            batch_actions = [route_pre]
                            raw = json.dumps({"actions": batch_actions}, ensure_ascii=False)
                            engine_planned_execute = True
                            execute_planner_failure_streak = 0

                if engine_planned_execute:
                    prompt_hash = hashlib.sha256(
                        f"engine_execute:{batch_actions}".encode("utf-8")
                    ).hexdigest()
                else:
                    prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
                    ollama_kw: dict[str, Any] = {}
                    if pipeline_phase == "execute" and not primary_fallback_active:
                        ollama_kw["max_attempts"] = min(2, OLLAMA_GENERATE_RETRIES)
                        ollama_kw["timeout_sec"] = min(_OLLAMA_GENERATE_TIMEOUT_SEC, 45.0)
                    try:
                        raw = _ollama_generate_with_retries(
                            prompt, action_model, ollama_endpoint, **ollama_kw
                        )
                        ollama_fail_steps = 0
                    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
                        raw = '{"actions":[{"action_type":"wait","reason":"ollama_error"}]}'
                        ollama_fail_steps += 1

                planner_turn_id += 1
                if not batch_actions:
                    batch_actions = _parse_actions_list(raw, max_actions=batch_limit)
                if (
                    pipeline_phase == "execute"
                    and not primary_fallback_active
                    and not exploring_phase
                    and ux_goals
                    and batch_actions
                    and _NAV_FIRST_PIPELINE
                    and _EXECUTE_ENGINE_ONLY
                    and all(
                        str(a.get("action_type")) == "wait"
                        and (
                            str(a.get("reason") or "").startswith("planner_contract_")
                            or str(a.get("reason") or "") == "planner_target_not_visible"
                            or str(a.get("reason") or "") == "ollama_error"
                        )
                        for a in batch_actions
                    )
                ):
                    active_goal = (
                        ux_goals[ux_goal_idx] if 0 <= ux_goal_idx < len(ux_goals) else ""
                    )
                    batch_actions = [
                        _execute_engine_fallback_action(
                            active_goal_route_for_controller,
                            active_goal,
                            nav_graph,
                            app_state,
                            elements,
                            pkg,
                            goal_status=goal_status,
                            goal_blocked_turns=goal_blocked_turns,
                            recent_actions=actions,
                        )
                    ]
                    execute_planner_failure_streak = 0
                if (
                    pipeline_phase == "execute"
                    and not primary_fallback_active
                    and not exploring_phase
                    and ux_goals
                    and batch_actions
                ):
                    planner_failed = all(
                        str(a.get("action_type")) == "wait"
                        and (
                            str(a.get("reason") or "").startswith("planner_contract_")
                            or str(a.get("reason") or "") == "planner_target_not_visible"
                        )
                        for a in batch_actions
                    )
                    if planner_failed:
                        execute_planner_failure_streak += 1
                    elif not all(str(a.get("action_type")) == "wait" for a in batch_actions):
                        execute_planner_failure_streak = 0
                    if execute_planner_failure_streak >= 2 and not engine_planned_execute:
                        recovery = _route_controller_action_for_goal(
                            active_goal_route_for_controller,
                            nav_graph,
                            app_state,
                            elements,
                            pkg,
                            recent_actions=actions,
                        )
                        if recovery is None and goal_status == "satisfied":
                            recovery = {
                                "action_type": "advance_goal",
                                "reason": "engine_prose_spiral_advance_satisfied",
                            }
                        elif recovery is None and goal_blocked_turns >= 2:
                            recovery = {
                                "action_type": "advance_goal",
                                "reason": "engine_prose_spiral_skip_blocked",
                            }
                        elif recovery is None:
                            recovery = {
                                "action_type": "advance_goal",
                                "reason": "engine_prose_spiral_skip_unroutable",
                            }
                        if recovery is not None:
                            logging.info(
                                "Execute prose-spiral recovery after %d planner failures: %s",
                                execute_planner_failure_streak,
                                recovery.get("reason"),
                            )
                            batch_actions = [recovery]
                            execute_planner_failure_streak = 0
                if (
                    ux_goals
                    and not primary_fallback_active
                    and not exploring_phase
                    and goal_status == "satisfied"
                    and 0 <= ux_goal_idx < len(ux_goals)
                ):
                    active_goal_for_advance = ux_goals[ux_goal_idx]
                    if _goal_needs_text_entry_field(active_goal_for_advance) and not _typing_goal_recently_satisfied(
                        actions
                    ):
                        goal_status = "feasible"
                    else:
                        batch_actions = [
                            {
                                "action_type": "advance_goal",
                                "reason": "engine_goal_status_satisfied",
                            }
                        ]
                elif (
                    ux_goals
                    and not primary_fallback_active
                    and not exploring_phase
                    and active_goal_route_for_controller
                ):
                    route_action = _route_controller_action_for_goal(
                        active_goal_route_for_controller,
                        nav_graph,
                        app_state,
                        elements,
                        pkg,
                        recent_actions=actions,
                    )
                    if route_action is not None:
                        batch_actions = [route_action]
                # Explore and execute: if the UI hash is stuck and the planner returns only waits, the fingerprint
                # never advances and we hit agent_stuck. Replace with a vertical swipe (nudge lists/feeds).
                if (
                    stagnant >= 4
                    and not primary_fallback_active
                    and elements
                    and batch_actions
                    and all(str(a.get("action_type")) == "wait" for a in batch_actions)
                ):
                    route_stagnation = None
                    if (
                        pipeline_phase == "execute"
                        and active_goal_route_for_controller
                    ):
                        route_stagnation = _route_controller_action_for_goal(
                            active_goal_route_for_controller,
                            nav_graph,
                            app_state,
                            elements,
                            pkg,
                            recent_actions=actions,
                        )
                    if route_stagnation is not None:
                        logging.info(
                            "Replacing all-wait batch under stagnation=%d phase=%s with route recovery (%s).",
                            stagnant,
                            pipeline_phase,
                            route_stagnation.get("reason"),
                        )
                        batch_actions = [route_stagnation]
                    else:
                        logging.info(
                            "Replacing all-wait batch under stagnation=%d phase=%s with swipe recovery.",
                            stagnant,
                            pipeline_phase,
                        )
                        batch_actions = [
                            {
                                "action_type": "swipe",
                                "x1": 540,
                                "y1": 1720,
                                "x2": 540,
                                "y2": 700,
                                "duration_ms": 240,
                                "reason": "engine_all_wait_to_swipe_stagnation",
                            }
                        ]

                duration_hit_outer = False
                batch_start_hash = screen_hash
                for bi, action in enumerate(batch_actions):
                    elapsed_inner = time.time() - simulation_started
                    if elapsed_inner >= duration_sec:
                        duration_hit_outer = True
                        break

                    if bi > 0:
                        elements, _, _ = dump_clean_screen(adb_bin)
                        elements = _filter_widgets_for_target(elements, pkg)
                        screen_hash = _screen_hash(elements)
                        app_state = _derive_app_screen_state(
                            elements,
                            pkg,
                            foreground_pkg=fg_now,
                            previous_nav_token=last_active_nav_token,
                        )
                        if app_state.get("active_nav_token"):
                            last_active_nav_token = str(app_state["active_nav_token"])
                        if (
                            screen_hash
                            and screen_hash not in exploration_digest
                            and len(exploration_digest) < _NAV_DIGEST_MAX_SCREENS
                        ):
                            exploration_digest[screen_hash] = _screen_digest_hint(elements)

                    proposal_before_repair = copy.deepcopy(action)
                    model_proposal = copy.deepcopy(proposal_before_repair)

                    if action.get("reason") == "ollama_error":
                        stagnant = 0
                    elif action.get("reason") != "ollama_error":
                        action = _repair_input_action_for_execution(
                            action,
                            elements,
                            ux_goals=None if primary_fallback_active else ux_goals,
                            ux_goal_idx=ux_goal_idx,
                            target_pkg=pkg,
                        )
                        if (
                            not exploring_phase
                            and not primary_fallback_active
                            and str(action.get("action_type") or "") == "tap"
                            and (
                                not ux_goals
                                or _hierarchy_shows_permission_dialog(elements, pkg)
                            )
                        ):
                            action = _repair_tap_action_for_execution(
                                action,
                                elements,
                                ux_goals=ux_goals,
                                ux_goal_idx=ux_goal_idx,
                                navigation_digest_text=digest_txt if _NAV_FIRST_PIPELINE else None,
                                target_pkg=pkg,
                            )
                    if (
                        ux_goals
                        and not primary_fallback_active
                        and not exploring_phase
                        and 0 <= ux_goal_idx < len(ux_goals)
                    ):
                        allowed_now = _allowed_resource_ids_from_elements(elements)
                        target_rejection = _structured_execute_target_rejection(action, elements)
                        prop_rid = str(action.get("target_resource_id") or "").strip()
                        prop_cd = str(action.get("target_content_desc") or "").strip()
                        prop_type = str(action.get("action_type") or "")
                        if target_rejection:
                            invalid_target_count += 1
                            if invalid_target_count >= 2:
                                if allowed_now:
                                    execute_replan_alert = (
                                        "INVALID_TARGET_RECOVERY: The previous target was not visible "
                                        f"({target_rejection}). "
                                        f"Use exactly one of these visible ids: {json.dumps(allowed_now[:32], ensure_ascii=False)}. "
                                        "If none matches the ACTIVE goal, return advance_goal. Return JSON only."
                                    )
                                else:
                                    execute_replan_alert = (
                                        "INVALID_TARGET_RECOVERY: No target app resource_ids are visible. "
                                        "Do not invent ids. Return wait or advance_goal; the runner will restore root "
                                        "if the hierarchy remains empty."
                                    )
                            else:
                                execute_replan_alert = (
                                    "REPLAN_ALERT: "
                                    f"Proposed target is not visible ({target_rejection}; "
                                    f"rid={prop_rid or '(none)'}; content_desc={prop_cd or '(none)'}). "
                                    "Follow GOAL_ACTION_HINT with only listed ids, or return advance_goal."
                                )
                            action = {
                                "action_type": "wait",
                                "reason": "planner_target_not_visible",
                            }
                        elif (
                            goal_blocked_turns >= 2
                            and goal_status == "blocked"
                            and stagnant >= 1
                        ):
                            execute_replan_alert = (
                                "GOAL_BLOCKED_ALERT: The ACTIVE goal cannot be completed on this screen "
                                f"(blocked_turns={goal_blocked_turns}). Follow GOAL_ACTION_HINT — use "
                                "ALLOWED_TARGET_RESOURCE_IDS to navigate, or return advance_goal."
                            )
                        elif prop_type in ("tap", "input", "advance_goal"):
                            invalid_target_count = 0
                    if (
                        ux_goals
                        and not primary_fallback_active
                        and not exploring_phase
                        and empty_state_now
                        and str(action.get("action_type") or "") in ("wait", "tap", "swipe")
                    ):
                        action = {
                            "action_type": "advance_goal",
                            "reason": "engine_empty_state_blocked_goal",
                        }

                    proposal_signature = _action_signature_for_guard(action)
                    recent_signatures = [
                        _action_signature_for_guard(a.get("parsed_action") or {})
                        for a in actions[-_REP_WIN:]
                    ]
                    recent_progress = _recent_progress_score(actions, window=6)
                    if (
                        action.get("reason") != "ollama_error"
                        and not str(action.get("reason") or "").startswith("planner_contract_")
                        and action.get("action_type") not in ("advance_goal", "swipe")
                        and not str(action.get("reason") or "").startswith("engine_route_")
                        and not str(action.get("reason") or "").startswith("engine_fallback_")
                        and recent_signatures.count(proposal_signature) >= _REP_THR
                        and recent_progress < 5
                    ):
                        if _REPETITION_GUARD_USE_BACK:
                            action = {"action_type": "back", "reason": "repetition_guard"}
                        else:
                            action = {"action_type": "wait", "reason": "repetition_guard"}

                    if primary_fallback_active and str(action.get("reason") or "").startswith("planner_contract_"):
                        action, primary_ux_tap_pick_index = _primary_ux_controller_action(
                            primary_micro_intent,
                            elements,
                            pkg,
                            tap_rotate=primary_ux_tap_pick_index,
                        )
                    if not exploring_phase and not primary_fallback_active:
                        action = _guard_planner_action(
                            action, elements, pkg, strict_visible_tap=True
                        )
                    if (
                        ux_goals
                        and not primary_fallback_active
                        and not exploring_phase
                        and active_goal_route_for_controller
                    ):
                        exec_reason = str(action.get("reason") or "")
                        prop_reason_exec = str(model_proposal.get("reason") or "")
                        if (
                            exec_reason.startswith("planner_contract_")
                            or prop_reason_exec.startswith("planner_contract_")
                            or exec_reason == "ollama_error"
                            or prop_reason_exec == "ollama_error"
                        ):
                            contract_route = _route_controller_action_for_goal(
                                active_goal_route_for_controller,
                                nav_graph,
                                app_state,
                                elements,
                                pkg,
                                recent_actions=actions,
                            )
                            if contract_route is None:
                                active_goal = (
                                    ux_goals[ux_goal_idx]
                                    if 0 <= ux_goal_idx < len(ux_goals)
                                    else ""
                                )
                                contract_route = _execute_engine_fallback_action(
                                    active_goal_route_for_controller,
                                    active_goal,
                                    nav_graph,
                                    app_state,
                                    elements,
                                    pkg,
                                    goal_status=goal_status,
                                    goal_blocked_turns=goal_blocked_turns,
                                    recent_actions=actions,
                                )
                            action = contract_route
                    if primary_fallback_active:
                        action, primary_ux_tap_pick_index = _sanitize_primary_ux_action(
                            action,
                            elements,
                            pkg,
                            stagnant=stagnant,
                            tap_rotate=primary_ux_tap_pick_index,
                        )

                    signature = _action_signature_for_guard(action)
                    if signature == last_failed_signature and signature in failed_once:
                        action = {"action_type": "wait", "reason": "skip_repeat_failed_action"}
                        signature = _action_signature_for_guard(action)

                    ok, outcome = _execute_action(adb_bin, action, elements)
                    if ok and str(action.get("action_type")) == "input" and any(
                        tok in outcome
                        for tok in (
                            "keyevent_enter",
                            "keyevent_tab_enter",
                            "keyevent_search",
                            "keyevent_enter_then_tab_enter",
                        )
                    ):
                        stagnant = max(0, stagnant - 4)
                    if ok and str(action.get("action_type")) == "swipe":
                        # Swipe recovery should buy at least one more planner turn before stagnation bailout.
                        stagnant = max(0, stagnant - 3)
                    action_nav_token = _action_nav_token(action)
                    if ok and action_nav_token and not _action_is_search_like(action):
                        last_active_nav_token = action_nav_token

                    if not ok:
                        failed_once.add(signature)
                        last_failed_signature = signature
                        _, _, _ = dump_clean_screen(adb_bin)
                    else:
                        last_failed_signature = ""

                    if (
                        ux_goals
                        and not primary_fallback_active
                        and ok
                        and action.get("action_type") == "advance_goal"
                    ):
                        stagnant = 0
                        goal_blocked_turns = 0
                        if ux_goal_idx < len(ux_goals) - 1:
                            ux_goal_idx += 1
                        else:
                            all_ux_goals_done = True

                    fg_pkg: Optional[str] = None
                    hash_after = ""
                    el_after_len = 0
                    app_state_after: dict[str, Any] = {}
                    assessment: dict[str, Any] = {"codes": [], "severity": "info"}

                    if _AUDIT_SESSION:
                        try:
                            fg_pkg = _foreground_package(adb_bin)
                            settle_pre_dump = max(_POST_ACTION_SETTLE_SEC, _AUDIT_POST_ACTION_SLEEP_SEC)
                            if settle_pre_dump > 0:
                                time.sleep(settle_pre_dump)
                            el_after, _, _ = dump_clean_screen(adb_bin)
                            el_after = _filter_widgets_for_target(el_after, pkg)
                            hash_after = _screen_hash(el_after)
                            app_state_after = _derive_app_screen_state(
                                el_after,
                                pkg,
                                foreground_pkg=fg_pkg,
                                previous_nav_token=last_active_nav_token,
                            )
                            if app_state_after.get("active_nav_token"):
                                last_active_nav_token = str(app_state_after["active_nav_token"])
                            seen_hashes.add(hash_after)
                            el_after_len = len(el_after)
                            assessment = _compute_audit_assessment(
                                pkg=pkg,
                                foreground_pkg=fg_pkg,
                                proposal=model_proposal,
                                executed=action,
                                ok=ok,
                                outcome=outcome,
                                hash_before=screen_hash,
                                hash_after=hash_after,
                                n_before=len(elements),
                                n_after=el_after_len,
                            )
                        except Exception as exc:
                            logging.warning(
                                "Audit post-action capture failed (continuing session): %s",
                                exc,
                            )
                            assessment = {
                                "codes": ["audit_capture_failed"],
                                "severity": "info",
                            }
                    elif _POST_ACTION_SETTLE_SEC > 0:
                        time.sleep(_POST_ACTION_SETTLE_SEC)

                    execution_kind = _execution_kind_for_step(
                        pipeline_phase=pipeline_phase,
                        proposal=model_proposal,
                        executed=action,
                        ok=ok,
                        outcome=outcome,
                    )
                    if _AUDIT_SESSION and execution_kind in ("blocked", "repaired", "recovery"):
                        assessment.setdefault("codes", [])
                        code = f"execution_kind_{execution_kind}"
                        if code not in assessment["codes"]:
                            assessment["codes"].append(code)

                    step_idx += 1
                    if audit_f is not None:
                        audit_rec = {
                            "step": step_idx,
                            "ts_epoch_ms": int(time.time() * 1000),
                            "foreground_package": fg_pkg,
                            "screen_hash_before": screen_hash,
                            "screen_hash_after": hash_after,
                            "app_state_before": app_state,
                            "app_state_after": app_state_after,
                            "interactive_count_before": len(elements),
                            "interactive_count_after": el_after_len,
                            "unique_screen_hashes_seen": len(seen_hashes),
                            "stagnation_at_step": stagnant,
                            "model_proposal": model_proposal,
                            "executed_action": action,
                            "raw_response_preview": (
                                (raw[:4000] + "…") if len(raw) > 4000 else raw
                            ),
                            "action_success": ok,
                            "action_outcome": outcome,
                            "execution_kind": execution_kind,
                            "assessment": assessment,
                            "planner_turn": planner_turn_id,
                            "pipeline_phase": pipeline_phase,
                            "batch_index": bi,
                            "batch_size": len(batch_actions),
                        }
                        if ux_goals and not primary_fallback_active:
                            audit_rec["ux_goal_index"] = ux_goal_idx
                            audit_rec["ux_goal_active"] = ux_goals[ux_goal_idx]
                            if 0 <= ux_goal_idx < len(ux_goal_routes):
                                audit_rec["ux_goal_route"] = ux_goal_routes[ux_goal_idx]
                            audit_rec["ux_goal_feasible_now"] = goal_feasible_now
                            audit_rec["ux_goal_blocked_turns"] = goal_blocked_turns
                            audit_rec["empty_state_now"] = empty_state_now
                        if primary_fallback_active:
                            audit_rec["primary_ux_micro_intent"] = primary_micro_intent
                        audit_f.write(json.dumps(audit_rec, ensure_ascii=False) + "\n")
                        audit_f.flush()

                    event = {
                        "step": step_idx,
                        "ts_epoch_ms": int(time.time() * 1000),
                        "prompt_hash": prompt_hash,
                        "temperature": _LLM_TEMPERATURE_RUNTIME,
                        "planner_model": action_model,
                        "planner_model_info": (
                            {"model": str(model_info.get("model", action_model))}
                            if _SLIM_ACTION_LOG
                            else model_info
                        ),
                        "raw_response": raw,
                        "parsed_action": action,
                        "action_success": ok,
                        "action_outcome": outcome,
                        "execution_kind": execution_kind,
                        "screen_hash": screen_hash,
                        "app_state": app_state,
                        "stagnant_after_dump": stagnant,
                        "interactive_element_count": len(elements),
                        "planner_turn": planner_turn_id,
                        "pipeline_phase": pipeline_phase,
                        "batch_index": bi,
                        "batch_size": len(batch_actions),
                    }
                    if ux_goals and not primary_fallback_active:
                        event["ux_goal_index"] = ux_goal_idx
                        event["ux_goal_active"] = ux_goals[ux_goal_idx]
                        if 0 <= ux_goal_idx < len(ux_goal_routes):
                            event["ux_goal_route"] = ux_goal_routes[ux_goal_idx]
                        event["ux_goal_status"] = goal_status
                        event["ux_goal_feasible_now"] = goal_feasible_now
                        event["ux_goal_blocked_turns"] = goal_blocked_turns
                        event["empty_state_now"] = empty_state_now
                    if primary_fallback_active:
                        event["primary_ux_micro_intent"] = primary_micro_intent
                    if _AUDIT_SESSION:
                        event["screen_hash_after"] = hash_after
                        event["app_state_after"] = app_state_after
                        event["interactive_element_count_after"] = el_after_len
                        event["unique_screen_hashes_seen"] = len(seen_hashes)
                        event["foreground_package"] = fg_pkg
                        event["model_proposal"] = model_proposal
                        event["audit_assessment"] = assessment
                    out.write(json.dumps(event, ensure_ascii=False) + "\n")
                    out.flush()
                    actions.append(event)

                    if (
                        ux_goals
                        and not primary_fallback_active
                        and pipeline_phase == "execute"
                    ):
                        exec_reason = str(action.get("reason") or "")
                        prop_type = str(model_proposal.get("action_type") or "")
                        prop_rid = str(model_proposal.get("target_resource_id") or "").strip()
                        if exec_reason.startswith("planner_contract_"):
                            execute_replan_alert = (
                                "REPLAN_ALERT: The previous response violated the JSON action contract "
                                f"({exec_reason}). Return STRICT JSON only: "
                                "{\"actions\":[{\"action_type\":\"tap|input|back|wait|advance_goal\","
                                "\"target_resource_id\":\"\",\"target_content_desc\":\"\",\"reason\":\"...\"}]}. "
                                "Use only current CLEAN_SCREEN_ELEMENTS."
                            )
                        elif exec_reason.startswith("guard_"):
                            execute_replan_alert = (
                                "REPLAN_ALERT: The previous step was blocked ("
                                f"{exec_reason}). Proposed {prop_type}"
                                + (f" on {prop_rid}" if prop_rid else "")
                                + " was not executable on the current screen. "
                                "Return ONE action for the ACTIVE UX GOAL using only "
                                "resource_ids listed in CLEAN_SCREEN_ELEMENTS."
                            )
                        elif prop_type == "tap" and "fallback_rid_missing" in str(outcome):
                            execute_replan_alert = (
                                "REPLAN_ALERT: The previous tap target was missing on screen "
                                f"({prop_rid or 'unknown'}). Pick a visible control from "
                                "CLEAN_SCREEN_ELEMENTS for the ACTIVE UX GOAL."
                            )
                        elif (
                            len(batch_actions) > 1
                            and bi > 0
                            and _AUDIT_SESSION
                            and hash_after
                            and batch_start_hash
                            and hash_after != batch_start_hash
                        ):
                            execute_replan_alert = (
                                "REPLAN_ALERT: UI changed mid-batch — replan for the ACTIVE UX GOAL "
                                "using the current CLEAN_SCREEN_ELEMENTS only."
                            )
                        elif exec_reason.startswith("tap_repair_") and ok:
                            execute_replan_alert = ""

                    if (
                        not primary_fallback_active
                        and ux_goals
                        and ux_goal_idx < len(ux_goals) - 1
                        and len(actions) >= 3
                        and stagnant >= 2
                    ):
                        tail3 = actions[-3:]
                        if all(
                            str((x.get("parsed_action") or {}).get("action_type")) == "input"
                            for x in tail3
                        ):
                            sig3 = [
                                _action_signature_for_guard(x.get("parsed_action") or {})
                                for x in tail3
                            ]
                            if sig3[0] == sig3[1] == sig3[2]:
                                ux_goal_idx += 1
                                stagnant = 0
                                logging.info(
                                    "UX goal forced advance (%d/%d): %s — broke identical-input stagnation.",
                                    ux_goal_idx + 1,
                                    len(ux_goals),
                                    ux_goals[ux_goal_idx],
                                )

                    if trace_f is not None:
                        _append_step_trace(
                            trace_f,
                            step=step_idx,
                            elapsed=elapsed_inner,
                            stagnant=stagnant,
                            element_count=len(elements),
                            screen_hash=screen_hash,
                            prompt_hash=prompt_hash,
                            prompt=prompt,
                            raw=raw,
                            action=action,
                            ok=ok,
                            outcome=outcome,
                            planner_turn=planner_turn_id,
                            batch_index=bi,
                            batch_size=len(batch_actions),
                            pipeline_phase=pipeline_phase,
                            execution_kind=execution_kind,
                        )

                    if not ok:
                        break

                if duration_hit_outer:
                    break

                time.sleep(0.8)

                if ollama_fail_steps >= OLLAMA_DEAD_AFTER_CONSECUTIVE_STEPS:
                    status = f"partial:{PARTIAL_OLLAMA_UNAVAILABLE}"
                    break

    except AnalysisFailure:
        raise
    except subprocess.TimeoutExpired as exc:
        logging.warning("LLM session hit subprocess timeout (continuing cleanup): %s", exc)
        if status == "success":
            status = "partial:adb_timeout"
    except Exception as exc:
        logging.exception("LLM session hit unexpected error (continuing cleanup): %s", exc)
        if status == "success":
            status = "partial:session_error"

    finally:
        if trace_f is not None:
            trace_f.close()
        if audit_f is not None:
            audit_f.close()

    logging.info("LLM agent session ended with status=%s actions=%d", status, len(actions))
    if _NAV_FIRST_PIPELINE:
        nav_obj = _build_navigation_artifact(
            pkg=pkg,
            discovered=exploration_digest,
            transitions=nav_transitions,
            visited_counts=nav_visited_counts,
            nav_graph=nav_graph,
        )
        nav_artifact_path.write_text(json.dumps(nav_obj, indent=2, ensure_ascii=False), encoding="utf-8")

    human_path_obj = output_dir / f"{pkg}_human_ux_report.json"
    human_report = _human_ux_evaluate(
        actions=actions,
        ux_goals=ux_goals,
        final_ux_goal_idx=ux_goal_idx if ux_goals else 0,
        llm_status=status,
    )
    if not simulation_status.startswith("failed:"):
        execute_events = [
            ev
            for ev in actions
            if str(ev.get("pipeline_phase") or "") in ("execute", "primary_ux", "legacy")
        ]
        execute_direct = [
            ev
            for ev in execute_events
            if str((ev.get("parsed_action") or {}).get("action_type") or "")
            in ("tap", "input", "back", "swipe")
            and _execution_counts_as_ux_progress(ev)
        ]
        if status != "success":
            simulation_status = f"failed:{status}"
            simulation_status_detail = status
        elif not execute_events:
            simulation_status = "failed:no_execute_phase"
            simulation_status_detail = "no execute/primary actions recorded"
        elif execute_events and all(int(ev.get("interactive_element_count") or 0) == 0 for ev in execute_events):
            simulation_status = "failed:empty_execute_hierarchy"
            simulation_status_detail = "all execute observations were empty"
        elif ux_goals and len(ux_goals) == 1:
            lone_goal = ux_goals[0]
            if _is_degenerate_transitions_goal(lone_goal):
                simulation_status = "failed:degenerate_goal_plan"
                simulation_status_detail = f"single_goal={lone_goal!r}"
            elif _goal_needs_text_entry_field(lone_goal) and not _single_typing_goal_substantiated(
                lone_goal, actions
            ):
                simulation_status = "failed:no_goal_progress"
                simulation_status_detail = "single_typing_goal_without_input_event"
            elif ux_goal_idx <= 0 and len(actions) >= 8:
                simulation_status = "failed:no_goal_progress"
                simulation_status_detail = f"single_goal_unadvanced index={ux_goal_idx}"
        elif ux_goals and len(ux_goals) > 1 and ux_goal_idx <= 0:
            simulation_status = "failed:no_goal_progress"
            simulation_status_detail = f"final_goal_index={ux_goal_idx} of {len(ux_goals)}"
        elif not execute_direct:
            simulation_status = "failed:no_direct_execute_actions"
            simulation_status_detail = "execute contained no successful tap/input/back/swipe"
        elif human_report["human_ux_overall_pass"]:
            simulation_status = "success"
            simulation_status_detail = "human_ux_overall_pass"
        else:
            simulation_status = "failed:ux_quality_gate"
            simulation_status_detail = "infrastructure completed but UX quality gates did not pass"
    if simulation_status.startswith("failed:") and status == "success":
        status = f"partial:{simulation_status[7:]}"
    infra_status = "success" if status == "success" else status
    human_path_obj.write_text(json.dumps(human_report, indent=2, ensure_ascii=False), encoding="utf-8")
    logging.info(
        "Human UX criteria (%s): mechanistic_pass=%s overall_pass=%s pragmatic_recovery=%s report=%s",
        human_report["criteria_version"],
        human_report["human_ux_mechanistic_pass"],
        human_report["human_ux_overall_pass"],
        human_report.get("human_ux_pragmatic_recovery"),
        human_path_obj,
    )

    return {
        "llm_status": status,
        "llm_infra_status": infra_status,
        "llm_simulation_status": simulation_status,
        "llm_simulation_status_detail": simulation_status_detail,
        "data_quality_status": data_quality_status,
        "llm_actions_count": len(actions),
        "llm_action_log_path": str(action_log),
        "llm_audit_log_path": str(audit_path_obj) if audit_path_obj else "",
        "llm_step_trace_path": str(trace_path_obj) if trace_path_obj else "",
        "llm_ux_goals": ux_goals if ux_goals else [],
        "llm_ux_goal_routes": ux_goal_routes,
        "llm_ux_plan_path": str(ux_plan_path) if ux_plan_path else "",
        "llm_navigation_artifact_path": str(nav_artifact_path) if _NAV_FIRST_PIPELINE else "",
        "llm_primary_ux_fallback_spec": primary_fallback_spec,
        "llm_primary_ux_fallback_reason": primary_fallback_reason,
        "llm_primary_ux_last_micro_intent": primary_micro_intent,
        "llm_root_handoff": {
            "done": root_handoff_done,
            "force_stop": _ROOT_HANDOFF_FORCE_STOP,
            "root_screen_hash": root_screen_hash,
            "root_screen_signature": root_screen_signature,
            "root_screen_hint": root_screen_hint,
            "root_screen_source": root_screen_source,
            "result": {
                k: v
                for k, v in root_handoff_info.items()
                if k not in ("elements", "raw_xml")
            },
        },
        "planner_model": action_model,
        "planner_plan_model": planner_model,
        "webview_dominant": webview_dominant,
        "human_ux_report_path": str(human_path_obj),
        "human_ux_overall_pass": human_report["human_ux_overall_pass"],
        "human_ux_behavior_pass": human_report["human_ux_behavior_pass"],
        "human_ux_mechanistic_pass": human_report["human_ux_mechanistic_pass"],
        "human_ux_session_pass": human_report["human_ux_session_pass"],
        "human_ux_pragmatic_recovery": human_report["human_ux_pragmatic_recovery"],
        "human_ux_criteria_version": human_report["criteria_version"],
    }
