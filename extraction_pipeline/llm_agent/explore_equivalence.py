"""Deterministic old-vs-new explore pick equivalence helpers (Step 5 verification)."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from .action_model import _nav_target_key
from .config import _BFS_INTERIOR_EXPAND_BUDGET
from .explore_policy import ExplorePickResult, ExploreState, ExploreTurnInput, choose_explore_action
from .explore_policy_legacy import choose_explore_action_legacy
from .navigation import _bfs_tap_triggers_interior_expand, _text_entry_probe_field_key


@dataclass
class ExploreEquivalenceSnapshot:
    """One frozen (elements, state, turn) input plus optional expected action from logs."""

    snapshot_id: str
    category: str
    turn: ExploreTurnInput
    state: ExploreState
    expected_action: dict[str, Any] | None = None
    expected_buckets: dict[str, int] | None = None
    verify_logged_action: bool = False


def action_signature(action: dict[str, Any]) -> dict[str, Any]:
    return {
        "action_type": str(action.get("action_type") or ""),
        "reason": str(action.get("reason") or ""),
        "target_resource_id": str(action.get("target_resource_id") or ""),
        "target_content_desc": str(action.get("target_content_desc") or ""),
        "text": str(action.get("text") or action.get("target_text") or ""),
        "x": action.get("x"),
        "y": action.get("y"),
    }


def bucket_signature(result: ExplorePickResult) -> dict[str, int]:
    from .explore_instrumentation import build_explore_candidate_instrumentation

    inst = build_explore_candidate_instrumentation(
        result.turn.elements if hasattr(result, "turn") else [],
        result.nav_cands,
        result.other_cands,
        result.expand_cands,
        result.tab_cands,
        screen_hash="",
        recovery_step=False,
    )
    counts = inst.get("explore_candidate_counts") or {}
    return {
        "nav_cands": int(counts.get("nav_cands") or 0),
        "other_cands": int(counts.get("other_cands") or 0),
        "expand_cands": int(counts.get("expand_cands") or 0),
        "tab_cands": int(counts.get("tab_cands") or 0),
        "skipped_interactive": int(counts.get("skipped_interactive") or 0),
    }


def bucket_signature_from_result(result: ExplorePickResult, elements: list[dict[str, str]]) -> dict[str, int]:
    from .explore_instrumentation import build_explore_candidate_instrumentation

    inst = build_explore_candidate_instrumentation(
        elements,
        result.nav_cands,
        result.other_cands,
        result.expand_cands,
        result.tab_cands,
        screen_hash="",
        recovery_step=False,
    )
    counts = inst.get("explore_candidate_counts") or {}
    return {
        "nav_cands": int(counts.get("nav_cands") or 0),
        "other_cands": int(counts.get("other_cands") or 0),
        "expand_cands": int(counts.get("expand_cands") or 0),
        "tab_cands": int(counts.get("tab_cands") or 0),
        "skipped_interactive": int(counts.get("skipped_interactive") or 0),
    }


def pick_legacy(turn: ExploreTurnInput, state: ExploreState) -> ExplorePickResult:
    return choose_explore_action_legacy(turn, copy.deepcopy(state))


def pick_new(turn: ExploreTurnInput, state: ExploreState) -> ExplorePickResult:
    return choose_explore_action(turn, copy.deepcopy(state))


def compare_picks(
    legacy: ExplorePickResult,
    new: ExplorePickResult,
    *,
    elements: list[dict[str, str]],
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    la = action_signature(legacy.action)
    na = action_signature(new.action)
    if la != na:
        errors.append(f"action mismatch legacy={la} new={na}")
    lb = bucket_signature_from_result(legacy, elements)
    nb = bucket_signature_from_result(new, elements)
    if lb != nb:
        errors.append(f"bucket mismatch legacy={lb} new={nb}")
    return (not errors, errors)


def replay_post_explore_action(
    state: ExploreState,
    action: dict[str, Any],
    *,
    screen_hash: str,
    hash_after: str | None,
    ok: bool = True,
    stall_by_screen: dict[str, int] | None = None,
) -> None:
    """Mirror session.py post-explore state updates (no device I/O)."""
    from .config import _BFS_EXPAND_STALL_LIMIT_PER_SCREEN

    stalls_map = stall_by_screen if stall_by_screen is not None else {}

    reason = str(action.get("reason") or "")
    if reason == "bfs_text_entry_probe" and ok:
        state.bfs_text_entry_probed_keys.add(_text_entry_probe_field_key(screen_hash, action))
    if ok and _bfs_tap_triggers_interior_expand(action):
        state.pending_interior_expand = _BFS_INTERIOR_EXPAND_BUDGET
    if str(action.get("action_type") or "") == "back":
        state.bfs_back_streak += 1
    else:
        state.bfs_back_streak = 0
    if reason.startswith("bfs_expand_"):
        if ok and hash_after and hash_after != screen_hash:
            stalls_map.pop(screen_hash, None)
        else:
            stalls = stalls_map.get(screen_hash, 0) + 1
            if stalls >= _BFS_EXPAND_STALL_LIMIT_PER_SCREEN:
                key = _nav_target_key(action)
                state.bfs_expand_tried_on_screen.setdefault(screen_hash, set()).add(key)
                stalls_map[screen_hash] = 0
            else:
                stalls_map[screen_hash] = stalls


@dataclass
class EquivalenceReport:
    snapshot_id: str
    category: str
    passed: bool
    errors: list[str] = field(default_factory=list)
    legacy_action: dict[str, Any] = field(default_factory=dict)
    new_action: dict[str, Any] = field(default_factory=dict)


def run_snapshot(snapshot: ExploreEquivalenceSnapshot) -> EquivalenceReport:
    legacy = pick_legacy(snapshot.turn, snapshot.state)
    new = pick_new(snapshot.turn, snapshot.state)
    ok, errors = compare_picks(legacy, new, elements=snapshot.turn.elements)
    if snapshot.verify_logged_action and snapshot.expected_action is not None:
        exp = action_signature(snapshot.expected_action)
        got = action_signature(new.action)
        if exp != got:
            errors.append(f"expected log action {exp} got {got}")
            ok = False
    if snapshot.expected_buckets is not None:
        got_b = bucket_signature_from_result(new, snapshot.turn.elements)
        if got_b != snapshot.expected_buckets:
            errors.append(f"expected buckets {snapshot.expected_buckets} got {got_b}")
            ok = False
    return EquivalenceReport(
        snapshot_id=snapshot.snapshot_id,
        category=snapshot.category,
        passed=ok,
        errors=errors,
        legacy_action=action_signature(legacy.action),
        new_action=action_signature(new.action),
    )
