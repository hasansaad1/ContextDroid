"""Single source of truth for session quality / flailing detection rules."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from evaluate_faithfulness import _action_target, _action_type

MECHANICAL_TYPES = frozenset({"back", "wait", "swipe", "scroll"})
PURPOSEFUL_TYPES = frozenset({"tap", "input", "type", "type_text", "fill", "long_press"})
DOMINANT_HASH_FRAC = 0.80
MECHANICAL_MAJORITY_FRAC = 0.50
MIN_PURPOSEFUL_NAMED = 3
DIRECT_RATIO_FLAil_THRESHOLD = 0.40
HIGH_BACK_WAIT_THRESHOLD = 0.50

PHASES_UX_SCORED = ("execute", "primary_ux", "legacy")
PHASES_ALL_UX = ("explore", "execute", "primary_ux", "legacy")
DIRECT_TYPES = frozenset({"tap", "input", "back", "swipe"})


def _direct_action_ratio(report: dict[str, Any] | None) -> float | None:
    if not report:
        return None
    for chk in report.get("checks") or []:
        if chk.get("id") == "direct_action_ratio":
            m = re.search(r"ratio=([0-9.]+)", str(chk.get("detail") or ""))
            if m:
                return float(m.group(1))
    return None


def _named_functional_tap(act: dict[str, Any]) -> bool:
    if _action_type(act) not in PURPOSEFUL_TYPES:
        return False
    pa = act.get("parsed_action") or {}
    rid = str(pa.get("target_resource_id") or "").strip()
    desc = str(pa.get("target_content_desc") or "").strip()
    text = str(pa.get("text") or pa.get("target_text") or "").strip()
    if rid or desc:
        return True
    if _action_type(act) in {"input", "type", "type_text", "fill"} and text:
        return True
    return False


def _phase_events(actions: list[dict[str, Any]], phases: tuple[str, ...]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for act in actions:
        phase = str(act.get("pipeline_phase") or "")
        if phase in phases:
            out.append(act)
        elif not phase and "legacy" in phases:
            out.append(act)
    return out


def _explore_metrics(actions: list[dict[str, Any]]) -> dict[str, Any]:
    explore = _phase_events(actions, ("explore",))
    n = len(explore)
    if n == 0:
        return {
            "explore_action_count": 0,
            "explore_named_tap_ratio": 0.0,
            "explore_back_wait_ratio": 0.0,
            "explore_screen_hash_gain": 0,
            "explore_functional_tap_count": 0,
        }
    named_taps = sum(1 for a in explore if _explore_named_functional_tap(a))
    functional_taps = sum(1 for a in explore if _explore_functional_tap(a))
    back_wait = sum(1 for a in explore if _action_type(a) in {"back", "wait"})
    seen: set[str] = set()
    gain = 0
    for a in explore:
        h = str(a.get("screen_hash") or "")
        if h and h not in seen:
            seen.add(h)
            gain += 1
    return {
        "explore_action_count": n,
        "explore_named_tap_ratio": round(named_taps / n, 4),
        "explore_back_wait_ratio": round(back_wait / n, 4),
        "explore_screen_hash_gain": gain,
        "explore_functional_tap_count": functional_taps,
    }


def _explore_input_effective(act: dict[str, Any]) -> bool:
    """True when an explore input changed the screen or was stamped effective (e.g. Frida)."""
    stamped = act.get("explore_input_effective")
    if stamped is True:
        return True
    if stamped is False:
        return False
    sh = str(act.get("screen_hash") or "")
    sha = act.get("screen_hash_after")
    return bool(sh and isinstance(sha, str) and sha and sh != sha)


def _explore_functional_tap(act: dict[str, Any]) -> bool:
    """Successful explore engagement: tap/input, excluding back/wait recovery.

    Includes anonymous bounds-center taps admitted by Step 2 (not only named targets).
    Inputs count only when effective (screen change or stamped downstream signal) — repeated
    no-op probes are type-loops and must not inflate functional tap counts.
    """
    if not act.get("action_success"):
        return False
    at = _action_type(act)
    if at in {"back", "wait"}:
        return False
    if at == "tap":
        return True
    if at in {"input", "type", "type_text", "fill"}:
        pa = act.get("parsed_action") or {}
        if not str(pa.get("text") or pa.get("target_text") or "").strip():
            return False
        return _explore_input_effective(act)
    return False


def _explore_named_functional_tap(act: dict[str, Any]) -> bool:
    if _action_type(act) != "tap" or not act.get("action_success"):
        return False
    pa = act.get("parsed_action") or {}
    rid = str(pa.get("target_resource_id") or "").strip()
    desc = str(pa.get("target_content_desc") or "").strip()
    text = str(pa.get("target_text") or pa.get("text") or "").strip()
    return bool(rid or desc or text)


def _all_phase_direct_action_ratio(actions: list[dict[str, Any]]) -> float:
    scored = _phase_events(actions, PHASES_ALL_UX)
    direct = [
        ev
        for ev in scored
        if _action_type(ev) in DIRECT_TYPES and bool(ev.get("action_success"))
    ]
    return round(len(direct) / max(1, len(scored)), 4)


def _hash_dominance_stats(actions: list[dict[str, Any]]) -> tuple[float, str, int, int]:
    hashes = [a.get("screen_hash") for a in actions if a.get("screen_hash")]
    if not hashes:
        return 0.0, "", 0, len(hashes)
    hash_counts = Counter(hashes)
    top_hash, top_n = hash_counts.most_common(1)[0]
    return (top_n / len(hashes)), str(top_hash), top_n, len(hashes)


def detect_flailing_legacy(
    actions: list[dict[str, Any]],
    *,
    sim_status: str,
    report: dict[str, Any] | None,
) -> tuple[bool, list[str]]:
    """Pre-merge rules from assemble_working_dataset (session-wide hash patterns)."""
    if not actions:
        return True, ["no agent actions recorded"]

    successful = [a for a in actions if a.get("action_success")]
    if not successful:
        return True, ["no successful actions"]

    mech = sum(1 for a in successful if _action_type(a) in MECHANICAL_TYPES)
    mech_frac = mech / len(successful)
    named = sum(1 for a in successful if _named_functional_tap(a))
    named_targets = Counter(
        (_action_target(a) or _action_type(a))
        for a in successful
        if _named_functional_tap(a)
    )

    hash_dom, top_hash, top_n, hash_n = _hash_dominance_stats(actions)
    direct_ratio = _direct_action_ratio(report)
    reasons: list[str] = []

    if mech_frac >= MECHANICAL_MAJORITY_FRAC and named < MIN_PURPOSEFUL_NAMED:
        reasons.append(
            f"mechanical_majority: {mech}/{len(successful)} successful actions are back/wait/swipe/scroll "
            f"({mech_frac:.0%}); named_functional_taps={named}"
        )

    if hash_dom >= DOMINANT_HASH_FRAC and named < MIN_PURPOSEFUL_NAMED:
        reasons.append(
            f"dominant_screen: hash {str(top_hash)[:12]}… on {top_n}/{hash_n} steps ({hash_dom:.0%}); "
            f"named_functional_taps={named}"
        )
    elif hash_dom >= DOMINANT_HASH_FRAC and named >= MIN_PURPOSEFUL_NAMED:
        top_target_n = named_targets.most_common(1)[0][1] if named_targets else 0
        if top_target_n >= max(3, int(named * 0.75)):
            reasons.append(
                f"same_element_cycle: screen hash {str(top_hash)[:12]}… dominates ({hash_dom:.0%}) and "
                f"top named target repeated {top_target_n}/{named} times"
            )

    if sim_status == "success" and direct_ratio is not None and direct_ratio < DIRECT_RATIO_FLAil_THRESHOLD:
        reasons.append(
            f"low_direct_action_ratio: sim_status=success but direct_action_ratio={direct_ratio:.2f} "
            f"(<{DIRECT_RATIO_FLAil_THRESHOLD})"
        )

    return bool(reasons), reasons


def detect_flailing_interim_new(
    actions: list[dict[str, Any]],
    *,
    sim_status: str,
    all_phase_ratio: float | None = None,
    explore_metrics: dict[str, Any] | None = None,
) -> tuple[bool, list[str]]:
    """Interim phase-aware rules (_flailing_new) kept for before/after comparison."""
    if all_phase_ratio is None:
        all_phase_ratio = _all_phase_direct_action_ratio(actions)
    if explore_metrics is None:
        explore_metrics = _explore_metrics(actions)

    reasons: list[str] = []
    if (
        explore_metrics["explore_back_wait_ratio"] > HIGH_BACK_WAIT_THRESHOLD
        and explore_metrics["explore_functional_tap_count"] < MIN_PURPOSEFUL_NAMED
    ):
        reasons.append(
            f"explore_back_wait_dominant: ratio={explore_metrics['explore_back_wait_ratio']:.2f} "
            f"functional_taps={explore_metrics['explore_functional_tap_count']}"
        )
    if sim_status == "success" and all_phase_ratio < DIRECT_RATIO_FLAil_THRESHOLD:
        reasons.append(
            f"low_all_phase_direct_ratio: {all_phase_ratio:.2f} (<{DIRECT_RATIO_FLAil_THRESHOLD})"
        )
    successful = [a for a in actions if a.get("action_success")]
    if successful:
        mech = sum(1 for a in successful if _action_type(a) in MECHANICAL_TYPES)
        named = sum(1 for a in successful if _named_functional_tap(a))
        if mech / len(successful) >= MECHANICAL_MAJORITY_FRAC and named < MIN_PURPOSEFUL_NAMED:
            reasons.append(
                f"mechanical_majority_session: {mech}/{len(successful)} mechanical; named={named}"
            )
    return bool(reasons), reasons


def detect_suspect_flailing(
    actions: list[dict[str, Any]],
    *,
    sim_status: str,
    report: dict[str, Any] | None = None,
    all_phase_ratio: float | None = None,
    explore_metrics: dict[str, Any] | None = None,
) -> tuple[bool, list[str]]:
    """Merged flailing rules — single source used by curation and metrics."""
    if not actions:
        return True, ["no agent actions recorded"]

    successful = [a for a in actions if a.get("action_success")]
    if not successful:
        return True, ["no successful actions"]

    if all_phase_ratio is None:
        all_phase_ratio = _all_phase_direct_action_ratio(actions)
    if explore_metrics is None:
        explore_metrics = _explore_metrics(actions)

    reasons: list[str] = []

    mech = sum(1 for a in successful if _action_type(a) in MECHANICAL_TYPES)
    mech_frac = mech / len(successful)
    session_named = sum(1 for a in successful if _named_functional_tap(a))
    if mech_frac >= MECHANICAL_MAJORITY_FRAC and session_named < MIN_PURPOSEFUL_NAMED:
        reasons.append(
            f"mechanical_majority: {mech}/{len(successful)} successful actions are back/wait/swipe/scroll "
            f"({mech_frac:.0%}); named_functional_taps={session_named}"
        )

    if (
        explore_metrics["explore_back_wait_ratio"] > HIGH_BACK_WAIT_THRESHOLD
        and explore_metrics["explore_functional_tap_count"] < MIN_PURPOSEFUL_NAMED
    ):
        reasons.append(
            f"explore_back_wait_dominant: ratio={explore_metrics['explore_back_wait_ratio']:.2f} "
            f"functional_taps={explore_metrics['explore_functional_tap_count']}"
        )

    ux_actions = _phase_events(actions, PHASES_UX_SCORED)
    ux_successful = [a for a in ux_actions if a.get("action_success")]
    ux_named = sum(1 for a in ux_successful if _named_functional_tap(a))
    ux_hash_dom, ux_top_hash, ux_top_n, ux_hash_n = _hash_dominance_stats(ux_actions)

    if ux_hash_dom >= DOMINANT_HASH_FRAC and ux_named < MIN_PURPOSEFUL_NAMED:
        reasons.append(
            f"dominant_screen: hash {str(ux_top_hash)[:12]}… on {ux_top_n}/{ux_hash_n} execute+primary steps "
            f"({ux_hash_dom:.0%}); named_functional_taps={ux_named}"
        )

    session_named_targets = Counter(
        (_action_target(a) or _action_type(a))
        for a in successful
        if _named_functional_tap(a)
    )
    session_hash_dom, session_top_hash, session_top_n, session_hash_n = _hash_dominance_stats(actions)
    # Session-wide repetition: execute+primary-only scoping misses cases like coolmicapp
    # (explore taps inflate session-wide named repetition that is absent on ux-only steps).
    if session_hash_dom >= DOMINANT_HASH_FRAC and session_named >= MIN_PURPOSEFUL_NAMED:
        top_target_n = session_named_targets.most_common(1)[0][1] if session_named_targets else 0
        if top_target_n >= max(3, int(session_named * 0.75)):
            reasons.append(
                f"same_element_cycle: screen hash {str(session_top_hash)[:12]}… dominates ({session_hash_dom:.0%}) and "
                f"top named target repeated {top_target_n}/{session_named} times"
            )

    if sim_status == "success" and all_phase_ratio < DIRECT_RATIO_FLAil_THRESHOLD:
        reasons.append(
            f"low_all_phase_direct_ratio: {all_phase_ratio:.2f} (<{DIRECT_RATIO_FLAil_THRESHOLD})"
        )

    return bool(reasons), reasons
