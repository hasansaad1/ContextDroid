#!/usr/bin/env python3
"""Evaluate simulation faithfulness (interaction quality, not trace richness)."""

from __future__ import annotations

import argparse
import csv
import json
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluate_scenario_level import _load_actions

JUDGE_VERSION = "faithfulness_v2_phase_aware"

LOGIN_GATE_RE = re.compile(
    r"\b(sign\s*in|log\s*in|login|create\s+account|register|permission|allow\s+access|grant|welcome|authenticate)\b",
    re.I,
)
DEGRADED_RE = re.compile(
    r"\b(offline|no\s+network|network\s+error|connection\s+failed|unable\s+to\s+connect|timeout|retry)\b",
    re.I,
)
LICENSE_GATE_RE = re.compile(
    r"\b(license|licence|activation|enter your shop|license_key)\b",
    re.I,
)
HARD_FAIL_STATUSES = {
    "failed:partial:agent_stuck",
    "failed:skip:login_required",
}
RECOVERABLE_MISMATCH_STATUS = "failed:partial:foreground_mismatch"
RECOVERABLE_HANDOFF_STATUS = "failed:bad_handoff"
INTERACTIVE_TYPES = {"tap", "input", "swipe", "scroll", "long_press", "type", "fill"}
MEANINGFUL_INTERACTIVE_TYPES = INTERACTIVE_TYPES  # back/wait excluded explicitly in C2/C3
EXPLORE_BACK_WAIT_THRESHOLD = 0.50
MIN_NAMED_FUNCTIONAL_EXPLORE_TAPS = 3
MIN_FUNCTIONAL_EXPLORE_SCREENS = 2

OVERNIGHT_CUTOFF_ISO = "2026-06-28T21:41:00Z"


def _short(h: str | None, n: int = 10) -> str:
    return (h or "")[:n]


def _action_type(act: dict[str, Any]) -> str:
    pa = act.get("parsed_action") or {}
    return str(pa.get("action_type") or act.get("action_type") or "").lower()


def _action_reason(act: dict[str, Any]) -> str:
    pa = act.get("parsed_action") or {}
    return str(pa.get("reason") or act.get("reason") or "")


def _action_target(act: dict[str, Any]) -> str:
    pa = act.get("parsed_action") or {}
    parts = [
        str(pa.get("target_resource_id") or ""),
        str(pa.get("target_content_desc") or ""),
        str(pa.get("target_text") or pa.get("text") or ""),
    ]
    return " ".join(p for p in parts if p).strip()


def _infer_app(meta: dict[str, Any], plan: dict[str, Any]) -> dict[str, str]:
    ctx = meta.get("app_context") or {}
    category = str(ctx.get("category") or "Unknown").strip()
    purpose = str(ctx.get("purpose") or "").strip()
    if purpose in ("", "No description available"):
        purpose = ""
    pkg = str(meta.get("package_name") or ctx.get("package_name") or "")
    flows = ctx.get("key_user_flows") or []
    digest = plan.get("screen_digest") or {}
    goal_n = len(plan.get("goals") or [])
    screen_n = len(digest)

    app_type = category if category != "Unknown" else _guess_type_from_package(pkg)
    if not purpose:
        purpose = _guess_purpose(pkg, app_type, digest)

    expected = _expected_flows(app_type, purpose, flows, digest, goal_n)
    simple = _is_simple_app(app_type, screen_n, goal_n, digest)
    return {
        "app_type": app_type,
        "purpose": purpose,
        "expected_use": expected,
        "simple_or_complex": "simple" if simple else "complex",
    }


def _guess_type_from_package(pkg: str) -> str:
    p = pkg.lower()
    if any(x in p for x in ("vpn", "security", "password", "auth")):
        return "Security"
    if any(x in p for x in ("music", "audio", "player", "radio")):
        return "Media"
    if any(x in p for x in ("calc", "flash", "torch", "compass", "timer")):
        return "Utility"
    if any(x in p for x in ("mail", "message", "chat", "social")):
        return "Communication"
    if any(x in p for x in ("map", "gps", "nav")):
        return "Navigation"
    return "General"


def _guess_purpose(pkg: str, app_type: str, digest: dict[str, Any]) -> str:
    hints = " ".join(str(v) for v in digest.values())[:400].lower()
    if "sign in" in hints or "login" in hints:
        return f"{app_type} app with account/login gate"
    if app_type == "Media":
        return "Play or browse media content"
    if app_type == "Utility":
        return "Use a focused single-purpose tool"
    return f"{app_type} app ({pkg})"


def _expected_flows(
    app_type: str, purpose: str, flows: list[Any], digest: dict[str, Any], goal_n: int
) -> str:
    if flows:
        return "; ".join(str(f) for f in flows[:4])
    digest_hints = list(digest.values())[:5]
    controls = " · ".join(str(h)[:60] for h in digest_hints if h)
    if app_type == "Security":
        return "Open app, configure or use security feature (connect/browse settings); login may gate full use"
    if app_type == "Media":
        return "Browse library, play or queue tracks, navigate artists/albums/playlists"
    if app_type == "Utility":
        return "Open app and use its primary control or view"
    if controls:
        return f"Interact with discovered UI: {controls[:180]}"
    if goal_n:
        return f"Execute planned goals across {goal_n} post-explore steps"
    return purpose or "Explore and use primary in-app features"


def _is_simple_app(app_type: str, screen_n: int, goal_n: int, digest: dict[str, Any]) -> bool:
    if app_type == "Utility":
        return True
    if screen_n <= 3 and goal_n <= 4:
        return True
    text = " ".join(str(v).lower() for v in digest.values())
    if screen_n <= 4 and any(k in text for k in ("flash", "torch", "calculator", "timer", "compass")):
        return True
    return screen_n <= 2 and goal_n <= 3


def _classify_screens(digest: dict[str, Any]) -> dict[str, list[str]]:
    login: list[str] = []
    functional: list[str] = []
    for h, hint in digest.items():
        text = str(hint)
        if LOGIN_GATE_RE.search(text):
            login.append(_short(h))
        else:
            functional.append(_short(h))
    return {"login_gate": login, "functional": functional}


def _explore_phase_metrics(actions: list[dict[str, Any]]) -> dict[str, Any]:
    from quality_rules import _explore_metrics

    return _explore_metrics(actions)


def _functional_explore_screen_hashes(
    actions: list[dict[str, Any]], digest: dict[str, Any]
) -> list[str]:
    from quality_rules import _phase_events

    screens = _classify_screens(digest)
    seen: set[str] = set()
    out: list[str] = []
    for act in _phase_events(actions, ("explore",)):
        h = str(act.get("screen_hash") or "")
        if not h or h in seen:
            continue
        role = str((act.get("app_state") or {}).get("screen_role") or "")
        iec = int(act.get("interactive_element_count") or 0)
        if role == "empty_hierarchy" or iec == 0:
            continue
        if any(h.startswith(prefix) for prefix in screens["login_gate"]):
            continue
        seen.add(h)
        out.append(h)
    return out


def _named_functional_explore_tap_count(actions: list[dict[str, Any]]) -> int:
    from quality_rules import _explore_named_functional_tap, _phase_events

    explore = _phase_events(actions, ("explore",))
    return sum(1 for a in explore if _explore_named_functional_tap(a))


def _substantial_real_engagement(
    actions: list[dict[str, Any]], digest: dict[str, Any], explore_metrics: dict[str, Any]
) -> bool:
    if int(explore_metrics.get("explore_functional_tap_count") or 0) >= MIN_NAMED_FUNCTIONAL_EXPLORE_TAPS:
        return True
    if _named_functional_explore_tap_count(actions) >= MIN_NAMED_FUNCTIONAL_EXPLORE_TAPS:
        return True
    if len(_functional_explore_screen_hashes(actions, digest)) >= MIN_FUNCTIONAL_EXPLORE_SCREENS:
        return True
    return False


def _judge_c0(actions: list[dict[str, Any]], digest: dict[str, Any]) -> dict[str, Any]:
    explore_metrics = _explore_phase_metrics(actions)
    named = _named_functional_explore_tap_count(actions)
    functional_screens = _functional_explore_screen_hashes(actions, digest)
    passed = named >= MIN_NAMED_FUNCTIONAL_EXPLORE_TAPS or len(functional_screens) >= MIN_FUNCTIONAL_EXPLORE_SCREENS
    return {
        "value": "yes" if passed else "no",
        "evidence": {
            "named_functional_explore_taps": named,
            "functional_explore_screen_hashes": len(functional_screens),
            "explore_functional_tap_count": explore_metrics.get("explore_functional_tap_count"),
            "explore_back_wait_ratio": explore_metrics.get("explore_back_wait_ratio"),
            "explore_screen_hash_gain": explore_metrics.get("explore_screen_hash_gain"),
        },
    }


def _gate_stuck_failed(
    actions: list[dict[str, Any]], digest: dict[str, Any], c1: dict[str, Any]
) -> tuple[bool, str]:
    from quality_rules import _phase_events

    screens = _classify_screens(digest)
    explore = _phase_events(actions, ("explore",))
    if not explore:
        return False, ""

    functional_visited = bool(c1["evidence"].get("functional_screen_hashes"))
    digest = digest or {}
    only_gate_screens = False
    if functional_visited:
        func_hashes = c1["evidence"].get("functional_screen_hashes") or []
        gateish = 0
        for fh in func_hashes:
            for h, hint in digest.items():
                if str(h).startswith(str(fh)[:10]) or str(fh).startswith(str(h)[:10]):
                    if LOGIN_GATE_RE.search(str(hint)) or LICENSE_GATE_RE.search(str(hint)):
                        gateish += 1
                    break
        only_gate_screens = gateish >= len(func_hashes)

    login_only = bool(screens["login_gate"]) and not functional_visited
    license_taps = 0
    gate_taps = 0
    for act in explore:
        if _action_type(act) != "tap" or not act.get("action_success"):
            continue
        target = _action_target(act).lower()
        if "license" in target or "licence" in target:
            license_taps += 1
        if any(k in target for k in ("sign in", "login", "register", "permission", "license", "licence")):
            gate_taps += 1

    if license_taps >= 2 and (not functional_visited or only_gate_screens):
        return True, f"license gate stuck ({license_taps} license taps, no post-gate functionality)"
    if login_only and gate_taps >= 2 and _named_functional_explore_tap_count(actions) == 0:
        return True, "never passed entry/login gate into real functionality"
    if (
        not functional_visited
        and int(c1["evidence"].get("distinct_screen_hashes") or 0) <= 1
        and sum(1 for a in explore if _action_type(a) in {"back", "wait"}) >= max(3, len(explore) // 2)
    ):
        return True, "explore never left launch/empty surface"
    return False, ""


def _effective_text_input_count(actions: list[dict[str, Any]]) -> int:
    from quality_rules import _explore_input_effective

    n = 0
    for act in actions:
        if _action_type(act) not in {"input", "type", "type_text", "fill"}:
            continue
        pa = act.get("parsed_action") or {}
        if not str(pa.get("text") or pa.get("target_text") or "").strip():
            continue
        if _explore_input_effective(act) or act.get("pipeline_phase") != "explore":
            n += 1
    return n


def _media_defining_action_seen(actions: list[dict[str, Any]]) -> bool:
    hints = (
        "play",
        "pause",
        "shuffle",
        "album",
        "artist",
        "playlist",
        "queue",
        "track",
        "library",
        "browse",
    )
    for act in actions:
        if _action_type(act) not in {"tap", "input"} or not act.get("action_success"):
            continue
        blob = f"{_action_target(act)} {_action_reason(act)}".lower()
        if any(h in blob for h in hints):
            return True
    return False


def _defining_action_gate(
    actions: list[dict[str, Any]], app_info: dict[str, str], pkg: str, explore_metrics: dict[str, Any]
) -> tuple[bool, str]:
    pkg_l = pkg.lower()
    purpose = str(app_info.get("purpose") or "").lower()
    app_type = str(app_info.get("app_type") or "")

    keyboard_app = any(k in pkg_l for k in ("yidkey", "keyboard", "inputmethod", "ime"))
    keyboard_app = keyboard_app or "keyboard" in purpose or "typing" in purpose
    if keyboard_app:
        if _effective_text_input_count(actions) == 0:
            return False, "keyboard/input app with no effective typing event"

    if app_type == "Media" or any(k in pkg_l for k in ("music", "player", "radio", "retromusic")):
        if not _media_defining_action_seen(actions):
            swipes = sum(1 for a in actions if _action_type(a) == "swipe")
            taps = int(explore_metrics.get("explore_functional_tap_count") or 0)
            if swipes >= 3 and taps == 0:
                return False, "media app without playback/library interaction (scroll-only)"

    if "mensa" in pkg_l or "menu" in purpose:
        ft = int(explore_metrics.get("explore_functional_tap_count") or 0)
        bw = float(explore_metrics.get("explore_back_wait_ratio") or 0)
        if ft == 0 or bw >= EXPLORE_BACK_WAIT_THRESHOLD:
            return False, "menu/meal app without meaningful menu exploration"

    return True, ""


def _judge_c1(
    actions: list[dict[str, Any]], digest: dict[str, Any], simple: bool
) -> dict[str, Any]:
    screens = _classify_screens(digest)
    hashes = {a.get("screen_hash") for a in actions if a.get("screen_hash")}
    hashes |= {a.get("screen_hash_after") for a in actions if a.get("screen_hash_after")}
    functional_visited = [
        h for h in hashes if any(h.startswith(f) for f in screens["functional"])
    ]
    login_visited = [h for h in hashes if any(h.startswith(l) for l in screens["login_gate"])]

    if functional_visited:
        value = "yes" if len(functional_visited) >= (1 if simple else 2) else "partial"
    elif login_visited and len(hashes) >= 1:
        value = "partial"
    elif len(hashes) >= 2:
        value = "partial"
    else:
        value = "no"

    return {
        "value": value,
        "evidence": {
            "distinct_screen_hashes": len(hashes),
            "functional_screen_hashes": functional_visited[:6],
            "login_gate_hashes": login_visited[:4],
            "digest_functional_hints": [
                str(digest[h])[:80]
                for h in digest
                if _short(h) in screens["functional"]
            ][:4],
        },
    }


def _judge_c2(actions: list[dict[str, Any]]) -> dict[str, Any]:
    interactive = [
        a
        for a in actions
        if _action_type(a) in MEANINGFUL_INTERACTIVE_TYPES and _action_type(a) not in {"back", "wait"}
    ]
    if not interactive:
        waits = sum(1 for a in actions if _action_type(a) == "wait")
        backs = sum(1 for a in actions if _action_type(a) == "back")
        return {
            "value": "no",
            "evidence": {
                "meaningful_interactive_actions": 0,
                "wait_actions": waits,
                "back_actions": backs,
                "action_success_rate": 0.0,
                "note": "no meaningful tap/input/swipe actions (back/wait excluded)",
            },
        }

    successes = sum(1 for a in interactive if a.get("action_success"))
    rate = successes / len(interactive)
    failed_targets: Counter[str] = Counter()
    for a in interactive:
        if not a.get("action_success"):
            failed_targets[_action_target(a) or _action_type(a)] += 1
    repeat_fail = {k: v for k, v in failed_targets.items() if v >= 3}

    if rate >= 0.65 and not repeat_fail:
        value = "yes"
    elif rate >= 0.35 or successes >= 3:
        value = "partial"
    else:
        value = "no"

    return {
        "value": value,
        "evidence": {
            "meaningful_interactive_actions": len(interactive),
            "successful_meaningful_interactive": successes,
            "action_success_rate": round(rate, 3),
            "repeat_failed_targets": dict(list(repeat_fail.items())[:5]),
            "note": "back/wait excluded from interactive success rate",
        },
    }


def _judge_c3(actions: list[dict[str, Any]], duration_sec: float) -> dict[str, Any]:
    ok = [
        a
        for a in actions
        if a.get("action_success")
        and a.get("ts_epoch_ms")
        and _action_type(a) not in {"back", "wait"}
    ]
    if len(ok) < 2:
        return {
            "value": "stalled",
            "evidence": {
                "meaningful_successful_actions_with_ts": len(ok),
                "note": "too few timed meaningful successes (back/wait excluded)",
            },
        }

    ts = [int(a["ts_epoch_ms"]) for a in ok]
    start, end = min(ts), max(ts)
    span = max(1, end - start)
    bins = [0, 0, 0, 0]
    for t in ts:
        q = min(3, int((t - start) / span * 4))
        bins[q] += 1
    total = sum(bins)
    fracs = [b / total for b in bins]
    last_half = fracs[2] + fracs[3]
    first_half = fracs[0] + fracs[1]
    active_quartiles = sum(1 for f in fracs if f >= 0.1)

    if active_quartiles >= 3 or last_half >= 0.25:
        value = "sustained"
    elif first_half >= 0.75 and last_half < 0.1:
        value = "front-loaded"
    elif last_half < 0.1 or (duration_sec > 120 and len(ok) < 5):
        value = "stalled"
    else:
        value = "sustained" if active_quartiles >= 2 else "front-loaded"

    return {
        "value": value,
        "evidence": {
            "meaningful_successful_actions": len(ok),
            "temporal_quartile_fracs": [round(f, 3) for f in fracs],
            "session_duration_sec": duration_sec,
            "first_action_step": ok[0].get("step"),
            "last_action_step": ok[-1].get("step"),
            "note": "back/wait excluded from sustained-engagement timing",
        },
    }


def _judge_c4(sim_status: str, *, substantial: bool) -> dict[str, Any]:
    if sim_status in HARD_FAIL_STATUSES:
        return {"value": "hard-fail", "evidence": {"llm_simulation_status": sim_status, "class": "fatal"}}
    if sim_status == RECOVERABLE_MISMATCH_STATUS:
        if substantial:
            return {
                "value": "recoverable-mismatch",
                "evidence": {
                    "llm_simulation_status": sim_status,
                    "class": "recoverable",
                    "note": "foreground mismatch after substantial explore engagement",
                },
            }
        return {"value": "hard-fail", "evidence": {"llm_simulation_status": sim_status, "class": "fatal"}}
    if sim_status == RECOVERABLE_HANDOFF_STATUS:
        if substantial:
            return {
                "value": "recoverable-handoff",
                "evidence": {
                    "llm_simulation_status": sim_status,
                    "class": "recoverable",
                    "note": "bad handoff after real in-app engagement",
                },
            }
        return {
            "value": "soft-fail",
            "evidence": {
                "llm_simulation_status": sim_status,
                "class": "fatal_handoff_no_engagement",
                "note": "bad handoff before meaningful app use",
            },
        }
    if sim_status == "success":
        return {"value": "clean", "evidence": {"llm_simulation_status": sim_status}}
    return {"value": "soft-fail", "evidence": {"llm_simulation_status": sim_status}}


def _judge_c5(actions: list[dict[str, Any]], app_type: str) -> dict[str, Any]:
    reasons = " ".join(_action_reason(a) for a in actions).lower()
    digest_text = reasons
    degraded_hits = DEGRADED_RE.findall(digest_text)
    network_app = app_type in {"Communication", "Navigation", "Security", "Media"} or "network" in reasons
    if degraded_hits and network_app:
        value = "degraded"
    elif degraded_hits:
        value = "degraded"
    elif network_app:
        value = "realistic"
    else:
        value = "unknown"
    return {
        "value": value,
        "evidence": {
            "degraded_keyword_hits": degraded_hits[:5],
            "network_dependent_app_type": network_app,
        },
    }


def _judge_c6(actions: list[dict[str, Any]], explore_metrics: dict[str, Any], c0: dict[str, Any]) -> dict[str, Any]:
    from quality_rules import _all_phase_direct_action_ratio, _phase_events

    explore_bw = float(explore_metrics.get("explore_back_wait_ratio") or 0)
    explore_ft = int(explore_metrics.get("explore_functional_tap_count") or 0)
    direct_ratio = _all_phase_direct_action_ratio(actions)
    c0_passed = c0["value"] == "yes"

    explore = _phase_events(actions, ("explore",))
    explore_backs = sum(1 for a in explore if _action_type(a) == "back")
    explore_waits = sum(1 for a in explore if _action_type(a) == "wait")

    if explore_bw >= EXPLORE_BACK_WAIT_THRESHOLD and not c0_passed:
        return {
            "value": "mechanical",
            "evidence": {
                "explore_back_wait_ratio": explore_bw,
                "explore_functional_tap_count": explore_ft,
                "all_phase_direct_action_ratio": direct_ratio,
                "explore_back_actions": explore_backs,
                "explore_wait_actions": explore_waits,
                "c0_explore_engagement": c0["value"],
                "justification": "explore dominated by back/wait without C0 explore engagement (primary_ux cannot rescue)",
            },
        }

    if direct_ratio >= 0.65 and explore_bw < EXPLORE_BACK_WAIT_THRESHOLD:
        value = "human-like"
        note = f"all_phase_direct_ratio={direct_ratio:.2f}; explore back/wait={explore_bw:.2f}"
    elif direct_ratio >= 0.45 and explore_bw < 0.35:
        value = "mixed"
        note = f"all_phase_direct_ratio={direct_ratio:.2f}; moderate explore recovery"
    elif explore_bw >= 0.35 and explore_ft < 2:
        value = "mechanical"
        note = "explore back/wait heavy with almost no functional explore taps"
    else:
        value = "mixed"
        note = "exploration-heavy but explore phase not dominated by idle recovery"

    return {
        "value": value,
        "evidence": {
            "all_phase_direct_action_ratio": direct_ratio,
            "explore_back_wait_ratio": explore_bw,
            "explore_functional_tap_count": explore_ft,
            "explore_back_actions": explore_backs,
            "explore_wait_actions": explore_waits,
            "justification": note,
        },
    }


def _verdict(
    simple: bool,
    sim: str,
    c0: dict[str, Any],
    c1: dict[str, Any],
    c2: dict[str, Any],
    c3: dict[str, Any],
    c4: dict[str, Any],
    c6: dict[str, Any],
    *,
    gate_stuck: bool,
    gate_stuck_reason: str,
    defining_ok: bool,
    defining_reason: str,
    sim_override: str | None = None,
) -> tuple[str, str]:
    if gate_stuck:
        return "FAILED", gate_stuck_reason

    if c4["value"] == "hard-fail":
        return "FAILED", f"hard failure exit: {c4['evidence']['llm_simulation_status']}"

    if c6["value"] == "mechanical":
        return "FAILED", c6["evidence"].get(
            "justification", "explore dominated by back/wait with insufficient functional taps"
        )

    if c1["value"] == "no":
        return "FAILED", "never reached real functional screens"

    if c3["value"] == "stalled":
        return "FAILED", "launch-only or stalled session (no sustained meaningful engagement)"

    recoverable = c4["value"] in {"recoverable-mismatch", "recoverable-handoff"}
    sim_ok = sim == "success" or bool(sim_override)

    if c4["value"] == "soft-fail" and c4["evidence"].get("class") == "fatal_handoff_no_engagement":
        if c1["value"] == "no":
            return "FAILED", c4["evidence"].get("note", "bad handoff before meaningful app use")
        return "PARTIAL", c4["evidence"].get("note", "bad handoff limited real app use")

    if not defining_ok:
        return "PARTIAL", defining_reason

    faithful_core = (
        c0["value"] == "yes"
        and c1["value"] in {"yes", "partial"}
        and c2["value"] in {"yes", "partial"}
        and c6["value"] in {"human-like", "mixed"}
        and c3["value"] in {"sustained", "front-loaded"}
    )

    if faithful_core and sim_ok:
        if c0["value"] == "yes" and c1["value"] == "yes" and c2["value"] == "yes":
            return "FAITHFUL", "explore engagement + real screens + successful actions + coherent session"
        if simple and c0["value"] == "yes":
            return "FAITHFUL", "simple app: genuine explore engagement on real screens"

    if faithful_core and recoverable and not sim_ok:
        return "PARTIAL", f"strong engagement but sim={sim} ({c4['value']})"

    if recoverable and c0["value"] == "yes" and sim_ok and sim_override:
        return "FAITHFUL", f"substantial engagement with recoverable sim exit ({sim_override})"

    if recoverable:
        return "PARTIAL", c4["evidence"].get("note", f"recoverable simulation exit: {sim}")

    if c1["value"] in {"yes", "partial"} and c2["value"] in {"yes", "partial"}:
        if c0["value"] == "no":
            return "PARTIAL", "some screen/action engagement but insufficient explore functional depth"
        return "PARTIAL", "engaged app incompletely but without hard failure"

    return "FAILED", "insufficient real engagement despite no hard exit"


def _coverage_gap(expected: str, actions: list[dict[str, Any]], plan: dict[str, Any], c1: dict[str, Any]) -> str:
    goals = plan.get("goals") or []
    executed_phases = {a.get("pipeline_phase") for a in actions}
    missing: list[str] = []
    if "execute" not in executed_phases and goals:
        missing.append("post-explore execute goals not reached")
    if c1["value"] == "partial":
        missing.append("login-gated or secondary flows beyond initial functional screen")
    if goals and len(goals) > 4:
        missing.append(f"deeper planned goals beyond early steps ({len(goals)} planned)")
    if not missing:
        return f"Core flows from expected use largely touched; residual: {expected[:120]}"
    return "; ".join(missing)


def evaluate_session(base: Path, pkg: str, meta: dict[str, Any]) -> dict[str, Any]:
    plan_path = base / f"{pkg}_llm_ux_plan.json"
    actions_path = base / f"{pkg}_llm_actions.jsonl"
    report_path = base / f"{pkg}_human_ux_report.json"

    plan = json.loads(plan_path.read_text(encoding="utf-8")) if plan_path.exists() else {}
    actions = _load_actions(actions_path)
    report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else None

    app_info = _infer_app(meta, plan)
    digest = plan.get("screen_digest") or {}
    duration = float(meta.get("elapsed_sec") or meta.get("duration_sec") or 0)
    sim = str(meta.get("llm_simulation_status") or "")

    explore_metrics = _explore_phase_metrics(actions)
    substantial = _substantial_real_engagement(actions, digest, explore_metrics)

    c0 = _judge_c0(actions, digest)
    c1 = _judge_c1(actions, digest, app_info["simple_or_complex"] == "simple")
    c2 = _judge_c2(actions)
    c3 = _judge_c3(actions, duration)
    c4 = _judge_c4(sim, substantial=substantial)
    c5 = _judge_c5(actions, app_info["app_type"])
    c6 = _judge_c6(actions, explore_metrics, c0)

    gate_stuck, gate_reason = _gate_stuck_failed(actions, digest, c1)
    defining_ok, defining_reason = _defining_action_gate(actions, app_info, pkg, explore_metrics)

    sim_override: str | None = None
    if c4["value"] == "recoverable-mismatch":
        sim_override = "recoverable_foreground_mismatch_after_substantial_explore"
    elif c4["value"] == "recoverable-handoff" and substantial:
        sim_override = "recoverable_bad_handoff_after_substantial_explore"
    elif (
        sim == "failed:ux_quality_gate"
        and c0["value"] == "yes"
        and substantial
        and c6["value"] in {"human-like", "mixed"}
    ):
        sim_override = "ux_quality_gate_with_substantial_explore_engagement"

    faith, deciding = _verdict(
        app_info["simple_or_complex"] == "simple",
        sim,
        c0,
        c1,
        c2,
        c3,
        c4,
        c6,
        gate_stuck=gate_stuck,
        gate_stuck_reason=gate_reason,
        defining_ok=defining_ok,
        defining_reason=defining_reason,
        sim_override=sim_override,
    )

    return {
        "package": pkg,
        "session_id": meta.get("session_id"),
        "artifact_path": str(base),
        "judge_version": JUDGE_VERSION,
        "app_inference": {
            "app_type": app_info["app_type"],
            "purpose": app_info["purpose"],
            "expected_use": app_info["expected_use"],
            "simple_or_complex": app_info["simple_or_complex"],
        },
        "C0_EXPLORE_ENGAGEMENT": c0,
        "C1_REACHED_REAL_SCREENS": c1,
        "C2_ACTED_ON_THEM": c2,
        "C3_SUSTAINED_ENGAGEMENT": c3,
        "C4_NO_BLOCKING_FAILURE": c4,
        "C5_REALISTIC_CONDITIONS": c5,
        "C6_HUMAN_LIKE_COHERENCE": c6,
        "faithfulness": faith,
        "deciding_factor": deciding,
        "coverage_gap": _coverage_gap(app_info["expected_use"], actions, plan, c1),
        "session_meta": {
            "llm_simulation_status": sim,
            "sim_override": sim_override,
            "substantial_real_engagement": substantial,
            "explore_metrics": explore_metrics,
            "gate_stuck": gate_stuck,
            "defining_action_ok": defining_ok,
            "distinct_screen_hashes": len(
                {a.get("screen_hash") for a in actions if a.get("screen_hash")}
                | {a.get("screen_hash_after") for a in actions if a.get("screen_hash_after")}
            ),
            "duration_sec": duration,
            "action_count": len(actions),
            "human_ux_report_present": report is not None,
        },
    }


def _load_cohort(index_path: Path, *, overnight_only: bool) -> list[dict[str, str]]:
    cutoff = datetime.fromisoformat(OVERNIGHT_CUTOFF_ISO.replace("Z", "+00:00"))
    rows: list[dict[str, str]] = []
    for row in csv.DictReader(index_path.open(encoding="utf-8")):
        if row.get("status") != "success":
            continue
        ts = row.get("analysis_timestamp") or ""
        if not ts:
            continue
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if overnight_only and dt >= cutoff:
            rows.append(row)
        elif not overnight_only and dt < cutoff:
            rows.append(row)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", default="logs/bulk_llm_benign_v6/dataset_index.csv")
    parser.add_argument("--out-json", default="experiment/faithfulness_evaluation.json")
    parser.add_argument("--cohort", choices=["overnight", "all", "prior"], default="overnight")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    overnight = args.cohort == "overnight"
    prior = args.cohort == "prior"
    rows = _load_cohort(root / args.index, overnight_only=overnight if not prior else False)
    if prior:
        rows = _load_cohort(root / args.index, overnight_only=False)
    if args.cohort == "all":
        rows = [
            r
            for r in csv.DictReader((root / args.index).open(encoding="utf-8"))
            if r.get("status") == "success"
        ]

    results: list[dict[str, Any]] = []
    for row in rows:
        base = Path(row["metadata_path"]).parent
        pkg = row["package_name"]
        meta_path = Path(row["metadata_path"])
        if not meta_path.exists():
            continue
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        results.append(evaluate_session(base, pkg, meta))

    summary = Counter(r["faithfulness"] for r in results)
    out = {
        "experiment": "faithfulness_evaluation",
        "cohort": args.cohort,
        "overnight_cohort_cutoff": OVERNIGHT_CUTOFF_ISO,
        "sessions": len(results),
        "summary": dict(summary),
        "per_session": results,
    }

    out_path = root / args.out_json
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"wrote {out_path}")
    print(f"summary: {dict(summary)}")


if __name__ == "__main__":
    main()
