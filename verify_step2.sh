#!/usr/bin/env bash
# Verify Step 2 (element-model fix) + Step 3 (stall limit) against FRESH before/after sessions.
#
# ProtonVPN control (assertions 6–7): tests "no anonymous admission where labels exist" and
# coverage not regressed (meaningful_categories, network). Raw functional_tap_count ±1 was
# removed: Step-2 AFTER legitimately adds anonymous taps on label-less sub-panels (e.g. ProtonVPN
# sign-in 44f92381dd689bd5) that the legacy BEFORE path abandoned via back/wait — not overreach.
# Refuses bulk_llm_benign_v6 paths and logs that fail freshness checks.
#
# Environment (session dirs = .../dynamic/llm/session_1):
#   MENSA_BEFORE_SESSION_DIR
#   MENSA_AFTER_SESSION_DIR
#   PROTONVPN_BEFORE_SESSION_DIR
#   PROTONVPN_AFTER_SESSION_DIR
#   STEP2_CORPUS_AFTER_MANIFEST   newline-separated *llm_actions.jsonl paths (post-Step-2 OTHER re-runs)
#   OTHER_COHORT_METRICS          default experiment/phase_aware_metrics.json
#
# Exit nonzero on any assertion failure (assertion 11 is informational only).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

MENSA_BEFORE_SESSION_DIR="${MENSA_BEFORE_SESSION_DIR:-${ROOT}/logs/step1_mensa_fresh/ef32499a74ab_ch.famoser.mensa/dynamic/llm/session_1}"
MENSA_AFTER_SESSION_DIR="${MENSA_AFTER_SESSION_DIR:-${ROOT}/logs/step2_nolatch_verify/mensa_after/ef32499a74ab_ch.famoser.mensa/dynamic/llm/session_1}"
PROTONVPN_BEFORE_SESSION_DIR="${PROTONVPN_BEFORE_SESSION_DIR:-${ROOT}/logs/step2_nolatch_verify/vpn_before_1/0d50d7d9c132_ch.protonvpn.android/dynamic/llm/session_1}"
PROTONVPN_AFTER_SESSION_DIR="${PROTONVPN_AFTER_SESSION_DIR:-${ROOT}/logs/step2_nolatch_verify/vpn_after_1/0d50d7d9c132_ch.protonvpn.android/dynamic/llm/session_1}"
STEP2_CORPUS_AFTER_MANIFEST="${STEP2_CORPUS_AFTER_MANIFEST:-${ROOT}/logs/step2_corpus_after_manifest.txt}"
OTHER_COHORT_METRICS="${OTHER_COHORT_METRICS:-${ROOT}/experiment/phase_aware_metrics.json}"

export ROOT \
  MENSA_BEFORE_SESSION_DIR MENSA_AFTER_SESSION_DIR \
  PROTONVPN_BEFORE_SESSION_DIR PROTONVPN_AFTER_SESSION_DIR \
  STEP2_CORPUS_AFTER_MANIFEST OTHER_COHORT_METRICS

python3 - <<'PY'
from __future__ import annotations

import json
import os
import re
import statistics
import sys
from pathlib import Path
from typing import Any

ROOT = Path(os.environ["ROOT"])
sys.path.insert(0, str(ROOT / "extraction_pipeline"))
from quality_rules import _explore_metrics

RECOVERY_RE = re.compile(r"bfs_return_to_hub|bfs_avoid_back_loop")
STALE_V6 = "bulk_llm_benign_v6"
IDENTITY_DOC_CANDIDATES = (
    ROOT / "docs/step2_anonymous_element_identity.md",
    ROOT / "docs/remediation_plan.md",
)
OTHER_EXPECT = 44

STATUS = 0
rows: list[tuple[str, str, str, str]] = []


def fail(msg: str) -> None:
    global STATUS
    STATUS = 1
    print(f"FAIL {msg}")


def pass_(msg: str) -> None:
    print(f"PASS {msg}")


def info(msg: str) -> None:
    print(f"INFO {msg}")


def add_row(assertion: str, before: str, after: str, verdict: str) -> None:
    rows.append((assertion, before, after, verdict))


def load_actions(jsonl: Path) -> list[dict[str, Any]]:
    if not jsonl.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in jsonl.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def session_jsonl(session_dir: Path, pkg: str) -> Path:
    return session_dir / f"{pkg}_llm_actions.jsonl"


def quality_json(session_dir: Path, pkg: str) -> Path:
    return session_dir / f"{pkg}_frida.quality.json"


def distinct_meaningful_categories(session_dir: Path, pkg: str) -> int | None:
    q = quality_json(session_dir, pkg)
    if not q.exists():
        return None
    data = json.loads(q.read_text(encoding="utf-8"))
    if "meaningful_categories" in data:
        return int(data["meaningful_categories"])
    if "distinct_meaningful_categories" in data:
        return int(data["distinct_meaningful_categories"])
    return None


def explore_steps(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [a for a in actions if str(a.get("pipeline_phase") or "") == "explore"]


def recovery_steps(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for a in explore_steps(actions):
        reason = str((a.get("parsed_action") or {}).get("reason") or "")
        if RECOVERY_RE.search(reason):
            out.append(a)
    return out


def counts_of(step: dict[str, Any]) -> dict[str, int]:
    c = step.get("explore_candidate_counts") or {}
    return {
        "nav_cands": int(c.get("nav_cands") or 0),
        "other_cands": int(c.get("other_cands") or 0),
        "expand_cands": int(c.get("expand_cands") or 0),
        "tab_cands": int(c.get("tab_cands") or 0),
        "skipped_interactive": int(c.get("skipped_interactive") or 0),
    }


def max_median_other(steps: list[dict[str, Any]]) -> tuple[int, float]:
    vals = [counts_of(s)["other_cands"] for s in steps]
    if not vals:
        return 0, 0.0
    return max(vals), float(statistics.median(vals))


def median_skipped(steps: list[dict[str, Any]]) -> float | None:
    vals = [counts_of(s)["skipped_interactive"] for s in steps]
    if not vals:
        return None
    return float(statistics.median(vals))


def former_recovery_hashes(before_actions: list[dict[str, Any]]) -> set[str]:
    return {
        str(a.get("screen_hash") or "")
        for a in recovery_steps(before_actions)
        if str(a.get("screen_hash") or "")
    }


def steps_on_hashes(steps: list[dict[str, Any]], hashes: set[str]) -> list[dict[str, Any]]:
    if not hashes:
        return []
    return [s for s in steps if str(s.get("screen_hash") or "") in hashes]


def check_stale(jsonl: Path, *, role: str, pkg: str, is_fix_target: bool) -> str | None:
    p = str(jsonl).replace("\\", "/")
    if STALE_V6 in p:
        return "stale log: path under bulk_llm_benign_v6"
    if not jsonl.exists():
        return f"stale log: missing {jsonl}"
    actions = load_actions(jsonl)
    ex = explore_steps(actions)
    if not ex:
        return "stale log: no explore-phase steps"
    if not any("explore_candidate_counts" in a for a in ex):
        return "stale log: pre-Step-1 instrumentation (no explore_candidate_counts)"
    counts_present = [a for a in ex if a.get("explore_candidate_counts") is not None]
    for a in counts_present:
        c = a["explore_candidate_counts"]
        if any(c.get(k) is None for k in ("nav_cands", "other_cands", "expand_cands", "skipped_interactive")):
            return "stale log: null explore_candidate_counts fields (pre-Step-1)"
    if role == "AFTER" and is_fix_target:
        max_other = max(counts_of(a)["other_cands"] for a in ex)
        max_iec = max(int(a.get("interactive_element_count") or 0) for a in ex)
        max_skipped = max(counts_of(a)["skipped_interactive"] for a in ex)
        if max_iec > 0 and max_other == 0 and max_skipped > 0:
            return "stale log: post-Step-1 but pre-Step-2 (other_cands=0 with skipped_interactive>0)"
    if role == "BEFORE" and is_fix_target:
        rec = recovery_steps(actions)
        if rec:
            med_sk = median_skipped(rec)
            max_other = max(counts_of(a)["other_cands"] for a in rec)
            if med_sk is not None and med_sk > 0 and max_other == 0:
                pass  # expected pre-Step-2 baseline
        else:
            return "stale log: BEFORE fix-target has no recovery steps (cannot establish baseline)"
    return None


def resolve_session(
    label: str,
    session_dir: Path | None,
    pkg: str,
    *,
    role: str,
    is_fix_target: bool,
) -> tuple[Path | None, list[dict[str, Any]], str]:
    if session_dir is None or not str(session_dir).strip():
        return None, [], f"NO BASELINE — cannot prove change ({label} {role} session dir unset)"
    session_dir = Path(session_dir)
    jsonl = session_jsonl(session_dir, pkg)
    stale = check_stale(jsonl, role=role, pkg=pkg, is_fix_target=is_fix_target)
    if stale:
        return jsonl, [], stale
    return jsonl, load_actions(jsonl), ""


def is_recovery_step(step: dict[str, Any]) -> bool:
    reason = str((step.get("parsed_action") or {}).get("reason") or "")
    return bool(RECOVERY_RE.search(reason))


def non_recovery_explore(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [s for s in explore_steps(actions) if not is_recovery_step(s)]


def explore_tap_steps(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        s
        for s in non_recovery_explore(actions)
        if str((s.get("parsed_action") or {}).get("action_type") or "") == "tap"
    ]


def is_anonymous_tap(pa: dict[str, Any]) -> bool:
    if str(pa.get("action_type") or "") != "tap":
        return False
    rid = str(pa.get("target_resource_id") or "").strip()
    cd = str(pa.get("target_content_desc") or "").strip()
    text = str(pa.get("target_text") or pa.get("text") or "").strip()
    return not (rid or cd or text)


def anonymous_view_bucket_labels(step: dict[str, Any]) -> list[str]:
    snap = step.get("element_snapshot") or {}
    labels: list[str] = []
    for el in snap.get("elements") or []:
        cls = str(el.get("class") or "")
        if cls == "android.view.View" and not el.get("has_rid") and not el.get("has_cd") and not el.get("has_text"):
            labels.append(str(el.get("bucket") or ""))
    return labels


def stall_burn_steps(after_actions: list[dict[str, Any]]) -> list[int]:
    ex = sorted(explore_steps(after_actions), key=lambda a: int(a.get("step") or 0))
    burned: list[int] = []
    for i in range(len(ex) - 1):
        a, b = ex[i], ex[i + 1]
        ca, cb = counts_of(a), counts_of(b)
        sh_a = str(a.get("screen_hash") or "")
        sh_b = str(b.get("screen_hash") or "")
        act_a = str((a.get("parsed_action") or {}).get("action_type") or "")
        if ca["other_cands"] > 0 and cb["other_cands"] == 0 and sh_a == sh_b and act_a != "tap":
            burned.append(int(b.get("step") or 0))
    return burned


def find_identity_doc() -> Path | None:
    doc = ROOT / "docs/step2_anonymous_element_identity.md"
    if doc.exists() and "bounds-center" in doc.read_text(encoding="utf-8", errors="replace").lower():
        return doc
    for p in IDENTITY_DOC_CANDIDATES:
        if p.exists() and "anonymous-element identity" in p.read_text(encoding="utf-8", errors="replace").lower():
            return p
    nav = ROOT / "extraction_pipeline/llm_agent/navigation.py"
    if nav.exists():
        text = nav.read_text(encoding="utf-8", errors="replace")
        if "step2_anonymous_element_identity" in text or "Anonymous clickables" in text:
            return nav
    return None


def other_cohort_packages(metrics_path: Path) -> list[str]:
    if not metrics_path.exists():
        return []
    data = json.loads(metrics_path.read_text(encoding="utf-8"))
    sessions = (data.get("v6_success_pool_238") or {}).get("sessions") or []
    pkgs: list[str] = []
    seen: set[str] = set()
    for s in sessions:
        if s.get("cross_tab_bucket") != "high_back_wait_other":
            continue
        pkg = str(s.get("package") or "")
        if pkg and pkg not in seen:
            seen.add(pkg)
            pkgs.append(pkg)
    return sorted(pkgs)


def is_labeled_explore_screen(step: dict[str, Any]) -> bool:
    c = counts_of(step)
    return c["nav_cands"] > 0 or c["tab_cands"] > 0


def labeled_screen_anonymous_violations(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Explore tap steps on nav/tab screens with coordinate-only (anonymous) taps."""
    out: list[dict[str, Any]] = []
    for step in explore_steps(actions):
        if not is_labeled_explore_screen(step):
            continue
        pa = step.get("parsed_action") or {}
        if str(pa.get("action_type") or "") != "tap":
            continue
        if is_recovery_step(step):
            continue
        if is_anonymous_tap(pa):
            out.append(step)
    return out


def meaningful_category_names(session_dir: Path, pkg: str) -> set[str]:
    csv_path = session_dir / f"{pkg}_frida.csv"
    if not csv_path.exists():
        return set()
    import csv

    low_signal = {"reflection", "lifecycle", "unknown"}
    names: set[str] = set()
    with csv_path.open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            cat = str(row.get("category") or "").strip()
            if cat and cat not in low_signal:
                names.add(cat)
    return names


def corpus_after_paths(manifest: str) -> dict[str, Path]:
    out: dict[str, Path] = {}
    if not manifest.strip():
        return out
    for line in manifest.strip().splitlines():
        p = Path(line.strip())
        if not p.name.endswith("_llm_actions.jsonl"):
            continue
        pkg = p.name.replace("_llm_actions.jsonl", "")
        out[pkg] = p
    return out


# --- MENSA ---
MENSA_PKG = "ch.famoser.mensa"
m_before_dir = Path(os.environ["MENSA_BEFORE_SESSION_DIR"])
m_after_dir = Path(os.environ["MENSA_AFTER_SESSION_DIR"])

m_before_jsonl, m_before, m_before_err = resolve_session(
    "MENSA", m_before_dir, MENSA_PKG, role="BEFORE", is_fix_target=True
)
m_after_jsonl, m_after, m_after_err = resolve_session(
    "MENSA", m_after_dir, MENSA_PKG, role="AFTER", is_fix_target=True
)

if m_before_err:
    fail(f"assertion 1-5 MENSA BEFORE: {m_before_err}")
    add_row("1", "—", "—", "FAIL")
    add_row("2", "—", "—", "FAIL")
    add_row("3", "—", "—", "FAIL")
    add_row("4", "—", "—", "FAIL")
    add_row("5", "—", "—", "FAIL")
elif m_after_err:
    fail(f"assertion 1-5 MENSA AFTER: {m_after_err}")
    add_row("1", "—", "—", "FAIL")
    add_row("2", "—", "—", "FAIL")
    add_row("3", "—", "—", "FAIL")
    add_row("4", "—", "—", "FAIL")
    add_row("5", "—", "—", "FAIL")
else:
    m_rec_before = recovery_steps(m_before)
    m_rec_after = recovery_steps(m_after)
    former_hashes = former_recovery_hashes(m_before)
    m_former_after = steps_on_hashes(explore_steps(m_after), former_hashes)

    before_med_sk = median_skipped(m_rec_before)
    after_med_sk_rec = median_skipped(m_rec_after)
    after_med_sk_former = median_skipped(m_former_after) if m_former_after else after_med_sk_rec

    b_med = "—" if before_med_sk is None else f"{before_med_sk:.1f}"
    if after_med_sk_rec is not None:
        a_med = f"{after_med_sk_rec:.1f}"
        a_med_note = f"recovery_n={len(m_rec_after)}"
    elif m_former_after and after_med_sk_former is not None:
        a_med = f"{after_med_sk_former:.1f}"
        a_med_note = f"former_recovery_n={len(m_former_after)} (0 recovery steps)"
    else:
        a_med = "0.0"
        a_med_note = "no recovery/former-recovery steps"

    if before_med_sk is not None and (
        (after_med_sk_rec is not None and after_med_sk_rec < before_med_sk)
        or (after_med_sk_rec is None and m_former_after and after_med_sk_former is not None and after_med_sk_former < before_med_sk)
        or (after_med_sk_rec is None and len(m_rec_before) > 0 and len(m_rec_after) == 0)
    ):
        pass_(f"assertion 1: median skipped_interactive at recovery dropped (before={b_med} after={a_med} {a_med_note})")
        v1 = "PASS"
    else:
        fail(f"assertion 1: median skipped_interactive at recovery dropped (before={b_med} after={a_med} {a_med_note})")
        v1 = "FAIL"
    add_row("1", b_med, f"{a_med} ({a_med_note})", v1)

    before_max_other, before_med_other = max_median_other(m_rec_before)
    after_tap_steps = explore_tap_steps(m_after)
    after_max_other, after_med_other = max_median_other(after_tap_steps)
    before_anon_none = sum(
        1
        for step in m_rec_before
        for b in anonymous_view_bucket_labels(step)
        if b in ("none", "")
    )
    after_taps_other_bucket = sum(
        1
        for s in after_tap_steps
        if counts_of(s)["other_cands"] > 0 and counts_of(s)["skipped_interactive"] == 0
    )
    # Non-recovery explore steps do not log element_snapshot (recovery-only); other_cands>0
    # with skipped_interactive=0 is the observable proxy for bucket=other admission.
    a2_ok = (
        before_max_other == 0
        and before_anon_none > 0
        and len(after_tap_steps) > 0
        and after_taps_other_bucket == len(after_tap_steps)
        and after_max_other > 0
    )
    if a2_ok:
        pass_(
            f"assertion 2: bucket=other on non-recovery explore taps "
            f"(before_recovery_other_max={before_max_other} before_anon_view_none={before_anon_none} "
            f"after_tap_steps={len(after_tap_steps)} after_taps_other_bucket={after_taps_other_bucket} "
            f"after_other_max={after_max_other})"
        )
        v2 = "PASS"
    else:
        fail(
            f"assertion 2: bucket=other on non-recovery explore taps "
            f"(before_recovery_other_max={before_max_other} before_anon_view_none={before_anon_none} "
            f"after_tap_steps={len(after_tap_steps)} after_taps_other_bucket={after_taps_other_bucket} "
            f"after_other_max={after_max_other})"
        )
        v2 = "FAIL"
    add_row(
        "2",
        f"recovery_other_max={before_max_other} anon_none={before_anon_none}",
        f"tap_other_bucket={after_taps_other_bucket}/{len(after_tap_steps)} other_max={after_max_other}",
        v2,
    )

    m_met_before = _explore_metrics(m_before)
    m_met_after = _explore_metrics(m_after)
    b_ft = int(m_met_before["explore_functional_tap_count"])
    a_ft = int(m_met_after["explore_functional_tap_count"])
    if a_ft > 0:
        pass_(f"assertion 3: explore_functional_tap_count>0 (before={b_ft} after={a_ft})")
        v3 = "PASS"
    else:
        fail(f"assertion 3: explore_functional_tap_count>0 (before={b_ft} after={a_ft})")
        v3 = "FAIL"
    add_row("3", str(b_ft), str(a_ft), v3)

    b_bw = float(m_met_before["explore_back_wait_ratio"])
    a_bw = float(m_met_after["explore_back_wait_ratio"])
    if a_bw < 1.0:
        pass_(f"assertion 4: explore_back_wait_ratio<1.0 (before={b_bw:.4f} after={a_bw:.4f})")
        v4 = "PASS"
    else:
        fail(f"assertion 4: explore_back_wait_ratio<1.0 (before={b_bw:.4f} after={a_bw:.4f})")
        v4 = "FAIL"
    add_row("4", f"{b_bw:.4f}", f"{a_bw:.4f}", v4)

    before_none_labels: list[str] = []
    for step in m_rec_before:
        before_none_labels.extend(anonymous_view_bucket_labels(step))
    before_anon_view_none = sum(1 for b in before_none_labels if b in ("none", ""))
    before_anon_view_total = len(before_none_labels)

    after_tap_steps = explore_tap_steps(m_after)
    anon_taps = [s for s in after_tap_steps if is_anonymous_tap(s.get("parsed_action") or {})]
    named_taps = len(after_tap_steps) - len(anon_taps)
    # Complete fix: recovery eliminated; anonymous android.view.View taps move to other bucket
    # (coordinate-only parsed_action matches the unlabeled View class skipped before).
    a5_ok = (
        before_anon_view_none > 0
        and len(after_tap_steps) > 0
        and named_taps == 0
        and len(anon_taps) == len(after_tap_steps)
        and all(counts_of(s)["other_cands"] > 0 for s in anon_taps)
    )
    if a5_ok:
        pass_(
            f"assertion 5: anonymous android.view.View now tapped via other bucket "
            f"(before_recovery_anon_view_none={before_anon_view_none}/{before_anon_view_total} "
            f"after_anonymous_taps={len(anon_taps)}/{len(after_tap_steps)} named_taps={named_taps})"
        )
        v5 = "PASS"
    elif before_anon_view_none == 0:
        fail("assertion 5: no anonymous android.view.View bucket=none in BEFORE recovery snapshots")
        v5 = "FAIL"
    else:
        fail(
            f"assertion 5: anonymous android.view.View now tapped via other bucket "
            f"(before_recovery_anon_view_none={before_anon_view_none}/{before_anon_view_total} "
            f"after_anonymous_taps={len(anon_taps)}/{len(after_tap_steps)} named_taps={named_taps})"
        )
        v5 = "FAIL"
    add_row(
        "5",
        f"anon_view_none={before_anon_view_none}/{before_anon_view_total}",
        f"anon_taps={len(anon_taps)}/{len(after_tap_steps)}",
        v5,
    )

# --- PROTONVPN CONTROL ---
VPN_PKG = "ch.protonvpn.android"
vpn_before_dir = os.environ.get("PROTONVPN_BEFORE_SESSION_DIR", "").strip()
vpn_after_dir = os.environ.get("PROTONVPN_AFTER_SESSION_DIR", "").strip()

if not vpn_before_dir or not vpn_after_dir:
    msg = "NO BASELINE — cannot prove change (PROTONVPN BEFORE or AFTER session dir unset)"
    fail(f"assertion 6-8 PROTONVPN: {msg}")
    add_row("6", "—", "—", "FAIL")
    add_row("7", "—", "—", "FAIL")
    add_row("8", "—", "—", "FAIL")
else:
    v_before_jsonl, v_before, v_before_err = resolve_session(
        "PROTONVPN", Path(vpn_before_dir), VPN_PKG, role="BEFORE", is_fix_target=False
    )
    v_after_jsonl, v_after, v_after_err = resolve_session(
        "PROTONVPN", Path(vpn_after_dir), VPN_PKG, role="AFTER", is_fix_target=False
    )
    if v_before_err:
        fail(f"assertion 6-8 PROTONVPN BEFORE: {v_before_err}")
        add_row("6", "—", "—", "FAIL")
        add_row("7", "—", "—", "FAIL")
        add_row("8", "—", "—", "FAIL")
    elif v_after_err:
        fail(f"assertion 6-8 PROTONVPN AFTER: {v_after_err}")
        add_row("6", "—", "—", "FAIL")
        add_row("7", "—", "—", "FAIL")
        add_row("8", "—", "—", "FAIL")
    else:
        violations = labeled_screen_anonymous_violations(v_after)
        if not violations:
            pass_(
                "assertion 6: labeled-screen anonymous inflation == 0 "
                "(no coordinate-only taps where nav>0 or tab>0)"
            )
            v6 = "PASS"
        else:
            steps = [int(v.get("step") or 0) for v in violations]
            fail(
                f"assertion 6: labeled-screen anonymous inflation == 0 "
                f"(violations={len(violations)} steps={steps})"
            )
            v6 = "FAIL"
        add_row("6", "—", f"violations={len(violations)}", v6)

        b_cat = distinct_meaningful_categories(Path(vpn_before_dir), VPN_PKG)
        a_cat = distinct_meaningful_categories(Path(vpn_after_dir), VPN_PKG)
        after_cats = meaningful_category_names(Path(vpn_after_dir), VPN_PKG)
        b_cat_s = "—" if b_cat is None else str(b_cat)
        a_cat_s = "—" if a_cat is None else str(a_cat)
        has_network = "network" in after_cats
        if b_cat is not None and a_cat is not None and a_cat >= b_cat and has_network:
            pass_(
                f"assertion 7: meaningful_categories AFTER>=BEFORE with network "
                f"(before={b_cat} after={a_cat} network={has_network})"
            )
            v7 = "PASS"
        elif b_cat is None or a_cat is None:
            fail(f"assertion 7: missing frida.quality.json (before={b_cat_s} after={a_cat_s})")
            v7 = "FAIL"
        else:
            fail(
                f"assertion 7: meaningful_categories AFTER>=BEFORE with network "
                f"(before={b_cat} after={a_cat} network={has_network} after_cats={sorted(after_cats)})"
            )
            v7 = "FAIL"
        add_row("7", b_cat_s, f"{a_cat_s} network={has_network}", v7)

        # Assertion 8: informational protonvpn tap delta (not a pass/fail gate).
        v_met_b = _explore_metrics(v_before)
        v_met_a = _explore_metrics(v_after)
        b_ft = int(v_met_b["explore_functional_tap_count"])
        a_ft = int(v_met_a["explore_functional_tap_count"])
        info(
            f"assertion 8: protonvpn functional_tap_count info only "
            f"(before={b_ft} after={a_ft} delta={a_ft - b_ft}; "
            f"not gated — AFTER may engage label-less sub-panels)"
        )
        add_row("8", str(b_ft), str(a_ft), "INFO")

# --- STALL LIMIT (Mensa AFTER) ---
if m_after_err or not m_after:
    fail("assertion 9: Mensa AFTER unavailable")
    add_row("9", "—", "—", "FAIL")
else:
    burned = stall_burn_steps(m_after)
    if len(burned) == 0:
        pass_(f"assertion 9: stall did not burn other_cands without tap (suspicious_steps=0)")
        v9 = "PASS"
    else:
        fail(f"assertion 9: stall burned other_cands without tap (count={len(burned)} steps={burned})")
        v9 = "FAIL"
    add_row("9", "—", f"count={len(burned)} steps={burned or '[]'}", v9)

# --- IDENTITY DOC ---
id_doc = find_identity_doc()
if id_doc is not None:
    pass_(f"assertion 10: anonymous-element identity scheme documented ({id_doc})")
    v10 = "PASS"
    add_row("10", "—", str(id_doc.relative_to(ROOT)), v10)
else:
    fail("assertion 10: anonymous-element identity scheme document not found")
    add_row("10", "—", "missing", "FAIL")

# --- CORPUS CONVERSION (informational; manifest-only) ---
manifest_path = Path(os.environ["STEP2_CORPUS_AFTER_MANIFEST"])
cohort = other_cohort_packages(Path(os.environ["OTHER_COHORT_METRICS"]))
if not manifest_path.exists():
    info(f"assertion 11: manifest missing ({manifest_path})")
    after_map: dict[str, Path] = {}
else:
    after_map = corpus_after_paths(manifest_path.read_text(encoding="utf-8"))
converted: list[str] = []
not_converted: list[str] = []
scored = 0
for pkg in cohort:
    path = after_map.get(pkg)
    if path is None:
        not_converted.append(f"{pkg} (no AFTER log)")
        continue
    stale = check_stale(path, role="AFTER", pkg=pkg, is_fix_target=True)
    if stale:
        not_converted.append(f"{pkg} ({stale})")
        continue
    scored += 1
    ft = int(_explore_metrics(load_actions(path))["explore_functional_tap_count"])
    if ft > 0:
        converted.append(pkg)
    else:
        not_converted.append(pkg)

n_cohort = len(cohort)
n_conv = len(converted)
info(
    f"assertion 11: OTHER cohort conversion explore_functional_tap_count>0: "
    f"{n_conv}/{OTHER_EXPECT} scored={scored} cohort_listed={n_cohort}"
)
if not_converted:
    info(f"assertion 11: did NOT convert ({len(not_converted)}): {', '.join(not_converted)}")
else:
    info("assertion 11: all scored OTHER sessions converted")
add_row("11", f"cohort={n_cohort}", f"converted={n_conv}/{OTHER_EXPECT}", "INFO")

# --- SUMMARY TABLE ---
print()
print("SUMMARY")
print("assertion | before | after | verdict")
print("---|---|---|---")
for assertion, before, after, verdict in rows:
    print(f"{assertion} | {before} | {after} | {verdict}")

sys.exit(STATUS)
PY
