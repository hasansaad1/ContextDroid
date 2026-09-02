#!/usr/bin/env python3
"""Verify collection v2 preflight gate (items a–f). Fails closed — no OVERNIGHT-READY unless ALL pass."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluate_scenario_level import _load_actions
from quality_rules import _explore_metrics, _explore_named_functional_tap, _phase_events

ROOT = Path(__file__).resolve().parents[1]
PKG = "ch.protonvpn.android"
LOG_ROOT = Path(os.environ.get("PREFLIGHT_LOG_ROOT", ROOT / "logs/collection_v2_preflight/protonvpn"))
EXPECTED_SESSIONS = int(os.environ.get("SESSIONS_PER_APP", "3") or 3)
EXPLORE_FLOOR = float(os.environ.get("CONTEXTDROID_LLM_EXPLORE_UNTIL_SEC_FLOOR", "120") or 120)
MIN_EXPLORE_FUNCTIONAL_TAPS = 11  # Mensa floor — budget must not clip below this


def _fail(check: str, msg: str) -> None:
    print(f"\nGATE FAILED at ({check}): {msg}")
    print("\nSTOP — not overnight-ready. Do not launch batch.")
    raise SystemExit(1)


def _sample_dir() -> Path:
    for pattern in (f"*_{PKG.replace('.', '_')}", f"*_{PKG}"):
        hits = sorted(LOG_ROOT.glob(pattern))
        if hits:
            return hits[0]
    _fail("setup", f"no sample dir under {LOG_ROOT}")
    raise AssertionError


def check_a(sample_dir: Path) -> None:
    """N distinct session dirs with metadata, actions, manifest modes."""
    manifest_path = sample_dir / "run_manifest.json"
    if not manifest_path.exists():
        _fail("a", f"missing run_manifest.json at {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = int(manifest.get("sessions_per_app") or EXPECTED_SESSIONS)
    if expected != EXPECTED_SESSIONS:
        _fail("a", f"sessions_per_app={expected} in manifest, expected {EXPECTED_SESSIONS}")

    print(f"a) SESSIONS_PER_APP={expected} — require {expected} distinct session directories")
    manifest_by_num = {int(s["session_num"]): s for s in (manifest.get("sessions") or []) if s.get("session_num")}

    for n in range(1, expected + 1):
        sess_dir = sample_dir / f"dynamic/llm/session_{n}"
        meta_path = sess_dir / f"{PKG}_dynamic_metadata.json"
        actions_path = sess_dir / f"{PKG}_llm_actions.jsonl"
        print(f"   session_{n} dir: {sess_dir}")

        if not sess_dir.is_dir():
            _fail("a", f"session_{n} directory missing: {sess_dir}")
        if not meta_path.is_file():
            _fail("a", f"session_{n} missing metadata: {meta_path}")
        if not actions_path.is_file():
            _fail("a", f"session_{n} missing actions log: {actions_path}")

        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        sid = str(meta.get("session_id") or "")
        expected_sid = f"{sample_dir.name.split('_')[0]}_llm_s{n}"
        if sid != expected_sid:
            _fail("a", f"session_{n} session_id={sid!r} expected {expected_sid!r}")

        mrow = manifest_by_num.get(n)
        if not mrow:
            _fail("a", f"session_{n} missing from run_manifest.json")
        mode = str(mrow.get("session_mode") or meta.get("session_mode") or "")
        print(
            f"      session_id={sid} mode={mode} agent_seed={meta.get('agent_seed')} "
            f"analysis_status={meta.get('analysis_status')} actions={meta.get('llm_actions_count')}"
        )
        if str(mrow.get("session_id") or "") != sid:
            _fail("a", f"session_{n} manifest session_id mismatch: {mrow.get('session_id')!r} vs {sid!r}")

    extra = sorted(
        p.name
        for p in (sample_dir / "dynamic/llm").glob("session_*")
        if p.is_dir() and int(p.name.split("_", 1)[1]) > expected
    )
    if extra:
        _fail("a", f"unexpected extra session dirs: {extra}")

    found = sorted(
        int(p.name.split("_", 1)[1]) for p in (sample_dir / "dynamic/llm").glob("session_*") if p.is_dir()
    )
    if found != list(range(1, expected + 1)):
        _fail("a", f"session dir indices {found} != 1..{expected}")

    print(f"   PASS: {expected} session dirs with distinct session_ids and manifest modes")


def check_b(sess_dir: Path) -> None:
    meta_path = sess_dir / f"{PKG}_dynamic_metadata.json"
    frida_path = sess_dir / f"{PKG}_frida.jsonl"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    hook_v = str(meta.get("hook_version") or "")
    hook_sha = str(meta.get("hook_script_sha256") or "")
    print(f"b) hook_version={hook_v!r} hook_script_sha256={hook_sha}")
    if hook_v != "3":
        _fail("b", f"hook_version expected '3', got {hook_v!r}")

    ipc = 0
    if frida_path.is_file():
        for line in frida_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if '"category": "ipc_intents"' in line or '"category":"ipc_intents"' in line:
                ipc += 1
    print(f"   ipc_intents event count in frida jsonl: {ipc}")
    if ipc <= 0:
        _fail("b", "zero ipc_intents events in frida jsonl")
    print("   PASS")


def check_c(sess_dir: Path, meta: dict[str, object]) -> None:
    actions_path = sess_dir / f"{PKG}_llm_actions.jsonl"
    actions = _load_actions(actions_path)
    explore_actions = _phase_events(actions, ("explore",))
    named_explore_taps = sum(1 for a in explore_actions if _explore_named_functional_tap(a))
    explore_last_step = max((int(a.get("step") or 0) for a in explore_actions), default=0)

    explore_until = None
    log_candidates = [ROOT / "pipeline.log", LOG_ROOT / "batch.log"]
    sid = str(meta.get("session_id") or "")
    for candidate in log_candidates:
        if not candidate.exists():
            continue
        for line in candidate.read_text(encoding="utf-8", errors="ignore").splitlines():
            if "explore_until_sec=" not in line:
                continue
            if sid and sid not in line and "Nav-first timing" not in line:
                continue
            m = re.search(r"explore_until_sec=([0-9.]+)", line)
            if m:
                explore_until = float(m.group(1))
        if explore_until is not None:
            break

    if explore_until is None:
        dur = float(meta.get("duration_sec") or 600)
        ratio = float(meta.get("llm_explore_ratio") or 0.35)
        from llm_agent.config import _explore_until_seconds  # noqa: WPS433

        explore_until = _explore_until_seconds(int(dur))

    elapsed = float(meta.get("elapsed_sec") or 0)
    print(
        f"c) explore_until_sec={explore_until} (floor={EXPLORE_FLOOR}) "
        f"elapsed_sec={elapsed} explore_phase_actions={len(explore_actions)} "
        f"named_explore_taps={named_explore_taps} last_explore_step={explore_last_step}"
    )
    if explore_until < EXPLORE_FLOOR - 1:
        _fail("c", f"explore budget {explore_until}s below floor {EXPLORE_FLOOR}s")
    if named_explore_taps < MIN_EXPLORE_FUNCTIONAL_TAPS:
        _fail(
            "c",
            f"explore clipped at ~{named_explore_taps} named taps (need >={MIN_EXPLORE_FUNCTIONAL_TAPS} for Mensa floor)",
        )
    print("   PASS")


def check_d(sess_dir: Path) -> None:
    actions_path = sess_dir / f"{PKG}_llm_actions.jsonl"
    actions = _load_actions(actions_path)
    anon_taps = 0
    named_taps = 0
    for act in _phase_events(actions, ("explore",)):
        if str((act.get("parsed_action") or {}).get("action_type") or "") != "tap":
            continue
        pa = act.get("parsed_action") or {}
        label = pa.get("target_resource_id") or pa.get("target_content_desc") or pa.get("target_text") or ""
        if str(label).strip():
            named_taps += 1
        else:
            anon_taps += 1
    print(f"d) scarcity (explore taps): named={named_taps} anonymous={anon_taps}")
    if anon_taps > named_taps and named_taps < 3:
        _fail("d", f"anonymous hub inflation: anon={anon_taps} named={named_taps}")
    print("   PASS")


def check_e(meta: dict[str, object]) -> None:
    status = str(meta.get("analysis_status") or "")
    sim = str(meta.get("llm_simulation_status") or "")
    exit_raw = meta.get("analysis_exit_code")
    exit_code = int(exit_raw) if exit_raw is not None else 1
    reattach = int(meta.get("frida_reattach_successes") or 0)
    print(
        f"e) analysis_status={status} llm_simulation_status={sim} "
        f"analysis_exit_code={exit_code} frida_reattach_successes={reattach}"
    )
    if exit_code != 0:
        _fail("e", f"analyze exit code {exit_code}")
    if status != "success":
        _fail("e", f"analysis_status={status!r} (expected success)")
    print("   PASS")


def check_f(sess_dir: Path) -> None:
    actions_path = sess_dir / f"{PKG}_llm_actions.jsonl"
    actions = _load_actions(actions_path)
    explore = _explore_metrics(actions)
    ft = int(explore.get("explore_functional_tap_count") or 0)
    bw = float(explore.get("explore_back_wait_ratio") or 0)
    print(f"f) explore_functional_tap_count={ft} explore_back_wait_ratio={bw}")
    if ft == 0:
        _fail("f", "zero effective explore_functional_tap_count")
    print("   PASS")


def main() -> None:
    print(f"Preflight log root: {LOG_ROOT}")
    print(f"Expected SESSIONS_PER_APP: {EXPECTED_SESSIONS}\n")

    sample_dir = _sample_dir()
    check_a(sample_dir)

    # b–f evaluated on session_1 (primary reference session).
    sess1 = sample_dir / "dynamic/llm/session_1"
    meta = json.loads((sess1 / f"{PKG}_dynamic_metadata.json").read_text(encoding="utf-8"))

    check_b(sess1)
    check_c(sess1, meta)
    check_d(sess1)
    check_e(meta)
    check_f(sess1)

    print("\nCOLLECTOR OVERNIGHT-READY (a–f all passed)")
    print("\nBatch launch command (DO NOT RUN unless you approve):")
    print("  bash extraction_pipeline/run_bulk_llm_benign_v2.sh 600")


if __name__ == "__main__":
    main()
