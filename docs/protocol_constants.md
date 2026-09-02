# ContextDroid Protocol Constants (Phase 0)

This document freezes the agreed methodological constants before implementation wiring.
Phase 0 is configuration/documentation only.

## Scope of Phase 0

- Define single-source constants and labels.
- Freeze additive schema defaults for backward compatibility.
- Freeze run-mode semantics and queue policy.
- No behavior changes are introduced in this phase.

## Run Modes

- `llm_only`: primary mode; runs only the LLM stimulation arm.
- `llm_plus_monkey`: optional mode; runs LLM plus Monkey baseline.

Comparison analysis is optional and post-collection.

## Session Fairness Protocol

- Timed session duration: `120` seconds.
- Sessions per app per arm: `3`.
- Per-session timeout: `3x` session duration (`360` seconds).
- Cold start every session (`pm clear` policy in later phases).
- Same network defaults across arms.
- Permission pre-grant step before timed session.
- First-run onboarding handled in pre-simulation step (excluded from timed window).
- Both arms begin from equivalent post-onboarding state.

## Pre-Simulation Warmup Constants

- Warmup monkey seed: `42`
- Warmup monkey events: `10`
- Warmup setup target duration: `15` seconds

## LLM Reproducibility Constants

- Temperature: `0.0`
- Prompt hash algorithm: `sha256`
- Action history window in prompt: last `3` actions
- Model name/version logged at session start (wired in future phase)

## Context/Truncation Constants

- Description cap: `1000` chars
- Permission hints cap: top `20`
- API hint cap: top `50`
- Agent XML token budget: `2000`
- XML preprocessing keeps interactive/actionable elements and removes invisible/zero-size/non-interactive elements.

## Agent Guardrails

- Repetition window: last `5` actions
- Repetition threshold: `>=3` same action in window
- Stagnation hash input: normalized cleaned XML only
- Auto-back trigger: `3` consecutive unchanged screens
- Bailout trigger: `5` consecutive unchanged screens after recovery attempts
- Bailout status: `partial: agent_stuck`

## Failure and Skip Taxonomy

- Retry once: immediate crash / ANR
- Skip reasons:
  - `unstable`
  - `login_required`
  - `anti_emulator`
- Non-skip flag:
  - `webview_dominant`
- Timeout partial status:
  - `partial: timeout`

## Metrics Definitions (Comparison Module, Optional)

- Sequence diversity: unique API-name trigrams (`N=3`) per session.
- Coverage denominator: union of unique APIs per app across both arms.
- Consistency: within-arm pairwise Jaccard on unique API sets across 3 sessions.

Phase 3 script:

- `extraction_pipeline/compute_comparison_metrics.py`
- Inputs: `dataset_index.csv` and per-session `*_frida.csv`
- Outputs:
  - `session_metrics.csv`
  - `arm_summary.csv`
  - `app_union_summary.csv`

## Additive-Only Schema Defaults (Legacy Compatibility)

- `arm=unknown`
- `metadata_source=unknown`
- `context_confidence=unknown`

## Queue Policy

- Full-run queue is built dynamically at runtime from `data/apks/benign` using `*.apk`.
- Deterministic ordering is required (stable sort).
- Pilot is a subset overlay for validation only (20-30 apps); full run targets all APKs discovered at runtime.
