#!/usr/bin/env bash
# Quick navigation-focused debug run: UX goal plan + wider planner memory + one audited session.
#
# Usage (repo root):
#   bash extraction_pipeline/run_llm_debug_nav_session.sh /path/to/App.apk [duration_sec]
#
# Defaults (override via env): NAV_FIRST_PIPELINE=1 (explore → digest → plan goals → batched execute),
# EXPLORE_RATIO, BATCH_ACTIONS_MAX, GOAL_PLAN=1, ACTION_HISTORY_WINDOW=6, SESSIONS_PER_APP=1.

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export CONTEXTDROID_LLM_NAV_FIRST_PIPELINE="${CONTEXTDROID_LLM_NAV_FIRST_PIPELINE:-1}"
export CONTEXTDROID_LLM_GOAL_PLAN="${CONTEXTDROID_LLM_GOAL_PLAN:-1}"
export CONTEXTDROID_LLM_EXPLORE_RATIO="${CONTEXTDROID_LLM_EXPLORE_RATIO:-0.30}"
# Optional: CONTEXTDROID_LLM_EXECUTE_RESERVE_SEC — min seconds left after explore ends for execute phase (see llm_agent.py)
export CONTEXTDROID_LLM_BATCH_ACTIONS_MAX="${CONTEXTDROID_LLM_BATCH_ACTIONS_MAX:-10}"
export CONTEXTDROID_LLM_ACTION_HISTORY_WINDOW="${CONTEXTDROID_LLM_ACTION_HISTORY_WINDOW:-6}"
export SESSIONS_PER_APP="${SESSIONS_PER_APP:-1}"

exec bash "${BASE_DIR}/extraction_pipeline/run_llm_audit_session.sh" "$@"
