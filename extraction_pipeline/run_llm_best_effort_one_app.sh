#!/usr/bin/env bash
# LLM-only runs with comparison-grade setup (clean start + fairness pre-setup) and
# tuned defaults aimed at fewer false partial:agent_stuck exits.
#
# Usage (from repo root):
#   bash extraction_pipeline/run_llm_best_effort_one_app.sh /path/to/App.apk [duration_sec]
#   bash extraction_pipeline/run_llm_best_effort_one_app.sh /path/to/folder_with_one_apk [duration_sec]
#
# Environment (optional):
#   OLLAMA_MODEL, OLLAMA_ENDPOINT, ANDROID_SERIAL
#   CONTEXTDROID_STAGNATION_BACK (default 6), CONTEXTDROID_STAGNATION_BAILOUT (default 14)
#   CONTEXTDROID_REPETITION_WINDOW (default 7), CONTEXTDROID_REPETITION_THRESHOLD (default 4)
#   CONTEXTDROID_MAX_AGENT_XML_TOKENS (default 3500)
#   CONTEXTDROID_LLM_SLIM_ACTION_LOG (default 1) — omit huge /api/show payloads from *_llm_actions.jsonl
#   CONTEXTDROID_LLM_STEP_DEBUG=1 — write *_llm_step_trace.txt (human-readable per-step log)
#   CONTEXTDROID_LLM_STEP_DEBUG_PROMPT=1 — embed full prompts in the trace (large files)
#   CONTEXTDROID_LLM_AUDIT_SESSION=1 — write *_llm_step_audit.jsonl (screen before/after, proposal vs executed, heuristic codes)
#   CONTEXTDROID_LLM_GOAL_PLAN=1 — upfront UX goal list + per-step prompts (see llm_agent.py)
#   CONTEXTDROID_LLM_NAV_FIRST_PIPELINE — default on in llm_agent (full phases). Set 0/false/no for legacy UX-only path.
#   CONTEXTDROID_LLM_EXPLORE_RATIO — target share of session for navigation/explore phase (default 0.30; capped by reserve below)
#   CONTEXTDROID_LLM_EXECUTE_RESERVE_SEC — reserve wall-clock after explore for goals+execute (env unset → max(90, duration*0.52))
#   CONTEXTDROID_LLM_BATCH_ACTIONS_MAX — actions per planner response when NAV_FIRST_PIPELINE (default 12)
#   CONTEXTDROID_LLM_NAV_DIGEST_MAX_SCREENS — max distinct screens stored in digest (default 56)
#   CONTEXTDROID_LLM_ACTION_HISTORY_WINDOW — recent actions JSON + RECENT_STEP_SUMMARY depth (default 3)
#   CONTEXTDROID_LLM_STICKY_FOREGROUND — default on; set to 0 to disable bring-app-forward when Chrome/launcher steals focus
#   CONTEXTDROID_LLM_STICKY_FOREGROUND_STRICT — default 1; only recover from launcher/browser (avoids IME/system UI false positives resetting MainActivity)
#   CONTEXTDROID_LLM_STAGNATION_USE_BACK — default 0; BACK during stagnation collapses search overlays
#   CONTEXTDROID_LLM_REPETITION_GUARD_USE_BACK — default 0; repetition_guard uses wait instead of BACK
#   CONTEXTDROID_LLM_FILTER_FOREIGN_WIDGETS — default on; drops Chrome/other-package resource_ids from the hierarchy prompt
#   CONTEXTDROID_LLM_INPUT_FOCUS_PAUSE_SEC — delay after focus tap before adb input text (default 0.35)
#   CONTEXTDROID_LLM_INPUT_CLEAR_BEFORE_TEXT — MOVE_END+DEL before adb input text so typing replaces text (default on)
#   CONTEXTDROID_LLM_INPUT_CLEAR_DEL_COUNT — max DEL keyevents when clearing (default 160)
#   CONTEXTDROID_LLM_INPUT_SUBMIT_SEARCH_INFER — submit after input when target looks search/query if model omits submit_search (default on)
#   CONTEXTDROID_LLM_INPUT_POST_TEXT_SUBMIT_PAUSE_SEC — delay before submit keyevents so IME catches injected text (default 0.15)
#   CONTEXTDROID_LLM_INPUT_SUBMIT_KEYSEQUENCE — enter | tab_enter | enter_then_tab_enter | search_key (unset = auto: enter_then_tab_enter if search-like else enter)
#   CONTEXTDROID_LLM_INPUT_SUBMIT_RESPECT_MODEL_FALSE_ON_SEARCH — if 1, honor submit_search:false even on search-like fields (default 0)
#   CONTEXTDROID_LLM_INPUT_FALLBACK_QUERY — when LLM emits input with empty text but UX goal implies typing (default demo)
#   CONTEXTDROID_LLM_TEMPERATURE (default 0; try 0.15–0.25 for more exploration)
#   SESSIONS_PER_APP (default 3), MIN_VALID_EVENTS, MIN_CATEGORY_COUNT

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <path_to_one.apk_or_folder> [duration_seconds]" >&2
  exit 1
fi

SRC="$1"
DURATION="${2:-420}"
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGING="${LLM_ONLY_STAGING_DIR:-${BASE_DIR}/logs/llm_best_effort_one_app}"
PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "${PYTHON_BIN}" ]]; then
  if [[ -x "${BASE_DIR}/.venv/bin/python" ]]; then
    PYTHON_BIN="${BASE_DIR}/.venv/bin/python"
  else
    PYTHON_BIN="$(command -v python3)"
  fi
fi

rm -rf "${STAGING}"
mkdir -p "${STAGING}"

if [[ -f "${SRC}" ]]; then
  cp "${SRC}" "${STAGING}/"
elif [[ -d "${SRC}" ]]; then
  shopt -s nullglob
  found=( "${SRC}"/*.apk )
  shopt -u nullglob
  if [[ ${#found[@]} -ne 1 ]]; then
    echo "Directory must contain exactly one .apk file; found ${#found[@]}: ${SRC}" >&2
    exit 1
  fi
  cp "${found[0]}" "${STAGING}/"
else
  echo "Not a file or directory: ${SRC}" >&2
  exit 1
fi

export ENABLE_COMPARISON=1
export RUN_MODE=llm_only
export SESSIONS_PER_APP="${SESSIONS_PER_APP:-3}"

export CONTEXTDROID_STAGNATION_BACK="${CONTEXTDROID_STAGNATION_BACK:-6}"
export CONTEXTDROID_STAGNATION_BAILOUT="${CONTEXTDROID_STAGNATION_BAILOUT:-14}"
export CONTEXTDROID_REPETITION_WINDOW="${CONTEXTDROID_REPETITION_WINDOW:-7}"
export CONTEXTDROID_REPETITION_THRESHOLD="${CONTEXTDROID_REPETITION_THRESHOLD:-4}"
export CONTEXTDROID_MAX_AGENT_XML_TOKENS="${CONTEXTDROID_MAX_AGENT_XML_TOKENS:-3500}"
export CONTEXTDROID_LLM_SLIM_ACTION_LOG="${CONTEXTDROID_LLM_SLIM_ACTION_LOG:-1}"

export MIN_VALID_EVENTS="${MIN_VALID_EVENTS:-3}"
export MIN_CATEGORY_COUNT="${MIN_CATEGORY_COUNT:-2}"

echo "[llm-best-effort] staging=${STAGING}"
echo "[llm-best-effort] duration=${DURATION}s  sessions=${SESSIONS_PER_APP}  RUN_MODE=${RUN_MODE}"
echo "[llm-best-effort] CONTEXTDROID_STAGNATION_BACK=${CONTEXTDROID_STAGNATION_BACK} CONTEXTDROID_STAGNATION_BAILOUT=${CONTEXTDROID_STAGNATION_BAILOUT}"
echo "[llm-best-effort] CONTEXTDROID_REPETITION_WINDOW=${CONTEXTDROID_REPETITION_WINDOW} CONTEXTDROID_REPETITION_THRESHOLD=${CONTEXTDROID_REPETITION_THRESHOLD}"
echo "[llm-best-effort] CONTEXTDROID_MAX_AGENT_XML_TOKENS=${CONTEXTDROID_MAX_AGENT_XML_TOKENS}"
echo "[llm-best-effort] OLLAMA_ENDPOINT=${OLLAMA_ENDPOINT:-http://127.0.0.1:11434} OLLAMA_MODEL=${OLLAMA_MODEL:-llama3.2}"

exec bash "${BASE_DIR}/extraction_pipeline/run_dynamic_dataset.sh" "${STAGING}" "${DURATION}"
