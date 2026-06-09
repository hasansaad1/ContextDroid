#!/usr/bin/env bash
# One-shot LLM run with structured step audit + optional goal plan / step trace.
#
# Usage (repo root):
#   bash extraction_pipeline/run_llm_audit_session.sh /path/to/App.apk [duration_sec]
#
# Writes per session:
#   .../dynamic/llm/session_*/<pkg>_llm_step_audit.jsonl   (machine-readable audit trail)
# Then prints report_llm_audit summary for session 1 (adjust SESSION_NUM below).
#
# Env (optional): CONTEXTDROID_LLM_GOAL_PLAN=1, CONTEXTDROID_LLM_ACTION_HISTORY_WINDOW, SESSIONS_PER_APP,
# OLLAMA_MODEL, ANDROID_SERIAL, etc.
# Quick navigation debug preset: extraction_pipeline/run_llm_debug_nav_session.sh (same args).
# Fixed 10-minute single-session + nav-first + Claude handoff: extraction_pipeline/run_llm_10min_simulation.sh

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <apk_or_folder_with_one_apk> [duration_seconds]" >&2
  exit 1
fi

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION_NUM="${AUDIT_SESSION_NUM:-1}"

export CONTEXTDROID_LLM_AUDIT_SESSION=1
export CONTEXTDROID_LLM_STEP_DEBUG="${CONTEXTDROID_LLM_STEP_DEBUG:-1}"

# Give the planner more runway before stagnation bailout during audited UX sessions.
export CONTEXTDROID_STAGNATION_BAILOUT="${CONTEXTDROID_STAGNATION_BAILOUT:-22}"

bash "${BASE_DIR}/extraction_pipeline/run_llm_best_effort_one_app.sh" "$@"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if [[ -x "${BASE_DIR}/.venv/bin/python" ]]; then
  PYTHON_BIN="${BASE_DIR}/.venv/bin/python"
fi

latest_artifact() {
  local suffix="$1"
  "${PYTHON_BIN}" - "${BASE_DIR}" "${SESSION_NUM}" "${suffix}" <<'PY' || true
import sys
from pathlib import Path

base = Path(sys.argv[1])
session_num = sys.argv[2]
suffix = sys.argv[3]
paths = list((base / "logs").glob(f"*/dynamic/llm/session_{session_num}/*{suffix}"))
if not paths:
    raise SystemExit(0)
paths.sort(key=lambda p: (p.stat().st_mtime_ns, str(p)), reverse=True)
print(paths[0])
PY
}

AUDIT="$(latest_artifact "_llm_step_audit.jsonl")"
if [[ -z "${AUDIT}" ]]; then
  echo "[audit-session] No *_llm_step_audit.jsonl found under logs/ for session_${SESSION_NUM}" >&2
  exit 0
fi

echo "[audit-session] report: ${AUDIT}"
"${PYTHON_BIN}" "${BASE_DIR}/extraction_pipeline/report_llm_audit.py" "${AUDIT}"

HUMAN="$(latest_artifact "_human_ux_report.json")"
if [[ -n "${HUMAN}" ]]; then
  echo "[audit-session] human UX criteria: ${HUMAN}"
  "${PYTHON_BIN}" "${BASE_DIR}/extraction_pipeline/report_human_ux.py" "${HUMAN}"
fi
