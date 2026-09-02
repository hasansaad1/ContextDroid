#!/usr/bin/env bash
# Single full LLM dynamic simulation: one session, 10 minutes of analyze_apk duration.
#
# Includes the same pipeline as run_llm_audit_session.sh (audit JSONL, human UX report,
# Frida + parse_logs, comparison fairness flags) plus:
#   - SESSIONS_PER_APP=1 so duration is one 10-minute block (not 3×10 minutes).
#   - Nav-first multi-phase run (explore → digest → goals → execute → primary UX); explicit export matches llm_agent default.
#   - PATH: prepends Android SDK platform-tools when present (adb on macOS).
#   - After success, writes claude_session_report.md next to session artifacts when exporter exists.
#
# Usage (repo root):
#   bash extraction_pipeline/run_llm_10min_simulation.sh /path/to/App.apk
#   bash extraction_pipeline/run_llm_10min_simulation.sh /path/to/folder_with_one_apk
#
# Optional env:
#   DURATION_SEC — wall duration passed to analyze_apk (default 600).
#   SESSIONS_PER_APP — override default 1 if you want multiple 10-minute sessions.
#   ANDROID_SERIAL, OLLAMA_MODEL, OLLAMA_ENDPOINT, AUDIT_SESSION_NUM, PYTHON_BIN, etc.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <path_to_one.apk_or_folder>" >&2
  echo "  One LLM session; default duration ${DURATION_SEC:-600}s (~10 minutes)." >&2
  exit 1
fi

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DURATION_SEC="${DURATION_SEC:-600}"

# One session = one continuous 10-minute simulation (best-effort defaults use 3).
export SESSIONS_PER_APP="${SESSIONS_PER_APP:-1}"

# Nav-first is default-on in llm_agent; export keeps behavior obvious and allows CONTEXTDROID_LLM_NAV_FIRST_PIPELINE=0 to opt out.
export CONTEXTDROID_LLM_NAV_FIRST_PIPELINE="${CONTEXTDROID_LLM_NAV_FIRST_PIPELINE:-1}"

# Typical macOS SDK layout — adb is often missing from non-interactive PATH.
if [[ -d "${HOME}/Library/Android/sdk/platform-tools" ]]; then
  export PATH="${HOME}/Library/Android/sdk/platform-tools:${PATH}"
elif [[ -d "${HOME}/Android/Sdk/platform-tools" ]]; then
  export PATH="${HOME}/Android/Sdk/platform-tools:${PATH}"
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
if [[ -x "${BASE_DIR}/.venv/bin/python" ]]; then
  PYTHON_BIN="${BASE_DIR}/.venv/bin/python"
fi

echo "[llm-10min] duration_sec=${DURATION_SEC} sessions_per_app=${SESSIONS_PER_APP} nav_first=${CONTEXTDROID_LLM_NAV_FIRST_PIPELINE}"
echo "[llm-10min] adb: $(command -v adb 2>/dev/null || echo 'not found — set PATH or ANDROID_HOME')"

bash "${BASE_DIR}/extraction_pipeline/run_llm_audit_session.sh" "$1" "${DURATION_SEC}"

SESSION_NUM="${AUDIT_SESSION_NUM:-1}"
AUDIT="$(find "${BASE_DIR}/logs" -path "*/dynamic/llm/session_${SESSION_NUM}/*_llm_step_audit.jsonl" 2>/dev/null | head -n 1 || true)"
EXPORTER="${BASE_DIR}/extraction_pipeline/export_llm_session_for_claude.py"
if [[ -n "${AUDIT}" && -f "${EXPORTER}" ]]; then
  SESS_DIR="$(dirname "${AUDIT}")"
  echo "[llm-10min] exporting handoff report: ${SESS_DIR}"
  "${PYTHON_BIN}" "${EXPORTER}" "${SESS_DIR}" || true
fi
