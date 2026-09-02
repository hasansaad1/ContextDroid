#!/usr/bin/env bash
# Resumable bulk LLM run from a fixed APK manifest (experiment / subset).
#
# Usage (repo root):
#   bash extraction_pipeline/run_bulk_llm_manifest_resumable.sh <manifest.txt> [duration_sec]
#
# Env: CONTEXTDROID_RUN_LOG_DIR, DATASET_INDEX_CSV, same as dataset resumable.
#
# Resume: re-run the same command after Ctrl+C or crash. Completed apps (analyze exit 0)
# are skipped. The interrupted app is not marked complete and restarts from scratch.
#
# State directory: logs/bulk_llm_dataset/state/
#   completed_apks.sha256   — one SHA256 per finished app
#   failed_apks.sha256      — non-zero analyze exit (skipped on resume unless BULK_RETRY_FAILED=1)
#   current.json            — in-flight app (re-run on resume)
#
# Env:
#   BULK_RETRY_FAILED=1     — retry apps listed in failed_apks.sha256
#   BULK_DRY_RUN=1          — list pending apps only
#   ANDROID_SERIAL, OLLAMA_MODEL, OLLAMA_ENDPOINT, SESSIONS_PER_APP (default 1)
#   DATASET_INDEX_CSV, CONTEXTDROID_RUN_LOG_DIR (default logs/bulk_llm_dataset)

set -euo pipefail

MANIFEST_PATH="${1:?manifest path required}"
DURATION="${2:-600}"
APK_ROOT="${APK_ROOT:-data/apks/benign}"
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${CONTEXTDROID_RUN_LOG_DIR:-${BASE_DIR}/logs/bulk_llm_dataset}"
STATE_DIR="${LOG_DIR}/state"
BATCH_LOG="${LOG_DIR}/batch.log"
INDEX_CSV="${DATASET_INDEX_CSV:-${LOG_DIR}/dataset_index.csv}"
COMPLETED_FILE="${STATE_DIR}/completed_apks.sha256"
FAILED_FILE="${STATE_DIR}/failed_apks.sha256"
CURRENT_FILE="${STATE_DIR}/current.json"
MANIFEST_FILE="${STATE_DIR}/apk_manifest.txt"

mkdir -p "${STATE_DIR}" "${LOG_DIR}"
touch "${BATCH_LOG}" "${COMPLETED_FILE}" "${FAILED_FILE}"

PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "${PYTHON_BIN}" ]]; then
  if [[ -x "${BASE_DIR}/.venv/bin/python" ]]; then
    PYTHON_BIN="${BASE_DIR}/.venv/bin/python"
  else
    PYTHON_BIN="$(command -v python3)"
  fi
fi

# shellcheck source=bulk_apk_sessions.sh
source "${BASE_DIR}/extraction_pipeline/bulk_apk_sessions.sh"

export ENABLE_COMPARISON="${ENABLE_COMPARISON:-1}"
export CONTEXTDROID_SKIP_SNAPSHOT_LOAD="${CONTEXTDROID_SKIP_SNAPSHOT_LOAD:-1}"
export FRIDA_USE_DOCKER="${FRIDA_USE_DOCKER:-0}"
export BULK_EMULATOR_WATCHDOG="${BULK_EMULATOR_WATCHDOG:-0}"
export SKIP_EMULATOR_AUTO_START="${SKIP_EMULATOR_AUTO_START:-0}"
export AVD_NAME="${AVD_NAME:-abrg_benign}"
export EMULATOR_GPU="${EMULATOR_GPU:-swiftshader_indirect}"
export EMULATOR_SHOW_WINDOW="${EMULATOR_SHOW_WINDOW:-1}"
export EMULATOR_NO_SNAPSHOT_LOAD="${EMULATOR_NO_SNAPSHOT_LOAD:-1}"
export EMULATOR_SAVE_SNAPSHOT="${EMULATOR_SAVE_SNAPSHOT:-0}"
export RUN_MODE="${RUN_MODE:-llm_only}"
export ARM_MODE="${ARM_MODE:-llm}"
export SESSIONS_PER_APP="${SESSIONS_PER_APP:-1}"
export OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.2}"
export OLLAMA_ENDPOINT="${OLLAMA_ENDPOINT:-http://127.0.0.1:11434}"
export CONTEXTDROID_LLM_AUDIT_SESSION="${CONTEXTDROID_LLM_AUDIT_SESSION:-0}"
export MIN_VALID_EVENTS="${MIN_VALID_EVENTS:-3}"
export MIN_CATEGORY_COUNT="${MIN_CATEGORY_COUNT:-2}"
export PATH="${BASE_DIR}/tools/platform-tools:${PATH}"

INDEX_HEADER="sample_id,apk_filename,apk_sha256,label,source,package_name,analysis_timestamp,duration_sec,status,status_detail,frida_log_path,strace_log_path,frida_csv_path,frida_quality_path,metadata_path,arm,metadata_source,context_confidence,session_id,planner_model,llm_simulation_status,data_quality_status"
if [[ ! -f "${INDEX_CSV}" ]]; then
  echo "${INDEX_HEADER}" >"${INDEX_CSV}"
fi

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${BATCH_LOG}"
}

if [[ "${SESSIONS_PER_APP}" =~ ^[0-9]+$ ]] && (( SESSIONS_PER_APP < 1 )); then
  log "[error] SESSIONS_PER_APP must be >= 1 (got ${SESSIONS_PER_APP})"
  exit 1
fi
log "Config: SESSIONS_PER_APP=${SESSIONS_PER_APP} SESSION_MODE_SCHEDULE=${SESSION_MODE_SCHEDULE:-identical,identical,varied}"

AAPT_BIN="${AAPT_BIN:-}"
if [[ -z "${AAPT_BIN}" ]]; then
  if command -v aapt >/dev/null 2>&1; then
    AAPT_BIN="$(command -v aapt)"
  else
    sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
    [[ -z "${sdk_root}" && -d "${HOME}/Library/Android/sdk" ]] && sdk_root="${HOME}/Library/Android/sdk"
    [[ -z "${sdk_root}" && -d "${HOME}/Android/Sdk" ]] && sdk_root="${HOME}/Android/Sdk"
    if [[ -n "${sdk_root}" && -d "${sdk_root}/build-tools" ]]; then
      AAPT_BIN="$(ls -1 "${sdk_root}/build-tools"/*/aapt 2>/dev/null | sort -V | tail -n 1 || true)"
    fi
  fi
fi
if [[ -z "${AAPT_BIN}" ]]; then
  log "[error] aapt not found"
  exit 1
fi

ADB_BIN="${ADB_BIN:-$(command -v adb || true)}"
if [[ -z "${ADB_BIN}" ]]; then
  ADB_BIN="${BASE_DIR}/tools/platform-tools/adb"
fi

extract_pkg() {
  ("${AAPT_BIN}" dump badging "$1" 2>/dev/null || true) | awk -F"'" '/package: name=/{print $2; exit}'
}

extract_min_sdk() {
  ("${AAPT_BIN}" dump badging "$1" 2>/dev/null || true) | awk -F"'" '/sdkVersion:/{print $2; exit}'
}

sanitize_name() {
  echo "$1" | tr '/: ' '___'
}

sha_done() {
  grep -qxF "$1" "${COMPLETED_FILE}" 2>/dev/null
}

sha_failed() {
  grep -qxF "$1" "${FAILED_FILE}" 2>/dev/null
}

MARK_COMPLETE=0
CURRENT_APK=""
CURRENT_SHA=""

on_signal() {
  if [[ "${MARK_COMPLETE}" != "1" && -n "${CURRENT_APK}" ]]; then
    log "Interrupted during ${pkg_name:-app} — will restart this APK on resume (see ${CURRENT_FILE})"
  fi
  exit 130
}
trap on_signal INT TERM

MANIFEST_FILE="${MANIFEST_PATH}"
TOTAL_APKS="$(grep -cve '^\s*$' "${MANIFEST_FILE}" || true)"

log "Bulk LLM manifest run: ${TOTAL_APKS} APKs from ${MANIFEST_FILE}, ${DURATION}s each"
log "State: ${STATE_DIR}"
log "Index: ${INDEX_CSV}"

exec 3<"${MANIFEST_PATH}"

if [[ "${BULK_DRY_RUN:-0}" == "1" ]]; then
  PENDING=0
  while IFS= read -r apk <&3 || [[ -n "${apk}" ]]; do
    [[ -z "${apk}" ]] && continue
    sha="$(shasum -a 256 "${apk}" | awk '{print $1}')"
    if sha_done "${sha}"; then status="skip:completed"
    elif sha_failed "${sha}" && [[ "${BULK_RETRY_FAILED:-0}" != "1" ]]; then status="skip:failed"
    else status="pending"; PENDING=$((PENDING + 1)); fi
    echo "${status}  ${sha:0:12}  $(basename "${apk}")"
  done
  log "Pending: ${PENDING}/${TOTAL_APKS}"
  exec 3<&-
  exit 0
fi

if [[ -f "${CURRENT_FILE}" ]]; then
  log "Resume: found in-flight marker: $(cat "${CURRENT_FILE}")"
fi

log "Ensuring Ollama (${OLLAMA_ENDPOINT}) ..."
if ! LOG_DIR="${LOG_DIR}" OLLAMA_ENDPOINT="${OLLAMA_ENDPOINT}" bash "${BASE_DIR}/extraction_pipeline/ensure_ollama.sh"; then
  log "[error] Ollama unavailable"
  exit 1
fi

export ANDROID_SERIAL="${ANDROID_SERIAL:-emulator-5554}"
export CONTEXTDROID_ISOLATE_EMULATOR="${CONTEXTDROID_ISOLATE_EMULATOR:-1}"
export CONTEXTDROID_STRICT_FOREGROUND="${CONTEXTDROID_STRICT_FOREGROUND:-1}"
export CONTEXTDROID_FOREGROUND_MISMATCH_LIMIT="${CONTEXTDROID_FOREGROUND_MISMATCH_LIMIT:-3}"
export FRIDA_EVENTS_STALE_SEC="${FRIDA_EVENTS_STALE_SEC:-45}"
export FRIDA_ATTACH_GRACE_SEC="${FRIDA_ATTACH_GRACE_SEC:-30}"
export CONTEXTDROID_ROOT_CAPTURE_DEADLINE_SEC="${CONTEXTDROID_ROOT_CAPTURE_DEADLINE_SEC:-30}"
export CONTEXTDROID_PRE_SETUP_MAX_SEC="${CONTEXTDROID_PRE_SETUP_MAX_SEC:-120}"
export CONTEXTDROID_LLM_UI_DUMP_TIMEOUT_SEC="${CONTEXTDROID_LLM_UI_DUMP_TIMEOUT_SEC:-15}"
export BULK_EMULATOR_REBOOT_EVERY_N="${BULK_EMULATOR_REBOOT_EVERY_N:-5}"

log "Ensuring Docker + Frida image ..."
if ! bash "${BASE_DIR}/extraction_pipeline/ensure_docker_frida.sh"; then
  log "[error] Docker/Frida image unavailable"
  exit 1
fi

log "Ensuring emulator (${ANDROID_SERIAL}, AVD=${AVD_NAME}) ..."
if ! LOG_DIR="${LOG_DIR}" ANDROID_SERIAL="${ANDROID_SERIAL}" AVD_NAME="${AVD_NAME}" \
  EMULATOR_GPU="${EMULATOR_GPU}" EMULATOR_SHOW_WINDOW="${EMULATOR_SHOW_WINDOW}" \
  EMULATOR_NO_SNAPSHOT_LOAD="${EMULATOR_NO_SNAPSHOT_LOAD}" \
  EMULATOR_SAVE_SNAPSHOT="${EMULATOR_SAVE_SNAPSHOT}" \
  bash "${BASE_DIR}/extraction_pipeline/ensure_emulator.sh"; then
  log "[error] emulator unavailable"
  exit 1
fi

DEVICE_SDK="$("${ADB_BIN}" -s "${ANDROID_SERIAL}" shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r' || true)"
if [[ -z "${DEVICE_SDK}" ]]; then
  DEVICE_SDK=0
fi
log "Device SDK level: ${DEVICE_SDK}"

BULK_EMULATOR_REBOOT_EVERY_N="${BULK_EMULATOR_REBOOT_EVERY_N:-5}"
APPS_SINCE_REBOOT=0

reboot_emulator_if_due() {
  if [[ "${BULK_EMULATOR_REBOOT_EVERY_N}" -le 0 ]]; then
    return 0
  fi
  if [[ "${APPS_SINCE_REBOOT}" -lt "${BULK_EMULATOR_REBOOT_EVERY_N}" ]]; then
    return 0
  fi
  log "Periodic emulator reboot (every ${BULK_EMULATOR_REBOOT_EVERY_N} apps, processed=${APPS_SINCE_REBOOT}) ..."
  "${ADB_BIN}" -s "${ANDROID_SERIAL}" reboot >/dev/null 2>&1 || true
  sleep 5
  if ! LOG_DIR="${LOG_DIR}" ANDROID_SERIAL="${ANDROID_SERIAL}" AVD_NAME="${AVD_NAME}" \
    EMULATOR_GPU="${EMULATOR_GPU}" EMULATOR_SHOW_WINDOW="${EMULATOR_SHOW_WINDOW}" \
    EMULATOR_NO_SNAPSHOT_LOAD="${EMULATOR_NO_SNAPSHOT_LOAD}" \
    EMULATOR_SAVE_SNAPSHOT="${EMULATOR_SAVE_SNAPSHOT}" \
    bash "${BASE_DIR}/extraction_pipeline/ensure_emulator.sh"; then
    log "[warn] emulator not ready after periodic reboot"
    return 1
  fi
  APPS_SINCE_REBOOT=0
  log "Periodic emulator reboot complete."
  return 0
}

WATCHDOG_PID=""
stop_watchdog() {
  if [[ -n "${WATCHDOG_PID}" ]] && kill -0 "${WATCHDOG_PID}" 2>/dev/null; then
    kill "${WATCHDOG_PID}" 2>/dev/null || true
    wait "${WATCHDOG_PID}" 2>/dev/null || true
  fi
}

if [[ "${BULK_EMULATOR_WATCHDOG:-1}" == "1" ]]; then
  WATCH_PID_FILE="${LOG_DIR}/emulator_watchdog.pid"
  if [[ -f "${WATCH_PID_FILE}" ]]; then
    old_pid="$(cat "${WATCH_PID_FILE}" 2>/dev/null || true)"
    if [[ -n "${old_pid}" ]] && kill -0 "${old_pid}" 2>/dev/null; then
      WATCHDOG_PID="${old_pid}"
      log "Emulator watchdog already running (pid=${WATCHDOG_PID})"
    fi
  fi
  if [[ -z "${WATCHDOG_PID}" ]]; then
    LOG_DIR="${LOG_DIR}" ANDROID_SERIAL="${ANDROID_SERIAL}" \
      nohup bash "${BASE_DIR}/extraction_pipeline/run_emulator_watchdog.sh" \
      >>"${LOG_DIR}/emulator_watchdog.log" 2>&1 &
    WATCHDOG_PID=$!
    log "Started emulator watchdog (pid=${WATCHDOG_PID})"
  fi
  trap 'stop_watchdog; on_signal' INT TERM
fi

DONE_COUNT="$(wc -l <"${COMPLETED_FILE}" | tr -d ' ')"
IDX=0
SKIPPED=0

while IFS= read -r apk <&3 || [[ -n "${apk}" ]]; do
  [[ -z "${apk}" ]] && continue
  IDX=$((IDX + 1))
  apk_sha256="$(shasum -a 256 "${apk}" | awk '{print $1}')"

  if sha_done "${apk_sha256}"; then
    SKIPPED=$((SKIPPED + 1))
    continue
  fi
  if sha_failed "${apk_sha256}" && [[ "${BULK_RETRY_FAILED:-0}" != "1" ]]; then
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  pkg_name="$(extract_pkg "${apk}")"
  if [[ -z "${pkg_name}" ]]; then
    log "[${IDX}/${TOTAL_APKS}] SKIP $(basename "${apk}"): no package name"
    echo "${apk_sha256}" >>"${FAILED_FILE}"
    continue
  fi

  min_sdk="$(extract_min_sdk "${apk}")"
  if [[ -n "${min_sdk}" ]] && [[ "${DEVICE_SDK}" =~ ^[0-9]+$ ]] && [[ "${min_sdk}" =~ ^[0-9]+$ ]] && (( min_sdk > DEVICE_SDK )); then
    log "[${IDX}/${TOTAL_APKS}] FAIL ${pkg_name} minSdk=${min_sdk} > deviceSdk=${DEVICE_SDK} (precheck skip)"
    echo "${apk_sha256}" >>"${FAILED_FILE}"
    rm -f "${CURRENT_FILE}"
    continue
  fi

  sample_id="${apk_sha256:0:12}"
  safe_pkg="$(sanitize_name "${pkg_name}")"
  sample_dir="${LOG_DIR}/${sample_id}_${safe_pkg}"
  mkdir -p "${sample_dir}"

  CURRENT_APK="${apk}"
  CURRENT_SHA="${apk_sha256}"
  MARK_COMPLETE=0
  "${PYTHON_BIN}" - <<PY
import json, time
from pathlib import Path
Path("${CURRENT_FILE}").write_text(json.dumps({
    "apk_path": "${apk}",
    "apk_sha256": "${apk_sha256}",
    "package_name": "${pkg_name}",
    "started_at_epoch": int(time.time()),
    "duration_sec": int("${DURATION}"),
    "sessions_per_app": int("${SESSIONS_PER_APP}"),
    "index": ${IDX},
    "total": ${TOTAL_APKS},
}, indent=2), encoding="utf-8")
PY

  log "[${IDX}/${TOTAL_APKS}] START ${pkg_name} (${DURATION}s x ${SESSIONS_PER_APP} sessions) $(basename "${apk}")"

  reboot_emulator_if_due || true

  if ! LOG_DIR="${LOG_DIR}" ANDROID_SERIAL="${ANDROID_SERIAL}" AVD_NAME="${AVD_NAME}" \
    EMULATOR_GPU="${EMULATOR_GPU}" EMULATOR_SHOW_WINDOW="${EMULATOR_SHOW_WINDOW}" \
  EMULATOR_NO_SNAPSHOT_LOAD="${EMULATOR_NO_SNAPSHOT_LOAD}" \
    EMULATOR_SAVE_SNAPSHOT="${EMULATOR_SAVE_SNAPSHOT}" \
    bash "${BASE_DIR}/extraction_pipeline/ensure_emulator.sh"; then
    log "[${IDX}/${TOTAL_APKS}] FAIL ${pkg_name}: emulator not ready"
    echo "${apk_sha256}" >>"${FAILED_FILE}"
    rm -f "${CURRENT_FILE}"
    continue
  fi

  bulk_run_apk_llm_sessions "${apk}" "${pkg_name}" "${apk_sha256}" "${sample_id}" "${safe_pkg}" "${sample_dir}" "${IDX}" "${TOTAL_APKS}"

  if [[ "${BULK_APK_ALL_OK:-0}" == "1" ]]; then
    echo "${apk_sha256}" >>"${COMPLETED_FILE}"
    MARK_COMPLETE=1
    rm -f "${CURRENT_FILE}"
    DONE_COUNT=$((DONE_COUNT + 1))
    log "[${IDX}/${TOTAL_APKS}] DONE ${pkg_name} all ${SESSIONS_PER_APP} sessions (completed ${DONE_COUNT}/${TOTAL_APKS})"
  else
    rm -f "${CURRENT_FILE}"
    log "[${IDX}/${TOTAL_APKS}] PARTIAL/FAIL ${pkg_name} — not all sessions succeeded (resume will skip finished sessions via run_manifest.json)"
  fi

  APPS_SINCE_REBOOT=$((APPS_SINCE_REBOOT + 1))
  CURRENT_APK=""
  CURRENT_SHA=""
done

exec 3<&-
log "Batch finished. completed=${DONE_COUNT} skipped_already_done=${SKIPPED} total=${TOTAL_APKS}"
