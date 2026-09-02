#!/usr/bin/env bash
# Resumable Step 2 verification log collection (ProtonVPN BEFORE + OTHER cohort AFTER).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

LOCK_DIR="${ROOT}/logs/step2_verification/collect.lock.d"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "collect_step2_verification already running (lock: $LOCK_DIR)" >&2
  exit 0
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT

export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${HOME}/Library/Android/sdk}"
export PATH="${ANDROID_SDK_ROOT}/platform-tools:${PATH}"
export EMULATOR_SHOW_WINDOW="${EMULATOR_SHOW_WINDOW:-0}"
export FRIDA_USE_DOCKER=0
export CONTEXTDROID_SKIP_SNAPSHOT_LOAD=1
export SESSIONS_PER_APP=1
export MIN_VALID_EVENTS=0
export MIN_CATEGORY_COUNT=0
export RUN_MODE=llm_only
unset ENABLE_COMPARISON

MANIFEST="${STEP2_CORPUS_AFTER_MANIFEST:-${ROOT}/logs/step2_corpus_after_manifest.txt}"
OTHER_DURATION="${OTHER_DURATION_SEC:-90}"
VPN_DURATION="${VPN_DURATION_SEC:-120}"
COLLECT_LOG="${ROOT}/logs/step2_verification/collect.log"

mkdir -p "$(dirname "$MANIFEST")" "$(dirname "$COLLECT_LOG")"
touch "$MANIFEST"

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$COLLECT_LOG"
}

manifest_has() {
  local needle="$1"
  grep -Fq "$needle" "$MANIFEST" 2>/dev/null
}

append_manifest() {
  local jsonl="$1"
  if [[ ! -f "$jsonl" ]]; then
    return 1
  fi
  if manifest_has "$jsonl"; then
    return 0
  fi
  echo "$jsonl" >>"$MANIFEST"
  log "manifest + $jsonl"
}

find_apk() {
  local pkg="$1"
  local apk
  apk="$(find "${ROOT}/data/apks" -name "${pkg}_*.apk" -print -quit 2>/dev/null || true)"
  if [[ -z "$apk" ]]; then
    apk="$(find "${ROOT}/data/apks" -name "${pkg}.apk" -print -quit 2>/dev/null || true)"
  fi
  printf '%s' "$apk"
}

ensure_device() {
  if ! adb devices 2>/dev/null | awk 'NR>1 && $2=="device"{found=1} END{exit !found}'; then
    log "emulator offline; calling ensure_emulator.sh"
    bash "${ROOT}/extraction_pipeline/ensure_emulator.sh" >>"$COLLECT_LOG" 2>&1
  fi
  export ANDROID_SERIAL="${ANDROID_SERIAL:-$(adb devices | awk 'NR>1 && $2=="device"{print $1; exit}')}"
  if [[ -z "${ANDROID_SERIAL:-}" ]]; then
    log "FATAL: no emulator device — stopping (no projected values)"
    exit 2
  fi
  log "device=${ANDROID_SERIAL}"
}

collect_one() {
  local pkg="$1"
  local duration="$2"
  local log_root="$3"
  local pre_step2="${4:-0}"

  local jsonl
  jsonl="$(find "$log_root" -path "*/dynamic/llm/session_1/${pkg}_llm_actions.jsonl" -print -quit 2>/dev/null || true)"
  if [[ -n "$jsonl" && -s "$jsonl" ]]; then
    append_manifest "$jsonl"
    log "skip existing $pkg -> $jsonl"
    return 0
  fi

  local apk staging
  apk="$(find_apk "$pkg")"
  if [[ -z "$apk" ]]; then
    log "MISSING APK for $pkg"
    return 1
  fi
  staging="${log_root}/apk_staging"
  mkdir -p "$staging"
  ln -sf "$apk" "${staging}/$(basename "$apk")"

  ensure_device
  export CONTEXTDROID_RUN_LOG_DIR="$log_root"
  if [[ "$pre_step2" == "1" ]]; then
    export CONTEXTDROID_PRE_STEP2=1
  else
    unset CONTEXTDROID_PRE_STEP2
  fi

  log "RUN $pkg duration=${duration}s pre_step2=${pre_step2}"
  if ! bash "${ROOT}/extraction_pipeline/run_dynamic_dataset.sh" "$staging" "$duration" >>"$COLLECT_LOG" 2>&1; then
    log "run_dynamic_dataset failed for $pkg (continuing)"
  fi
  unset CONTEXTDROID_PRE_STEP2

  jsonl="$(find "$log_root" -path "*/dynamic/llm/session_1/${pkg}_llm_actions.jsonl" -print -quit 2>/dev/null || true)"
  if [[ -n "$jsonl" && -s "$jsonl" ]]; then
    append_manifest "$jsonl"
    log "OK $pkg -> $jsonl"
    return 0
  fi
  log "NO JSONL for $pkg under $log_root"
  return 1
}

other_packages() {
  python3 - <<'PY'
import json
from pathlib import Path
data = json.loads(Path("experiment/phase_aware_metrics.json").read_text())
sessions = (data.get("v6_success_pool_238") or {}).get("sessions") or []
for pkg in sorted({s["package"] for s in sessions if s.get("cross_tab_bucket") == "high_back_wait_other"}):
    print(pkg)
PY
}

main() {
  log "=== collect_step2_verification start ==="
  ensure_device

  VPN_BEFORE_ROOT="${ROOT}/logs/step2_verification/protonvpn/before"
  VPN_AFTER_JSONL="${ROOT}/logs/step2_verification/protonvpn/after/0d50d7d9c132_ch.protonvpn.android/dynamic/llm/session_1/ch.protonvpn.android_llm_actions.jsonl"
  if [[ -f "$VPN_AFTER_JSONL" ]]; then
    append_manifest "$VPN_AFTER_JSONL"
  fi

  collect_one "ch.protonvpn.android" "$VPN_DURATION" "$VPN_BEFORE_ROOT" 1

  OTHER_ROOT="${ROOT}/logs/step2_verification/other"
  PKG_LIST="${ROOT}/logs/step2_verification/other_packages.txt"
  other_packages >"$PKG_LIST"
  pkg_total="$(wc -l <"$PKG_LIST" | tr -d ' ')"
  log "OTHER cohort packages=${pkg_total}"
  set +e
  while IFS= read -r pkg || [[ -n "${pkg:-}" ]]; do
    [[ -z "${pkg:-}" ]] && continue
    collect_one "$pkg" "$OTHER_DURATION" "${OTHER_ROOT}/${pkg}" 0
    rc=$?
    if [[ "$rc" -ne 0 ]]; then
      log "collect_one failed for $pkg (rc=$rc, continuing)"
    fi
  done <"$PKG_LIST"
  set -e

  log "=== collect_step2_verification done ==="
}

main "$@"
