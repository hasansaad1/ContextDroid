#!/usr/bin/env bash
# Malware AVD session launcher — refuse without sink Gate A.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

ADB_BIN="${ADB_BIN:-${ROOT}/tools/platform-tools/adb}"
[[ -x "${ADB_BIN}" ]] || ADB_BIN="${HOME}/Library/Android/sdk/platform-tools/adb"
EMU_BIN="${EMU_BIN:-${HOME}/Library/Android/sdk/emulator/emulator}"

AVD_NAME="${AVD_NAME:-abrg_mw}"
ANDROID_SERIAL="${ANDROID_SERIAL:-emulator-5556}"
MW_PORT="${MW_PORT:-5556}"
DNS_HOST_PORT="${ABRG_SINK_DNS_PORT:-15353}"

log() { printf '[avd_session] %s\n' "$*" >&2; }

vault_sink_dir() {
  python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path("extraction_pipeline").resolve()))
from safety.vault_paths import assert_mounted, ensure_layout, MOUNT_ROOT
assert_mounted()
ensure_layout()
print(MOUNT_ROOT / "logs" / "sink")
PY
}

require_gate_a() {
  local run_id="$1"
  local sink_dir env_file flag
  sink_dir="$(vault_sink_dir)"
  env_file="${sink_dir}/${run_id}.env"
  flag="${sink_dir}/${run_id}.gate_a_ok"
  if [[ ! -f "${env_file}" ]]; then
    log "REFUSE: missing sink env for run_id=${run_id}"
    exit 1
  fi
  if [[ ! -f "${flag}" ]]; then
    log "REFUSE: Gate A not passed for run_id=${run_id}"
    exit 1
  fi
  # Re-check live health
  if ! bash "${ROOT}/scripts/safety/network_sink.sh" gate-a --run-id "${run_id}"; then
    log "REFUSE: Gate A live check failed"
    exit 1
  fi
}

cmd_launch() {
  local run_id=""
  local require_sink=1
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --run-id)
        run_id="${2:-}"
        shift 2
        ;;
      --run-id=*)
        run_id="${1#*=}"
        shift
        ;;
      --no-sink)
        # Explicit opt-out only for non-malware experimentation — still refuse for abrg_mw.
        log "REFUSE: --no-sink is not permitted for malware AVD ${AVD_NAME}"
        exit 1
        ;;
      *)
        log "unknown arg: $1"
        exit 2
        ;;
    esac
  done
  if [[ -z "${run_id}" ]]; then
    run_id="${ABRG_RUN_ID:-}"
  fi
  if [[ -z "${run_id}" ]]; then
    log "REFUSE: --run-id required (sink Gate A must already pass)"
    exit 2
  fi
  if [[ "${AVD_NAME}" == "abrg_mw" ]]; then
    require_gate_a "${run_id}"
  fi

  ADB_BIN="${ADB_BIN}" AVD_NAME="${AVD_NAME}" ANDROID_SERIAL="${ANDROID_SERIAL}" \
    bash "${ROOT}/scripts/safety/device_guard.sh" hard-prelaunch

  # -dns-server points qemu's 10.0.2.3 forwarder at host; guest DNAT still mandatory.
  # Host DNS listens on DNS_HOST_PORT; qemu always uses :53 so we rely on guest DNAT
  # for containment. Still pass a sentinel flag string for refuse-without-flags tests.
  local sink_flags=(-dns-server "127.0.0.1")
  log "launching ${AVD_NAME} serial=${ANDROID_SERIAL} with sink flags + Gate A ok"
  nohup "${EMU_BIN}" -avd "${AVD_NAME}" -port "${MW_PORT}" \
    "${sink_flags[@]}" \
    -writable-system -no-boot-anim -no-audio -gpu swiftshader_indirect \
    -no-snapshot-load -no-snapshot-save -no-window \
    >"/tmp/abrg_avd_session_${AVD_NAME}.log" 2>&1 &
  echo $!
}

cmd_refuse_demo() {
  # Used by gate_p4: prove launch without run-id / Gate A fails.
  if AVD_NAME=abrg_mw bash "${ROOT}/scripts/safety/avd_session.sh" launch 2>/tmp/avd_session_refuse.txt; then
    log "unexpected success without run-id"
    exit 1
  fi
  if ! grep -q 'REFUSE' /tmp/avd_session_refuse.txt; then
    log "expected REFUSE message"
    cat /tmp/avd_session_refuse.txt >&2
    exit 1
  fi
  echo "REFUSE_DEMO_OK"
}

cmd_watchdog_start() {
  local run_id="${ABRG_RUN_ID:-}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --run-id) run_id="${2:-}"; shift 2 ;;
      --run-id=*) run_id="${1#*=}"; shift ;;
      *) shift ;;
    esac
  done
  if [[ -z "${run_id}" ]]; then
    log "REFUSE: --run-id required for watchdog-start"
    exit 2
  fi
  # Session-lifetime rule re-verify; start only after guest rules are installed.
  if ! ANDROID_SERIAL="${ANDROID_SERIAL}" bash "${ROOT}/scripts/safety/guest_sink_rules.sh" verify >/dev/null; then
    log "REFUSE: guest sink rules not verified — install rules before watchdog"
    exit 1
  fi
  ANDROID_SERIAL="${ANDROID_SERIAL}" bash "${ROOT}/scripts/safety/sink_rule_watchdog.sh" start --run-id "${run_id}"
}

cmd_watchdog_stop() {
  local run_id="${ABRG_RUN_ID:-}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --run-id) run_id="${2:-}"; shift 2 ;;
      --run-id=*) run_id="${1#*=}"; shift ;;
      *) shift ;;
    esac
  done
  if [[ -z "${run_id}" ]]; then
    log "REFUSE: --run-id required for watchdog-stop"
    exit 2
  fi
  bash "${ROOT}/scripts/safety/sink_rule_watchdog.sh" stop --run-id "${run_id}"
}

usage() {
  cat <<EOF
Usage:
  $0 launch --run-id <ID>     # requires vault + sink Gate A for abrg_mw
  $0 refuse-demo              # prove fail-closed without sink
  $0 watchdog-start --run-id <ID>  # 15s rule pin watchdog (after guest_sink_rules install)
  $0 watchdog-stop --run-id <ID>
EOF
}

main() {
  local cmd="${1:-}"
  shift || true
  case "${cmd}" in
    launch) cmd_launch "$@" ;;
    refuse-demo) cmd_refuse_demo ;;
    watchdog-start) cmd_watchdog_start "$@" ;;
    watchdog-stop) cmd_watchdog_stop "$@" ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
