#!/usr/bin/env bash
# Batch: N benign canaries with overlapping A–D monitor ticks.
# NO real malware. CONTEXTDROID_MALWARE_GO must stay unset.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

N="${1:-5}"
DURATION="${CANARY_DURATION:-60}"
ADB_BIN="${ADB_BIN:-${HOME}/Library/Android/sdk/platform-tools/adb}"
export ADB_BIN AVD_NAME=abrg_mw ANDROID_SERIAL=emulator-5556
export PATH="${ROOT}/.venv/bin:${HOME}/Library/Android/sdk/platform-tools:${PATH}"
export FRIDA_USE_DOCKER="${FRIDA_USE_DOCKER:-0}"
unset CONTEXTDROID_MALWARE_GO || true
unset CONTEXTDROID_DEVICE_GUARD_DISABLE || true

CANARY_APK="${CANARY_APK:-${ROOT}/data/apks/benign/ademar.textlauncher_10.apk}"
CANARY_PKG="${CANARY_PKG:-ademar.textlauncher}"
BATCH_ID="batch5-$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${ROOT}/logs/sim_canary/${BATCH_ID}"
mkdir -p "${OUT}/runs" "${OUT}/monitors"
SUMMARY="${OUT}/SUMMARY.txt"

note() { printf '%s\n' "$*" | tee -a "${SUMMARY}" >&2; }

count_python_script() {
  NEEDLE="$1" python3 - <<'PY'
import os, re, subprocess
needle = os.environ["NEEDLE"]
out = subprocess.check_output(["ps", "ax", "-o", "pid=", "-o", "command="], text=True)
n = 0
for line in out.splitlines():
    parts = line.split(None, 1)
    if len(parts) < 2:
        continue
    cmd = parts[1]
    argv0 = cmd.split(None, 1)[0]
    if not re.search(r"python", argv0, re.I):
        continue
    if needle in cmd:
        n += 1
print(n)
PY
}

monitor_loop() {
  local run_id="$1"
  local mon_dir="$2"
  local tick=0
  : > "${mon_dir}/ALL.log"
  while true; do
    tick=$((tick + 1))
    local rs aa
    rs="$(count_python_script 'scripts/corpus/run_sample.py')"
    aa="$(count_python_script 'extraction_pipeline/analyze_apk.py')"
    if [[ "${rs}" == "0" && "${aa}" == "0" && "${tick}" -gt 2 ]]; then
      echo "HARNESS_GONE tick=${tick}" >> "${mon_dir}/ALL.log"
      break
    fi
    if [[ "${tick}" -gt 40 ]]; then
      echo "MAX_TICKS tick=${tick}" >> "${mon_dir}/ALL.log"
      break
    fi
    echo "===== tick=${tick} utc=$(date -u +%H:%M:%S) rs=${rs} aa=${aa} =====" >> "${mon_dir}/ALL.log"
    local domain rc
    for domain in A B C D; do
      set +e
      SIM_PHASE=live-canary ABRG_RUN_ID="${run_id}" ANDROID_SERIAL=emulator-5556 \
        bash "${ROOT}/scripts/safety/malware_sim_monitor_tick.sh" \
        --domain "${domain}" --run-id "${run_id}" \
        >> "${mon_dir}/${domain}.log" 2>&1
      rc=$?
      set -e
      echo "domain=${domain} rc=${rc}" >> "${mon_dir}/ALL.log"
      if [[ "${rc}" -ne 0 ]]; then
        echo "NONCLEAR domain=${domain} tick=${tick}" >> "${mon_dir}/ALL.log"
        # Gate A fail after harness teardown is expected once rs=aa=0; only
        # escalate mid-run (harness still alive).
        if [[ "${rs}" != "0" || "${aa}" != "0" ]]; then
          echo "ESCALATE_MIDRUN domain=${domain} tick=${tick}" >> "${mon_dir}/ALL.log"
          bash "${ROOT}/scripts/safety/malware_sim_abort.sh" \
            "batch_monitor_${domain}_tick_${tick}" >> "${mon_dir}/abort.log" 2>&1 || true
          echo ABORTED > "${mon_dir}/RESULT"
          return 0
        fi
      fi
    done
    sleep 8
  done
  if [[ ! -f "${mon_dir}/RESULT" ]]; then
    echo CLEAR > "${mon_dir}/RESULT"
  fi
}

note "=== canary batch ${BATCH_ID} N=${N} duration=${DURATION} ==="
note "date_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
note "GO must stay unset (canary)"

if [[ ! -f "${CANARY_APK}" ]]; then
  note "FAIL: canary APK missing"
  exit 1
fi
boot="$("${ADB_BIN}" -s emulator-5556 shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
if [[ "${boot}" != "1" ]]; then
  note "FAIL: emulator-5556 not booted"
  exit 1
fi

PASS=0
FAIL=0
for i in $(seq 1 "${N}"); do
  RUN_ID="${BATCH_ID}-c${i}"
  note ""
  note "----- canary ${i}/${N} run_id=${RUN_ID} -----"
  MON="${OUT}/monitors/${RUN_ID}"
  mkdir -p "${MON}"
  RUN_LOG="${OUT}/runs/${RUN_ID}.log"

  # Start canary
  python3 "${ROOT}/scripts/corpus/run_sample.py" \
    --tier canary \
    --seal-from "${CANARY_APK}" \
    --pkg "${CANARY_PKG}" \
    --duration "${DURATION}" \
    --arm monkey \
    --run-id "${RUN_ID}" \
    --no-wipe-boot \
    > "${RUN_LOG}" 2>&1 &
  CANARY_PID=$!

  # Wait for Gate A (up to 90s)
  GATE_OK=0
  for _ in $(seq 1 90); do
    if bash "${ROOT}/scripts/safety/network_sink.sh" gate-a --run-id "${RUN_ID}" >/dev/null 2>&1; then
      GATE_OK=1
      break
    fi
    if ! kill -0 "${CANARY_PID}" 2>/dev/null; then
      break
    fi
    sleep 1
  done
  note "gate_a=${GATE_OK}"

  # Overlapping monitors
  monitor_loop "${RUN_ID}" "${MON}" &
  MON_PID=$!

  set +e
  wait "${CANARY_PID}"
  CRC=$?
  set -e
  wait "${MON_PID}" 2>/dev/null || true

  MON_RES="$(cat "${MON}/RESULT" 2>/dev/null || echo UNKNOWN)"
  OK_LINE="$(rg -n 'run_sample: OK' "${RUN_LOG}" || true)"
  note "canary_rc=${CRC} monitor=${MON_RES}"
  if [[ "${CRC}" -eq 0 && -n "${OK_LINE}" && "${MON_RES}" == "CLEAR" ]]; then
    note "RESULT PASS"
    PASS=$((PASS + 1))
  else
    note "RESULT FAIL (see ${RUN_LOG} / ${MON})"
    FAIL=$((FAIL + 1))
    # Tail for triage
    note "--- run log tail ---"
    tail -15 "${RUN_LOG}" | tee -a "${SUMMARY}" >&2 || true
    note "--- monitor ALL tail ---"
    tail -20 "${MON}/ALL.log" | tee -a "${SUMMARY}" >&2 || true
  fi

  # Brief settle between canaries
  sleep 3
done

note ""
note "=== batch summary PASS=${PASS} FAIL=${FAIL} N=${N} ==="
bash "${ROOT}/scripts/safety/malware_session_postflight.sh" --run-id "${BATCH_ID}-c${N}" \
  2>&1 | tee -a "${SUMMARY}" >&2 || true

if [[ "${FAIL}" -ne 0 ]]; then
  exit 1
fi
exit 0
