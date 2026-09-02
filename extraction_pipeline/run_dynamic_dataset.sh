#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <apk_folder> [duration_seconds]"
  exit 1
fi

APK_DIR="$1"
DURATION="${2:-180}"
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${CONTEXTDROID_RUN_LOG_DIR:-${BASE_DIR}/logs}"
RUN_LOG="${LOG_DIR}/run_log.txt"
INDEX_CSV="${DATASET_INDEX_CSV:-${LOG_DIR}/dataset_index.csv}"
PYTHON_BIN="${PYTHON_BIN:-}"
MIN_VALID_EVENTS="${MIN_VALID_EVENTS:-5}"
MIN_CATEGORY_COUNT="${MIN_CATEGORY_COUNT:-2}"
ARM_MODE="${ARM_MODE:-monkey}"
OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.2}"
OLLAMA_ENDPOINT="${OLLAMA_ENDPOINT:-http://127.0.0.1:11434}"
ENABLE_COMPARISON="${ENABLE_COMPARISON:-0}"
RUN_MODE="${RUN_MODE:-llm_only}"
SESSIONS_PER_APP="${SESSIONS_PER_APP:-}"

mkdir -p "${LOG_DIR}"
touch "${RUN_LOG}"

INDEX_HEADER="sample_id,apk_filename,apk_sha256,label,source,package_name,analysis_timestamp,duration_sec,status,status_detail,frida_log_path,strace_log_path,frida_csv_path,frida_quality_path,metadata_path,arm,metadata_source,context_confidence,session_id,planner_model,llm_simulation_status,data_quality_status"
if [[ ! -f "${INDEX_CSV}" ]]; then
  echo "${INDEX_HEADER}" >"${INDEX_CSV}"
elif ! head -n 1 "${INDEX_CSV}" | grep -q "llm_simulation_status"; then
  tmp_index="${INDEX_CSV}.tmp"
  {
    echo "${INDEX_HEADER}"
    tail -n +2 "${INDEX_CSV}" | awk '{print $0 ",unknown,unknown"}'
  } >"${tmp_index}"
  mv "${tmp_index}" "${INDEX_CSV}"
fi

log() {
  local msg="$1"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${msg}" | tee -a "${RUN_LOG}"
}

if [[ -z "${PYTHON_BIN}" ]]; then
  if [[ -x "${BASE_DIR}/.venv/bin/python" ]]; then
    PYTHON_BIN="${BASE_DIR}/.venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
  else
    log "[error] python3 not found."
    exit 1
  fi
fi

AAPT_BIN="${AAPT_BIN:-}"
if [[ -z "${AAPT_BIN}" ]]; then
  if command -v aapt >/dev/null 2>&1; then
    AAPT_BIN="$(command -v aapt)"
  else
    sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
    if [[ -z "${sdk_root}" ]]; then
      if [[ -d "${HOME}/Library/Android/sdk" ]]; then
        sdk_root="${HOME}/Library/Android/sdk"
      elif [[ -d "${HOME}/Android/Sdk" ]]; then
        sdk_root="${HOME}/Android/Sdk"
      fi
    fi
    if [[ -n "${sdk_root}" && -d "${sdk_root}/build-tools" ]]; then
      AAPT_BIN="$(ls -1 "${sdk_root}/build-tools"/*/aapt 2>/dev/null | sort -V | tail -n 1 || true)"
    fi
  fi
fi

if [[ -z "${AAPT_BIN}" ]]; then
  log "[error] aapt not found."
  exit 1
fi

extract_pkg() {
  local apk_file="$1"
  ("${AAPT_BIN}" dump badging "${apk_file}" 2>/dev/null || true) | awk -F"'" '/package: name=/{print $2; exit}'
}

sanitize_name() {
  echo "$1" | tr '/: ' '___'
}

LABEL="$(basename "${APK_DIR}")"

if [[ "${ENABLE_COMPARISON}" == "1" ]]; then
  if [[ -z "${SESSIONS_PER_APP}" ]]; then
    SESSIONS_PER_APP=3
  fi
else
  if [[ -z "${SESSIONS_PER_APP}" ]]; then
    SESSIONS_PER_APP=1
  fi
fi

declare -a ARMS
if [[ "${RUN_MODE}" == "llm_plus_monkey" || "${ARM_MODE}" == "llm_plus_monkey" ]]; then
  ARMS=("llm" "monkey")
elif [[ "${ARM_MODE}" == "llm" || "${RUN_MODE}" == "llm_only" ]]; then
  ARMS=("llm")
else
  ARMS=("monkey")
fi

APK_LIST=()
while IFS= read -r apk_path; do
  [[ -n "${apk_path}" ]] && APK_LIST+=("${apk_path}")
done < <("${PYTHON_BIN}" - <<PY
from pathlib import Path
for p in sorted(Path("${APK_DIR}").glob("*.apk")):
    print(str(p))
PY
)
if [[ ${#APK_LIST[@]} -eq 0 ]]; then
  log "No APK files found in ${APK_DIR}"
  exit 0
fi

needs_ollama=0
for a in "${ARMS[@]}"; do
  if [[ "${a}" == "llm" ]]; then
    needs_ollama=1
    break
  fi
done
if [[ "${needs_ollama}" -eq 1 ]]; then
  log "Ensuring Ollama is reachable (${OLLAMA_ENDPOINT:-http://127.0.0.1:11434}) ..."
  if ! LOG_DIR="${LOG_DIR}" OLLAMA_ENDPOINT="${OLLAMA_ENDPOINT}" bash "${BASE_DIR}/extraction_pipeline/ensure_ollama.sh"; then
    log "[error] Ollama is required for LLM runs but could not be started. Install Ollama, or set SKIP_OLLAMA_AUTO_START=1 if you start it yourself."
    exit 1
  fi
fi

for apk in "${APK_LIST[@]}"; do

  pkg_name="$(extract_pkg "${apk}")"
  apk_sha256="$(shasum -a 256 "${apk}" | awk '{print $1}')"
  sample_id="${apk_sha256:0:12}"
  analysis_timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

  if [[ -z "${pkg_name}" ]]; then
    log "FAILED $(basename "${apk}"): could not extract package name"
    printf '%s,"%s",%s,%s,"%s",%s,%s,%s,%s,%s,"%s","%s","%s","%s","%s","%s","%s","%s","%s","%s"\n' \
      "${sample_id}" "$(basename "${apk}")" "${apk_sha256}" "${LABEL}" "${APK_DIR}" \
      "unknown" "${analysis_timestamp}" "${DURATION}" "failed" "failed_extract_package" \
      "" "" "" "" "" "unknown" "unknown" "unknown" "unknown" "unknown" >>"${INDEX_CSV}"
    continue
  fi

  safe_pkg="$(sanitize_name "${pkg_name}")"
  sample_dir="${LOG_DIR}/${sample_id}_${safe_pkg}"

  for arm in "${ARMS[@]}"; do
    for ((session_num=1; session_num<=SESSIONS_PER_APP; session_num++)); do
      session_id="${sample_id}_${arm}_s${session_num}"
      dynamic_dir="${sample_dir}/dynamic/${arm}/session_${session_num}"
      mkdir -p "${dynamic_dir}"

      frida_log="${dynamic_dir}/${pkg_name}_frida.jsonl"
      frida_csv="${dynamic_dir}/${pkg_name}_frida.csv"
      frida_quality_json="${dynamic_dir}/${pkg_name}_frida.quality.json"
      strace_log="${dynamic_dir}/${pkg_name}_strace.log"
      metadata_path="${dynamic_dir}/${pkg_name}_dynamic_metadata.json"

      log "START ${pkg_name} arm=${arm} session=${session_num} (${apk})"
      set +e
      strict_flag=""
      fairness_flag=""
      if [[ "${ENABLE_COMPARISON}" == "1" ]]; then
        strict_flag="--strict-clean-start"
        fairness_flag="--fairness-protocol"
      fi
      analyze_cmd=(
        "${PYTHON_BIN}" "${BASE_DIR}/extraction_pipeline/analyze_apk.py"
        --apk "${apk}"
        --pkg "${pkg_name}"
        --duration "${DURATION}"
        --output-dir "${dynamic_dir}"
        --arm "${arm}"
        --session-id "${session_id}"
        --ollama-model "${OLLAMA_MODEL}"
        --ollama-endpoint "${OLLAMA_ENDPOINT}"
      )
      if [[ -n "${strict_flag}" ]]; then
        analyze_cmd+=("${strict_flag}")
      fi
      if [[ -n "${fairness_flag}" ]]; then
        analyze_cmd+=("${fairness_flag}")
      fi
      "${analyze_cmd[@]}"
      analyze_rc=$?

      "${PYTHON_BIN}" "${BASE_DIR}/extraction_pipeline/parse_logs.py" \
        --frida-log "${frida_log}" \
        --output "${frida_csv}" \
        --quality-output "${frida_quality_json}"
      parse_rc=$?

      quality_rc=0
      if [[ ${parse_rc} -eq 0 && -f "${frida_quality_json}" ]]; then
        "${PYTHON_BIN}" - <<PY
import json
from pathlib import Path
q = json.loads(Path("${frida_quality_json}").read_text(encoding="utf-8"))
valid_events = int(q.get("valid_events", 0))
unique_categories = int(q.get("unique_categories", 0))
if valid_events < int("${MIN_VALID_EVENTS}") or unique_categories < int("${MIN_CATEGORY_COUNT}"):
    raise SystemExit(2)
PY
        quality_rc=$?
      fi
      set -e

      status_detail="failed_analyze"
      if [[ ${analyze_rc} -eq 0 ]]; then
        status_detail="success"
      elif [[ ${analyze_rc} -eq 10 ]]; then
        status_detail="failed_install"
      elif [[ ${analyze_rc} -eq 11 ]]; then
        status_detail="skip:unstable"
      elif [[ ${analyze_rc} -eq 12 ]]; then
        status_detail="failed_frida_attach"
      elif [[ ${analyze_rc} -eq 13 ]]; then
        status_detail="failed_unexpected"
      elif [[ ${analyze_rc} -eq 14 ]]; then
        status_detail="failed_snapshot_restore"
      elif [[ ${analyze_rc} -eq 15 ]]; then
        status_detail="failed_pm_clear"
      elif [[ ${analyze_rc} -eq 16 ]]; then
        status_detail="failed_ollama_startup"
      fi

      if [[ ${analyze_rc} -eq 0 ]]; then
        if [[ ${parse_rc} -ne 0 ]]; then
          status_detail="failed_parse"
        elif [[ ${quality_rc} -ne 0 ]]; then
          status_detail="failed_quality_gate"
        fi
      fi

      if [[ ${analyze_rc} -eq 0 && ${parse_rc} -eq 0 && ${quality_rc} -eq 0 ]]; then
        status="success"
        log "SUCCESS ${pkg_name} arm=${arm} session=${session_num}"
      else
        status="failed"
        log "FAILED ${pkg_name} arm=${arm} session=${session_num}: detail=${status_detail} analyze=${analyze_rc} parse=${parse_rc} quality=${quality_rc}"
      fi

      arm_value="unknown"
      metadata_source="unknown"
      context_confidence="unknown"
      planner_model="unknown"
      analysis_status="unknown"
      llm_simulation_status="unknown"
      data_quality_status="unknown"
      if [[ -f "${metadata_path}" ]]; then
        meta_line="$("${PYTHON_BIN}" -c '
import json
import sys
from pathlib import Path
p = Path(sys.argv[1])
obj = json.loads(p.read_text(encoding="utf-8"))
vals = [
    obj.get("arm", "unknown"),
    obj.get("metadata_source", "unknown"),
    obj.get("context_confidence", "unknown"),
    obj.get("planner_model", "unknown") or "unknown",
    obj.get("analysis_status", "unknown"),
    obj.get("llm_simulation_status", "unknown") or "unknown",
    obj.get("data_quality_status", "unknown") or "unknown",
]
print("\t".join(str(v).replace("\t", " ").replace("\n", " ") for v in vals))
' "${metadata_path}")"
        IFS=$'\t' read -r arm_value metadata_source context_confidence planner_model analysis_status llm_simulation_status data_quality_status <<< "${meta_line}"
        arm_value="${arm_value:-unknown}"
        metadata_source="${metadata_source:-unknown}"
        context_confidence="${context_confidence:-unknown}"
        planner_model="${planner_model:-unknown}"
        analysis_status="${analysis_status:-unknown}"
        llm_simulation_status="${llm_simulation_status:-unknown}"
        data_quality_status="${data_quality_status:-unknown}"
      fi

      if [[ "${analysis_status}" == partial:* || "${analysis_status}" == skip:* || "${analysis_status}" == flag:* ]]; then
        status_detail="${analysis_status}"
        if [[ "${analysis_status}" == partial:* || "${analysis_status}" == skip:* ]]; then
          status="failed"
        fi
      fi
      if [[ "${arm_value}" == "llm" && "${llm_simulation_status}" == failed:* ]]; then
        status="failed"
        status_detail="${llm_simulation_status}"
      fi

      if [[ -f "${metadata_path}" ]]; then
        updated_data_quality_status="$("${PYTHON_BIN}" - "${metadata_path}" "${status_detail}" "${parse_rc}" "${quality_rc}" <<'PY' || true
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
status_detail = sys.argv[2]
parse_rc = int(sys.argv[3])
quality_rc = int(sys.argv[4])
try:
    obj = json.loads(path.read_text(encoding="utf-8"))
except json.JSONDecodeError:
    raise SystemExit(0)

if parse_rc != 0:
    dq = "failed_parse"
elif quality_rc != 0:
    dq = "failed_quality_gate"
elif status_detail == "success":
    dq = "success"
else:
    dq = "not_evaluated"

obj["data_quality_status"] = dq
obj["dataset_status_detail"] = status_detail
path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
print(dq)
PY
)"
        if [[ -n "${updated_data_quality_status}" ]]; then
          data_quality_status="${updated_data_quality_status}"
        fi
      fi

      printf '%s,"%s",%s,%s,"%s",%s,%s,%s,%s,%s,"%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s"\n' \
        "${sample_id}" "$(basename "${apk}")" "${apk_sha256}" "${LABEL}" "${APK_DIR}" \
        "${pkg_name}" "${analysis_timestamp}" "${DURATION}" "${status}" "${status_detail}" \
        "${frida_log}" "${strace_log}" "${frida_csv}" "${frida_quality_json}" "${metadata_path}" \
        "${arm_value}" "${metadata_source}" "${context_confidence}" "${session_id}" "${planner_model}" \
        "${llm_simulation_status}" "${data_quality_status}" >>"${INDEX_CSV}"
    done
  done
done

log "Run complete."
