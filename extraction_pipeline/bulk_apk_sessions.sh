#!/usr/bin/env bash
# Shared multi-session loop for bulk LLM resumable orchestrators (Step 8).
# Source from run_bulk_llm_*_resumable.sh — do not execute directly.

if [[ -z "${BULK_SESSION_HELPERS_LOADED:-}" ]]; then
  BULK_SESSION_HELPERS_LOADED=1

  # Default schedule: 2 identical-config (variance floor) + 1 varied-seed (coverage).
  # Override with SESSION_MODE_SCHEDULE="identical,varied,..." (comma-separated, length >= SESSIONS_PER_APP).
  : "${SESSION_MODE_SCHEDULE:=identical,identical,varied}"

  bulk_session_mode() {
    local session_num="$1"
    local schedule="${SESSION_MODE_SCHEDULE}"
    local -a modes=()
    IFS=',' read -r -a modes <<<"${schedule}"
    local idx=$((session_num - 1))
    if [[ ${idx} -lt ${#modes[@]} ]]; then
      echo "${modes[${idx}]}"
    elif [[ ${#modes[@]} -gt 0 ]]; then
      echo "${modes[$(( ${#modes[@]} - 1 ))]}"
    else
      echo "varied"
    fi
  }

  bulk_session_seeds() {
    local apk_sha256="$1"
    local session_num="$2"
    local mode="$3"
    "${PYTHON_BIN}" - <<PY
import hashlib
apk = "${apk_sha256}"
session_num = int("${session_num}")
mode = "${mode}"
base = int(hashlib.sha256(apk.encode()).hexdigest()[:8], 16) % 2147483647
if mode == "identical":
    agent = base
    monkey = base
else:
    agent = int(hashlib.sha256(f"{apk}:varied:{session_num}".encode()).hexdigest()[:8], 16) % 2147483647
    monkey = int(hashlib.sha256(f"{apk}:monkey:varied:{session_num}".encode()).hexdigest()[:8], 16) % 2147483647
print(f"{agent}\t{monkey}")
PY
  }

  bulk_session_already_success() {
    local manifest="$1"
    local session_num="$2"
    [[ -f "${manifest}" ]] || return 1
    "${PYTHON_BIN}" - <<PY
import json, sys
from pathlib import Path
p = Path("${manifest}")
num = int("${session_num}")
try:
    m = json.loads(p.read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(1)
for s in m.get("sessions") or []:
    if int(s.get("session_num") or 0) == num and s.get("status") == "success":
        raise SystemExit(0)
raise SystemExit(1)
PY
  }

  bulk_update_run_manifest() {
    local manifest="$1"
    local apk_sha256="$2"
    local pkg_name="$3"
    local session_num="$4"
    local session_id="$5"
    local session_mode="$6"
    local agent_seed="$7"
    local monkey_seed="$8"
    local dynamic_dir="$9"
    local analyze_rc="${10}"
    local metadata_path="${11}"
    "${PYTHON_BIN}" - <<PY
import json
from datetime import datetime, timezone
from pathlib import Path

manifest = Path("${manifest}")
payload = {
    "apk_sha256": "${apk_sha256}",
    "package_name": "${pkg_name}",
    "sessions_per_app": int("${SESSIONS_PER_APP}"),
    "session_mode_schedule": "${SESSION_MODE_SCHEDULE}",
    "collection_config": "${CONTEXTDROID_COLLECTION_CONFIG:-}",
    "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "sessions": [],
}
if manifest.exists():
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        pass
sessions = [s for s in (payload.get("sessions") or []) if int(s.get("session_num") or 0) != int("${session_num}")]
sessions.append({
    "session_num": int("${session_num}"),
    "session_id": "${session_id}",
    "session_mode": "${session_mode}",
    "agent_seed": int("${agent_seed}"),
    "monkey_seed": int("${monkey_seed}"),
    "artifact_dir": "${dynamic_dir}",
    "metadata_path": "${metadata_path}",
    "status": "success" if int("${analyze_rc}") == 0 else "failed",
    "analyze_rc": int("${analyze_rc}"),
})
payload["sessions"] = sorted(sessions, key=lambda s: int(s.get("session_num") or 0))
payload["sessions_per_app"] = int("${SESSIONS_PER_APP}")
payload["session_mode_schedule"] = "${SESSION_MODE_SCHEDULE}"
payload["collection_config"] = "${CONTEXTDROID_COLLECTION_CONFIG:-}"
manifest.parent.mkdir(parents=True, exist_ok=True)
manifest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
PY
  }

  # Run SESSIONS_PER_APP LLM sessions for one APK. Sets BULK_APK_ALL_OK=1 on full success.
  bulk_run_apk_llm_sessions() {
    local apk="$1"
    local pkg_name="$2"
    local apk_sha256="$3"
    local sample_id="$4"
    local safe_pkg="$5"
    local sample_dir="$6"
    local idx="$7"
    local total="$8"

    BULK_APK_ALL_OK=0
    local manifest="${sample_dir}/run_manifest.json"
    local sessions_ok=0
    local session_num=0

    log "[bulk-sessions] SESSIONS_PER_APP=${SESSIONS_PER_APP} schedule=${SESSION_MODE_SCHEDULE} pkg=${pkg_name}"

    for ((session_num=1; session_num<=SESSIONS_PER_APP; session_num++)); do
      if bulk_session_already_success "${manifest}" "${session_num}"; then
        log "[${idx}/${total}] SKIP ${pkg_name} session_${session_num} (already success in run_manifest)"
        sessions_ok=$((sessions_ok + 1))
        continue
      fi

      local session_mode
      session_mode="$(bulk_session_mode "${session_num}")"
      local seed_line agent_seed monkey_seed
      seed_line="$(bulk_session_seeds "${apk_sha256}" "${session_num}" "${session_mode}")"
      IFS=$'\t' read -r agent_seed monkey_seed <<<"${seed_line}"

      local dynamic_dir="${sample_dir}/dynamic/llm/session_${session_num}"
      mkdir -p "${dynamic_dir}"
      local session_id="${sample_id}_llm_s${session_num}"
      local analysis_timestamp
      analysis_timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

      export CONTEXTDROID_LLM_AGENT_SEED="${agent_seed}"
      export CONTEXTDROID_SESSION_MODE="${session_mode}"
      export MONKEY_SEED="${monkey_seed}"

      log "[${idx}/${total}] START ${pkg_name} session=${session_num}/${SESSIONS_PER_APP} mode=${session_mode} agent_seed=${agent_seed}"

      local frida_log="${dynamic_dir}/${pkg_name}_frida.jsonl"
      local frida_csv="${dynamic_dir}/${pkg_name}_frida.csv"
      local frida_quality_json="${dynamic_dir}/${pkg_name}_frida.quality.json"
      local strace_log="${dynamic_dir}/${pkg_name}_strace.log"
      local metadata_path="${dynamic_dir}/${pkg_name}_dynamic_metadata.json"

      set +e
      "${PYTHON_BIN}" "${BASE_DIR}/extraction_pipeline/analyze_apk.py" \
        --apk "${apk}" \
        --pkg "${pkg_name}" \
        --duration "${DURATION}" \
        --output-dir "${dynamic_dir}" \
        --arm llm \
        --session-id "${session_id}" \
        --monkey-seed "${monkey_seed}" \
        --ollama-model "${OLLAMA_MODEL}" \
        --ollama-endpoint "${OLLAMA_ENDPOINT}" \
        --strict-clean-start \
        --fairness-protocol \
        </dev/null
      local analyze_rc=$?

      "${PYTHON_BIN}" "${BASE_DIR}/extraction_pipeline/parse_logs.py" \
        --frida-log "${frida_log}" \
        --output "${frida_csv}" \
        --quality-output "${frida_quality_json}" \
        </dev/null 2>/dev/null || true
      set -e

      if [[ -f "${metadata_path}" && -f "${frida_quality_json}" ]]; then
        "${PYTHON_BIN}" - <<PY
import json
from pathlib import Path
meta_path = Path("${metadata_path}")
quality_path = Path("${frida_quality_json}")
try:
    m = json.loads(meta_path.read_text(encoding="utf-8"))
    q = json.loads(quality_path.read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(0)
valid_events = int(q.get("valid_events", 0))
meaningful_events = int(q.get("meaningful_events", 0))
meaningful_categories = int(q.get("meaningful_categories", 0))
if ${analyze_rc} != 0:
    dq = "failed_analyze"
elif valid_events < int("${MIN_VALID_EVENTS}"):
    dq = "weak:low_events"
elif meaningful_events < 5:
    dq = "weak:low_meaningful_events"
elif meaningful_categories < int("${MIN_CATEGORY_COUNT}"):
    dq = "weak:low_meaningful_categories"
else:
    dq = "good"
m["data_quality_status"] = dq
m["frida_valid_events"] = valid_events
m["frida_meaningful_events"] = meaningful_events
m["frida_meaningful_categories"] = meaningful_categories
meta_path.write_text(json.dumps(m, ensure_ascii=False, indent=2), encoding="utf-8")
PY
      fi

      bulk_update_run_manifest \
        "${manifest}" "${apk_sha256}" "${pkg_name}" "${session_num}" \
        "${session_id}" "${session_mode}" "${agent_seed}" "${monkey_seed}" \
        "${dynamic_dir}" "${analyze_rc}" "${metadata_path}"

      local status_detail="failed_analyze"
      if [[ ${analyze_rc} -eq 0 ]]; then status_detail="success"; fi
      local status="failed"
      if [[ ${analyze_rc} -eq 0 ]]; then status="success"; fi

      local arm_value="llm"
      local metadata_source="unknown"
      local context_confidence="unknown"
      local planner_model="${OLLAMA_MODEL}"
      local llm_simulation_status="unknown"
      local data_quality_status="unknown"
      if [[ -f "${metadata_path}" ]]; then
        local meta_line
        meta_line="$("${PYTHON_BIN}" -c '
import json, sys
from pathlib import Path
obj = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print("\t".join(str(obj.get(k,"unknown") or "unknown") for k in (
    "arm","metadata_source","context_confidence","planner_model",
    "llm_simulation_status","data_quality_status")))
' "${metadata_path}" 2>/dev/null || echo -e "llm\tunknown\tunknown\t${OLLAMA_MODEL}\tunknown\tunknown")"
        IFS=$'\t' read -r arm_value metadata_source context_confidence planner_model llm_simulation_status data_quality_status <<<"${meta_line}" || true
      fi

      printf '%s,"%s",%s,%s,"%s",%s,%s,%s,%s,%s,"%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s"\n' \
        "${sample_id}" "$(basename "${apk}")" "${apk_sha256}" "benign" "${APK_ROOT}" \
        "${pkg_name}" "${analysis_timestamp}" "${DURATION}" "${status}" "${status_detail}" \
        "${frida_log}" "${strace_log}" "${frida_csv}" "${frida_quality_json}" "${metadata_path}" \
        "${arm_value}" "${metadata_source}" "${context_confidence}" "${session_id}" "${planner_model}" \
        "${llm_simulation_status}" "${data_quality_status}" >>"${INDEX_CSV}"

      if [[ ${analyze_rc} -eq 0 ]]; then
        sessions_ok=$((sessions_ok + 1))
        log "[${idx}/${total}] DONE ${pkg_name} session=${session_num} mode=${session_mode}"
      else
        log "[${idx}/${total}] FAIL ${pkg_name} session=${session_num} analyze_rc=${analyze_rc} (continuing remaining sessions)"
      fi
    done

    if [[ "${sessions_ok}" -eq "${SESSIONS_PER_APP}" ]]; then
      BULK_APK_ALL_OK=1
    fi
  }
fi
