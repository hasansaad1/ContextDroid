#!/usr/bin/env bash
# Ensure Ollama HTTP API is reachable for LLM sessions. If not, start `ollama serve` in the
# background (when `ollama` is on PATH) and wait until /api/tags responds.
#
# Environment:
#   OLLAMA_ENDPOINT   default http://127.0.0.1:11434
#   LOG_DIR             optional; default ../logs from this script's repo root
#   SKIP_OLLAMA_AUTO_START  set to 1 to skip (use your own Ollama)
#
# On success, may export CONTEXTDROID_OLLAMA_PID when this script started the server (for cleanup).

set -euo pipefail

if [[ "${SKIP_OLLAMA_AUTO_START:-0}" == "1" ]]; then
  exit 0
fi

BASE_URL="${OLLAMA_ENDPOINT:-http://127.0.0.1:11434}"
BASE_URL="${BASE_URL%/}"
TAGS_URL="${BASE_URL}/api/tags"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_DIR="${LOG_DIR:-${REPO_ROOT}/logs}"
mkdir -p "${LOG_DIR}"
SERVE_LOG="${LOG_DIR}/ollama_serve.log"

log() { printf '[ollama-ensure] %s\n' "$1" >&2; }

tags_ok() {
  curl -fsS --connect-timeout 2 --max-time 5 "${TAGS_URL}" >/dev/null 2>&1
}

if tags_ok; then
  log "API already up at ${BASE_URL}"
  exit 0
fi

if command -v ollama >/dev/null 2>&1; then
  if pgrep -f "ollama serve" >/dev/null 2>&1 || pgrep -x ollama >/dev/null 2>&1; then
    log "waiting for existing Ollama process to accept ${TAGS_URL} ..."
    for _ in $(seq 1 90); do
      if tags_ok; then
        log "API ready"
        exit 0
      fi
      sleep 1
    done
    log "timeout: Ollama process present but ${TAGS_URL} never responded"
    exit 1
  fi

  log "starting: ollama serve (logs: ${SERVE_LOG})"
  nohup ollama serve >>"${SERVE_LOG}" 2>&1 &
  OLLAMA_PID=$!
  export CONTEXTDROID_OLLAMA_PID="${OLLAMA_PID}"
  for _ in $(seq 1 90); do
    if tags_ok; then
      log "API ready (started pid=${OLLAMA_PID})"
      exit 0
    fi
    if ! kill -0 "${OLLAMA_PID}" 2>/dev/null; then
      log "ollama serve exited early; see ${SERVE_LOG}"
      exit 1
    fi
    sleep 1
  done
  log "timeout: ollama serve did not respond on ${BASE_URL}"
  exit 1
fi

log "Ollama not reachable at ${TAGS_URL} and 'ollama' not on PATH — install Ollama or set SKIP_OLLAMA_AUTO_START=1 and start it yourself."
exit 1
