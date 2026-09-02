#!/usr/bin/env bash
# Ensure Docker daemon is up and the Frida tools image exists (for analyze_apk).
#
# Environment:
#   FRIDA_USE_DOCKER       default 1; set 0 to skip
#   DOCKER_FRIDA_IMAGE     default frida-tools-local:14.8.1
#   SKIP_DOCKER_AUTO_START set 1 to skip auto-start of Docker Desktop

set -euo pipefail

if [[ "${FRIDA_USE_DOCKER:-1}" != "1" ]]; then
  exit 0
fi

IMAGE="${DOCKER_FRIDA_IMAGE:-frida-tools-local:14.8.1}"
FRIDA_VERSION="${FRIDA_VERSION:-17.9.1}"
FRIDA_TOOLS_VERSION="${FRIDA_TOOLS_VERSION:-14.9.0}"

log() { printf '[docker-ensure] %s\n' "$1" >&2; }

docker_ok() {
  docker info >/dev/null 2>&1
}

start_docker_desktop() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    return 1
  fi
  open -a Docker 2>/dev/null || open -a "Docker Desktop" 2>/dev/null || return 1
  for _ in $(seq 1 90); do
    if docker_ok; then
      return 0
    fi
    sleep 2
  done
  return 1
}

ensure_frida_image() {
  if docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    log "Frida image present (${IMAGE})"
    return 0
  fi
  log "building Frida image ${IMAGE} ..."
  printf 'FROM python:3.11-slim\nRUN pip install -q frida==%s frida-tools==%s\n' "${FRIDA_VERSION}" "${FRIDA_TOOLS_VERSION}" \
    | docker build -t "${IMAGE}" - >/dev/null
  log "Frida image built"
}

if docker_ok; then
  ensure_frida_image
  exit 0
fi

if [[ "${SKIP_DOCKER_AUTO_START:-0}" == "1" ]]; then
  log "Docker not reachable and SKIP_DOCKER_AUTO_START=1"
  exit 1
fi

log "Docker daemon down; starting Docker Desktop ..."
if ! start_docker_desktop; then
  log "Docker did not become ready in time"
  exit 1
fi

ensure_frida_image
log "Docker ready"
exit 0
