#!/usr/bin/env bash
# Encrypted APFS vault for malware corpus samples (mount / unmount / status).
# Password: macOS Keychain (service ABRG_MW_VAULT) or interactive prompt only.
# Never stored in repo files, env vars, or script literals.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KEYCHAIN_SERVICE="${ABRG_MW_KEYCHAIN_SERVICE:-ABRG_MW_VAULT}"
KEYCHAIN_ACCOUNT="${USER}"
SPARSE_BUNDLE="${HOME}/Vaults/abrg_mw.sparsebundle"

vault_paths_py() {
  python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path("extraction_pipeline").resolve()))
from safety import vault_paths as vp
print(vp.MOUNT_ROOT)
print(vp.SPARSE_BUNDLE)
print(vp.VOLUME_NAME)
PY
}

read_vault_paths() {
  MOUNT_ROOT=""
  _SPARSE_PY=""
  VOLUME_NAME=""
  while IFS= read -r line; do
    if [[ -z "${MOUNT_ROOT}" ]]; then MOUNT_ROOT="${line}"
    elif [[ -z "${_SPARSE_PY}" ]]; then _SPARSE_PY="${line}"
    else VOLUME_NAME="${line}"; fi
  done < <(vault_paths_py)
}

log() { printf '[vault] %s\n' "$*" >&2; }

read_vault_password() {
  local pw
  if pw="$(security find-generic-password -a "${KEYCHAIN_ACCOUNT}" -s "${KEYCHAIN_SERVICE}" -w 2>/dev/null)"; then
    printf '%s' "${pw}"
    return 0
  fi
  if [[ -t 0 ]]; then
    read -rsp "Vault password: " pw >&2
    echo >&2
    printf '%s' "${pw}"
    return 0
  fi
  log "no Keychain entry (${KEYCHAIN_SERVICE}) and stdin is not a TTY"
  return 1
}

is_mounted() {
  mount | grep -F " on ${MOUNT_ROOT} " >/dev/null 2>&1
}

sync_check() {
  python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path("extraction_pipeline").resolve()))
from safety.vault_paths import SPARSE_BUNDLE, sparse_bundle_under_sync_root
if sparse_bundle_under_sync_root():
    print(f"ERROR: sparse bundle resolves under a sync-managed root: {SPARSE_BUNDLE}", file=sys.stderr)
    sys.exit(1)
print("sync_check_ok")
PY
}

cmd_init() {
  mkdir -p "${HOME}/Vaults"
  if [[ -e "${SPARSE_BUNDLE}" ]]; then
    log "sparse bundle already exists: ${SPARSE_BUNDLE}"
    return 0
  fi
  sync_check
  local pw
  pw="$(read_vault_password)" || exit 1
  log "creating encrypted sparse bundle at ${SPARSE_BUNDLE}"
  printf '%s' "${pw}" | hdiutil create -size 20g -type SPARSEBUNDLE -fs APFS \
    -encryption AES-256 -stdinpass -volname "${VOLUME_NAME}" "${SPARSE_BUNDLE}"
  log "created ${SPARSE_BUNDLE}"
}

cmd_mount() {
  if is_mounted; then
    log "already mounted at ${MOUNT_ROOT}"
    cmd_layout
    return 0
  fi
  if [[ ! -e "${SPARSE_BUNDLE}" ]]; then
    log "sparse bundle missing — run: $0 init"
    exit 1
  fi
  sync_check
  local pw attach_out dev
  pw="$(read_vault_password)" || exit 1
  attach_out="$(printf '%s' "${pw}" | hdiutil attach -stdinpass -nobrowse "${SPARSE_BUNDLE}" 2>&1)" || {
    log "hdiutil attach failed: ${attach_out}"
    exit 1
  }
  if ! is_mounted; then
    log "attach succeeded but ${MOUNT_ROOT} not mounted: ${attach_out}"
    exit 1
  fi
  log "mounted ${MOUNT_ROOT}"
  cmd_layout
}

cmd_layout() {
  is_mounted || { log "not mounted"; exit 1; }
  mkdir -p "${MOUNT_ROOT}/quarantine" "${MOUNT_ROOT}/staging" "${MOUNT_ROOT}/manifest" \
    "${MOUNT_ROOT}/traces" "${MOUNT_ROOT}/logs" "${MOUNT_ROOT}/logs/sink"
}

cmd_unmount() {
  if ! is_mounted; then
    log "not mounted"
    return 0
  fi
  hdiutil detach "${MOUNT_ROOT}" >/dev/null
  log "unmounted ${MOUNT_ROOT}"
}

cmd_status() {
  if is_mounted; then
    echo "mounted ${MOUNT_ROOT}"
    mount | grep -F " on ${MOUNT_ROOT} " || true
  else
    echo "unmounted"
  fi
  if [[ -e "${SPARSE_BUNDLE}" ]]; then
    echo "sparsebundle ${SPARSE_BUNDLE}"
  else
    echo "sparsebundle missing"
  fi
}

cmd_assert_mounted() {
  if is_mounted; then
    exit 0
  fi
  log "vault not mounted at ${MOUNT_ROOT}"
  exit 1
}

usage() {
  cat <<EOF
Usage: $0 {init|mount|unmount|status|assert_mounted|layout}

  init            Create ~/Vaults/abrg_mw.sparsebundle (once)
  mount           Attach vault and ensure internal layout
  unmount         Detach vault volume (see vault_paths.MOUNT_ROOT)
  status          Print mounted/unmounted state
  assert_mounted  Exit 0 iff mounted; else 1 with message
  layout          Create quarantine/staging/manifest/traces/logs under mount

Password: Keychain service "${KEYCHAIN_SERVICE}" (account ${KEYCHAIN_ACCOUNT}) or TTY prompt.
EOF
}

main() {
  cd "${ROOT}"
  read_vault_paths
  case "${1:-}" in
    init) cmd_init ;;
    mount) cmd_mount ;;
    unmount) cmd_unmount ;;
    status) cmd_status ;;
    assert_mounted) cmd_assert_mounted ;;
    layout) cmd_layout ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
