#!/usr/bin/env bash
# Pre-commit: reject APK/sample-like blobs and vault paths from entering git.
# Installed via: make install-hooks
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "${ROOT}" ]]; then
  echo "[precommit_no_samples] not inside a git repo" >&2
  exit 1
fi
cd "${ROOT}"

MAX_BYTES=$((2 * 1024 * 1024))
# Explicit allowlist for staged files larger than 2 MB (empty by default).
# Add repo-relative paths here only with justification.
ALLOWLIST_GT_2MB=(
)

is_allowlisted() {
  local path="$1"
  local a
  for a in "${ALLOWLIST_GT_2MB[@]+"${ALLOWLIST_GT_2MB[@]}"}"; do
    [[ "${path}" == "${a}" ]] && return 0
  done
  return 1
}

vault_path_blocked() {
  local path="$1"
  case "${path}" in
    *ABRG_MW*|vault/*|*/vault/*|*.sparsebundle|*abrg_mw.sparsebundle*)
      return 0
      ;;
  esac
  return 1
}

looks_like_apk_zip() {
  local path="$1"
  [[ -f "${path}" ]] || return 1
  # ZIP local-file magic
  local magic
  magic="$(dd if="${path}" bs=4 count=1 2>/dev/null | LC_ALL=C od -An -tx1 | tr -d ' \n')"
  [[ "${magic}" == "504b0304" ]] || return 1
  # Prefer zipinfo; fall back to python zipfile
  if command -v zipinfo >/dev/null 2>&1; then
    if zipinfo -1 "${path}" 2>/dev/null | grep -E -q '(^|/)(AndroidManifest\.xml|classes\.dex)$'; then
      return 0
    fi
    return 1
  fi
  python3 - "${path}" <<'PY'
import sys, zipfile
path = sys.argv[1]
try:
    with zipfile.ZipFile(path) as zf:
        names = set(zf.namelist())
except Exception:
    sys.exit(1)
if any(n == "AndroidManifest.xml" or n.endswith("/AndroidManifest.xml") or n == "classes.dex" or n.endswith("/classes.dex") for n in names):
    sys.exit(0)
sys.exit(1)
PY
}

fail() {
  echo "[precommit_no_samples] REJECT: $*" >&2
  exit 1
}

# Staged files (Added/Copied/Modified/Renamed)
while IFS= read -r -d '' path; do
  [[ -n "${path}" ]] || continue

  if vault_path_blocked "${path}"; then
    fail "staged path looks like vault/mount content: ${path}"
  fi

  if [[ -f "${path}" ]]; then
    size="$(wc -c <"${path}" | tr -d ' ')"
    if [[ "${size}" -gt "${MAX_BYTES}" ]] && ! is_allowlisted "${path}"; then
      fail "staged file exceeds 2 MB and is not allowlisted: ${path} (${size} bytes)"
    fi
    if looks_like_apk_zip "${path}"; then
      fail "staged ZIP looks like an Android APK (AndroidManifest.xml/classes.dex): ${path}"
    fi
  fi
done < <(git diff --cached --name-only --diff-filter=ACMR -z)

exit 0
