#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <packages_manifest.txt> [output_dir]"
  exit 1
fi

MANIFEST_FILE="$1"
OUT_DIR="${2:-samples/benign}"

if [[ ! -f "${MANIFEST_FILE}" ]]; then
  echo "[error] Manifest file not found: ${MANIFEST_FILE}"
  exit 1
fi

if ! command -v fdroidcl >/dev/null 2>&1; then
  echo "[error] fdroidcl is not installed. Install with: brew install fdroidcl"
  exit 1
fi

mkdir -p "${OUT_DIR}"
fdroidcl update >/dev/null 2>&1 || true

success=0
failed=0
while IFS= read -r raw_line || [[ -n "${raw_line}" ]]; do
  line="$(echo "${raw_line}" | tr -d '\r')"
  if [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]]; then
    continue
  fi
  pkg="$(echo "${line}" | awk '{print $1}')"
  if [[ -z "${pkg}" ]]; then
    continue
  fi
  if (cd "${OUT_DIR}" && fdroidcl download "${pkg}") >/dev/null 2>&1; then
    echo "[ok] ${pkg}"
    success=$((success + 1))
  else
    echo "[failed] ${pkg}"
    failed=$((failed + 1))
  fi
done < "${MANIFEST_FILE}"

echo "[summary] success=${success} failed=${failed} output=${OUT_DIR}"
