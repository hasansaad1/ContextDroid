#!/usr/bin/env bash
# Force every device-targeted adb command onto ANDROID_SERIAL via explicit -s.
# Structural prevention: a second attached device cannot receive commands.
set -euo pipefail

REAL_ADB="${CONTEXTDROID_REAL_ADB:-adb}"
SERIAL="${ANDROID_SERIAL:-}"

if [[ -z "${SERIAL}" ]]; then
  echo "adb_pinned: ANDROID_SERIAL is required" >&2
  exit 2
fi

# Global / non-device commands: do not inject -s.
case "${1:-}" in
  devices|start-server|kill-server|connect|disconnect|version|help|-h|--help)
    exec "${REAL_ADB}" "$@"
    ;;
esac

# Already explicitly targeted.
if [[ "${1:-}" == "-s" || "${1:-}" == "--serial" ]]; then
  exec "${REAL_ADB}" "$@"
fi

exec "${REAL_ADB}" -s "${SERIAL}" "$@"
