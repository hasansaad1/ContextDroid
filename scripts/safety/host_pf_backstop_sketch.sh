#!/usr/bin/env bash
# Optional host pfctl backstop — PRINT ONLY. Does not apply rules (needs sudo + human).
# See docs/malware_host_defense_plan.md B5.
set -euo pipefail

DNS_PORT="${ABRG_SINK_DNS_PORT:-15353}"
HTTP_PORT="${ABRG_SINK_HTTP_PORT:-8080}"
HTTPS_PORT="${ABRG_SINK_HTTPS_PORT:-8443}"
UDP_CA="${ABRG_SINK_UDP_CATCHALL_PORT:-8053}"

cat <<EOF
# ABRG malware host backstop (OPTIONAL — defense in depth)
# Guest containment remains iptables + sink. This only suggests host-side deny.
#
# DO NOT paste blindly without understanding pfctl on macOS.
# Apply only with interactive sudo after human review.
#
# Intent: discourage qemu/emulator processes from arbitrary Internet egress
# while still allowing localhost sink ports ${DNS_PORT},${HTTP_PORT},${HTTPS_PORT},${UDP_CA}.
#
# Reality check: identifying the emulator's traffic on macOS pf is brittle
# (UTM/QEMU NAT). Prefer relying on guest catch-all + filter DROP + gate_p4.
# Treat this file as a residual-risk discussion aid, not a completed control.
#
# Example sketch (NOT auto-applied by harness):
#   block drop out proto {tcp udp} from any to any
#   pass out quick on lo0
#   pass out proto tcp to 127.0.0.1 port { ${HTTP_PORT} ${HTTPS_PORT} }
#   pass out proto udp to 127.0.0.1 port { ${DNS_PORT} ${UDP_CA} }
#
# To apply (HUMAN ONLY):
#   sudo pfctl -f /path/to/reviewed/rules.conf
# To disable:
#   sudo pfctl -d
EOF
