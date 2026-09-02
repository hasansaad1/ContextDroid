"""Probe path constants. All new code lives under probe/androct/."""

from __future__ import annotations

import sys
from pathlib import Path

PROBE_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROBE_ROOT / "data"
OUT_DIR = PROBE_ROOT / "out"
EXTRACT_DIR = DATA_DIR / "extracted"

# Sibling ABGA repo — import existing mapper/graph; do not copy or modify.
ABGA_ROOT = PROBE_ROOT.parents[2] / "adaptive-behavioral-graph-analysis"
if not ABGA_ROOT.is_dir():
    raise FileNotFoundError(f"ABGA repo not found at {ABGA_ROOT}")
if str(ABGA_ROOT) not in sys.path:
    sys.path.insert(0, str(ABGA_ROOT))

CONTEXTDROID_ROOT = PROBE_ROOT.parents[1]
V2_SESSIONS = ABGA_ROOT / "datasets" / "v2" / "sessions"
