"""DroidFax allowlist line classifier for AndroCT traces.

Accepted in-format (Step 3.5 decision):
  (a) call lines `<sig> -> <sig>` (Jimple quotes / non-ASCII OK)
  (b) `+through reflection` annotations (kept as annotations, not dropped)
  (c) ICC multi-line blocks: [ Intent sent|received ], caller=, callsite=, tab fields
  (d) logcat beginning headers

NOT accepted: any other line (malware logcat pollution etc.) — explicit drop with counts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

CALL_RE = re.compile(r"^<.+>\s*->\s*<.+>$")
HEADER_RE = re.compile(r"^--------- beginning of \w+")
INTENT_MARKER_RE = re.compile(r"^\[ Intent (sent|received) \]$")


@dataclass
class LineStats:
    n_total: int = 0
    n_empty: int = 0
    n_call: int = 0
    n_reflection_tag: int = 0
    n_icc: int = 0
    n_header: int = 0
    n_dropped: int = 0
    dropped_examples: list[str] = field(default_factory=list)


def classify_allowlisted(line: str) -> str:
    """Return: empty|call|reflection_tag|icc|header|drop."""
    if not line.strip():
        return "empty"
    s = line.strip()
    if HEADER_RE.match(s):
        return "header"
    if CALL_RE.match(s):
        return "call"
    if s == "+through reflection":
        return "reflection_tag"
    if INTENT_MARKER_RE.match(s):
        return "icc"
    if s.startswith("caller=") or s.startswith("callsite="):
        return "icc"
    # tab-indented Intent field lines / category values
    if line.startswith("\t"):
        return "icc"
    return "drop"


def scan_file(path: Path, *, max_drop_examples: int = 5) -> LineStats:
    st = LineStats()
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            st.n_total += 1
            kind = classify_allowlisted(line.rstrip("\n"))
            if kind == "empty":
                st.n_empty += 1
            elif kind == "call":
                st.n_call += 1
            elif kind == "reflection_tag":
                st.n_reflection_tag += 1
            elif kind == "icc":
                st.n_icc += 1
            elif kind == "header":
                st.n_header += 1
            else:
                st.n_dropped += 1
                if len(st.dropped_examples) < max_drop_examples:
                    st.dropped_examples.append(line.rstrip("\n")[:160])
    return st


def iter_trace_files(extract_root: Path) -> Iterator[tuple[str, Path]]:
    """Yield (class_label, path) for *.apk.logcat under extract_root.

    class_label from path: 'benign' if 'benign' in path else 'malware' if 'malware' in path.
    Ignores year directory labels.
    """
    for p in sorted(extract_root.rglob("*.apk.logcat")):
        rel = str(p).lower()
        if "benign" in rel:
            yield "benign", p
        elif "malware" in rel:
            yield "malware", p


def sha256_from_filename(name: str) -> str | None:
    stem = Path(name).name
    if stem.endswith(".apk.logcat"):
        stem = stem[: -len(".apk.logcat")]
    if re.fullmatch(r"[a-fA-F0-9]{64}", stem):
        return stem.lower()
    return None
