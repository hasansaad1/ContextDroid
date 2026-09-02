"""AndroCT trace line parsing (format assertions live in step3)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

# Non-ICC call: <caller> -> <callee>
_CALL_RE = re.compile(
    r"^<(?P<caller>.+?)>\s*->\s*<(?P<callee>.+?)>$"
)

# Timestamp-like tokens on a call line (must not appear)
_TS_HINT = re.compile(
    r"(?i)\b(timestamp|time_ms|relative_time|epoch|unix)\b|\d{10,13}"
)


@dataclass(frozen=True)
class CallLine:
    caller: str
    callee: str
    raw: str


@dataclass(frozen=True)
class IccValueLine:
    raw: str
    fields: tuple[str, ...]


def is_call_line(line: str) -> bool:
    return bool(_CALL_RE.match(line.strip()))


def parse_call_line(line: str) -> Optional[CallLine]:
    m = _CALL_RE.match(line.strip())
    if not m:
        return None
    return CallLine(caller=m.group("caller"), callee=m.group("callee"), raw=line.rstrip("\n"))


def call_line_has_timestamp_field(line: str) -> bool:
    """Heuristic: named timestamp fields or bare epoch-looking ints outside signatures."""
    # Signatures contain type names; strip the call form then check leftover.
    m = _CALL_RE.match(line.strip())
    if not m:
        return bool(re.search(r"(?i)timestamp", line))
    # Inside signatures, long digit runs can appear in synthetic names; require field names.
    return bool(re.search(r"(?i)\b(timestamp|time_ms|relative_time)\b", line))


def iter_trace_lines(path: Path) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            yield line.rstrip("\n")
