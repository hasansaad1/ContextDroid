"""Pure syntactic adapter: AndroCT callee signature -> categorize_callee inputs.

Does not invent categories. Unparseable or unmappable -> None.
"""

from __future__ import annotations

import re
from typing import Optional

from abrg.api_category_map import categorize_callee
from abrg.registry import GRAPH_CATEGORY_UNIVERSE

# AndroCT / Soot style: <pkg.Class: retType methodName(paramTypes)>
_SIG_RE = re.compile(
    r"^<(?P<cls>[^:]+):\s+(?P<ret>[^\s]+)\s+(?P<meth>[^(]+)\((?P<params>.*)\)>$"
)

GRAPH_SET = frozenset(GRAPH_CATEGORY_UNIVERSE)


def parse_androct_signature(sig: str) -> Optional[tuple[str, str]]:
    """Return (class_name_dotted, method_name) or None if not parseable."""
    s = sig.strip()
    m = _SIG_RE.match(s)
    if not m:
        return None
    cls = m.group("cls").strip()
    meth = m.group("meth").strip()
    if not cls or not meth:
        return None
    return cls, meth


def androct_callee_to_graph_category(callee_sig: str) -> Optional[str]:
    """
    Syntactic transform only: parse signature -> categorize_callee(class, method).

    Returns one GRAPH_CATEGORY_UNIVERSE category, or None if:
      - signature does not parse
      - categorize_callee returns empty
      - all returned categories are outside GRAPH_CATEGORY_UNIVERSE
    If multiple graph categories are returned, pick the lexicographically first
    (deterministic; no invented preference beyond sort).
    """
    parsed = parse_androct_signature(callee_sig)
    if parsed is None:
        return None
    cls, meth = parsed
    cats = categorize_callee(cls, meth)
    graph_cats = sorted(c for c in cats if c in GRAPH_SET)
    if not graph_cats:
        return None
    return graph_cats[0]


def class_prefix(callee_sig: str, depth: int = 3) -> str:
    """Dotted class prefix for unmapped frequency tables."""
    parsed = parse_androct_signature(callee_sig)
    if parsed is None:
        return "<unparseable>"
    parts = parsed[0].split(".")
    return ".".join(parts[:depth]) if parts else "<empty>"
