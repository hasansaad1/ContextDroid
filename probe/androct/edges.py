"""Edge formation: reuse abrg.graph.update_graph with delta disabled (k only)."""

from __future__ import annotations

from abrg.corpus import build_session_graph
from abrg.config import K_BURST
from abrg.graph import ABRGGraph
from abrg.trace import TraceEvent


def build_k_only_graph(
    categories: list[str],
    *,
    package: str = "probe.androct",
    k_burst: int = K_BURST,
) -> ABRGGraph:
    """
    Existing edge logic with temporal condition disabled.

    Timestamps are unavailable in AndroCT. We do not invent inter-event deltas:
    every event gets timestamp_ms=0 and delta_sec=+inf so only k_burst sequence
    proximity applies (the δ check never rejects).
    """
    events = [
        TraceEvent(category=c, api="androct", timestamp_ms=0) for c in categories
    ]
    return build_session_graph(
        events,
        package,
        k_burst=k_burst,
        delta_sec=float("inf"),
    )


def edge_set(graph: ABRGGraph) -> set[tuple[str, str]]:
    return set(graph.edges.keys())


def build_full_edge_set(
    categories: list[str],
    timestamps_ms: list[int],
    *,
    package: str,
    k_burst: int = K_BURST,
    delta_sec: float,
) -> set[tuple[str, str]]:
    """Build edge keys with explicit delta (for Step 8 A/B)."""
    assert len(categories) == len(timestamps_ms)
    events = [
        TraceEvent(category=c, api="v2", timestamp_ms=t)
        for c, t in zip(categories, timestamps_ms)
    ]
    g = build_session_graph(events, package, k_burst=k_burst, delta_sec=delta_sec)
    return set(g.edges.keys())
