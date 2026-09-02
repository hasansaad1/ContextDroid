#!/usr/bin/env python3
"""Step 8 — v2 corpus: delta-retention rate + edge-set symmetric difference (k-only vs k+δ)."""

from __future__ import annotations

import csv
import json
import statistics
import sys
from collections import Counter
from pathlib import Path

import paths  # noqa: F401 — inserts ABGA into sys.path
from paths import OUT_DIR, V2_SESSIONS

from abrg.config import DELTA_SEC, K_BURST
from abrg.dataset_paths import find_frida_trace
from abrg.trace import load_frida_trace

from edges import build_full_edge_set


def _dist(vals: list[float]) -> dict:
    if not vals:
        return {"n": 0, "min": None, "p25": None, "median": None, "p75": None, "max": None}
    s = sorted(vals)
    n = len(s)
    q = statistics.quantiles(s, n=4) if n >= 4 else [s[0], statistics.median(s), s[-1]]
    return {
        "n": n,
        "min": s[0],
        "p25": q[0] if n >= 4 else s[0],
        "median": statistics.median(s),
        "p75": q[2] if n >= 4 else s[-1],
        "max": s[-1],
    }


def candidate_pairs(categories: list[str], timestamps_ms: list[int], k: int = K_BURST):
    """All (i,j) with 1 <= j-i <= k and categories[i] != categories[j]."""
    n = len(categories)
    for i in range(n):
        for j in range(i + 1, min(i + k + 1, n)):
            if categories[i] == categories[j]:
                continue
            yield i, j, timestamps_ms[i], timestamps_ms[j]


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if not V2_SESSIONS.is_dir():
        print(f"FAIL: v2 sessions missing: {V2_SESSIONS}", file=sys.stderr)
        return 1

    session_dirs = sorted(p for p in V2_SESSIONS.iterdir() if p.is_dir())
    per_session_rows: list[dict] = []
    overall_candidates = 0
    overall_retained = 0
    agg_only_k: Counter[tuple[str, str]] = Counter()
    agg_only_kd: Counter[tuple[str, str]] = Counter()
    agg_both = 0
    total_sym_diff = 0

    event_counts: list[int] = []

    for sd in session_dirs:
        try:
            trace = find_frida_trace(sd)
        except FileNotFoundError:
            continue
        events, _rep = load_frida_trace(trace)
        if not events:
            continue
        cats = [e.category for e in events]
        ts = [e.timestamp_ms for e in events]
        n_ev = len(cats)
        event_counts.append(n_ev)

        cand = 0
        retained = 0
        for i, j, t_i, t_j in candidate_pairs(cats, ts):
            cand += 1
            if (t_j - t_i) / 1000.0 <= DELTA_SEC:
                retained += 1
        overall_candidates += cand
        overall_retained += retained
        rate = (retained / cand) if cand else None

        edges_kd = build_full_edge_set(cats, ts, package=sd.name, delta_sec=DELTA_SEC)
        edges_k = build_full_edge_set(cats, ts, package=sd.name, delta_sec=float("inf"))
        only_k = edges_k - edges_kd
        only_kd = edges_kd - edges_k  # should be empty
        both = edges_k & edges_kd
        sym = only_k | only_kd
        total_sym_diff += len(sym)
        agg_both += len(both)
        for e in only_k:
            agg_only_k[e] += 1
        for e in only_kd:
            agg_only_kd[e] += 1

        per_session_rows.append(
            {
                "session": sd.name,
                "n_events": n_ev,
                "k_candidates": cand,
                "delta_retained": retained,
                "delta_retention_rate": rate,
                "edges_k_delta": len(edges_kd),
                "edges_k_only": len(edges_k),
                "sym_diff_count": len(sym),
                "only_in_k_disabled": len(only_k),
                "only_in_k_delta": len(only_kd),
            }
        )

    # Quartile split by session event count
    quartile_rates: dict[str, dict] = {}
    if event_counts:
        qs = statistics.quantiles(event_counts, n=4) if len(event_counts) >= 4 else None
        buckets: dict[str, list[dict]] = {"Q1": [], "Q2": [], "Q3": [], "Q4": []}
        for row in per_session_rows:
            n = row["n_events"]
            if qs is None:
                buckets["Q1"].append(row)
                continue
            if n <= qs[0]:
                buckets["Q1"].append(row)
            elif n <= qs[1]:
                buckets["Q2"].append(row)
            elif n <= qs[2]:
                buckets["Q3"].append(row)
            else:
                buckets["Q4"].append(row)
        for qname, rows in buckets.items():
            c = sum(r["k_candidates"] for r in rows)
            r = sum(r["delta_retained"] for r in rows)
            quartile_rates[qname] = {
                "n_sessions": len(rows),
                "event_count_bounds": {
                    "min": min((x["n_events"] for x in rows), default=None),
                    "max": max((x["n_events"] for x in rows), default=None),
                },
                "k_candidates": c,
                "delta_retained": r,
                "delta_retention_rate": (r / c) if c else None,
            }

    summary = {
        "k_burst": K_BURST,
        "delta_sec": DELTA_SEC,
        "n_sessions": len(per_session_rows),
        "overall": {
            "k_candidates": overall_candidates,
            "delta_retained": overall_retained,
            "delta_retention_rate": (
                overall_retained / overall_candidates if overall_candidates else None
            ),
        },
        "by_event_count_quartile": quartile_rates,
        "edge_symmetric_difference": {
            "aggregate_sym_diff_edge_instances_sum_over_sessions": total_sym_diff,
            "aggregate_intersection_edge_count_sum": agg_both,
            "unique_edges_only_in_k_disabled": {
                f"{u}->{v}": c for (u, v), c in agg_only_k.most_common()
            },
            "unique_edges_only_in_k_delta": {
                f"{u}->{v}": c for (u, v), c in agg_only_kd.most_common()
            },
            "n_unique_only_k": len(agg_only_k),
            "n_unique_only_kd": len(agg_only_kd),
        },
        "per_session_sym_diff_dist": _dist(
            [float(r["sym_diff_count"]) for r in per_session_rows]
        ),
    }

    (OUT_DIR / "step8_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (OUT_DIR / "step8_per_session.csv").open("w", newline="", encoding="utf-8") as fh:
        if per_session_rows:
            w = csv.DictWriter(fh, fieldnames=list(per_session_rows[0].keys()))
            w.writeheader()
            w.writerows(per_session_rows)

    print(json.dumps(summary["overall"], indent=2))
    print("wrote", OUT_DIR / "step8_summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
