#!/usr/bin/env python3
"""Step 3.5d — Step 8 denominator + continuous δ-retention vs event count."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import paths  # noqa: F401
from paths import OUT_DIR, V2_SESSIONS
from edges import build_full_edge_set

from abrg.config import DELTA_SEC, K_BURST
from abrg.dataset_paths import find_frida_trace
from abrg.trace import load_frida_trace


def candidate_pairs(categories: list[str], timestamps_ms: list[int], k: int = K_BURST):
    n = len(categories)
    for i in range(n):
        for j in range(i + 1, min(i + k + 1, n)):
            if categories[i] == categories[j]:
                continue
            yield i, j, timestamps_ms[i], timestamps_ms[j]


def fit_log_retention(xs: list[float], ys: list[float]) -> dict:
    """Fit y ≈ a + b*ln(x) for x>0 via least squares. Return coeffs + predictions."""
    pts = [(x, y) for x, y in zip(xs, ys) if x > 0 and y is not None]
    if len(pts) < 3:
        return {"model": "a+b*ln(x)", "n": len(pts), "a": None, "b": None, "r2": None}
    lx = [math.log(x) for x, _ in pts]
    yy = [y for _, y in pts]
    n = len(pts)
    mean_lx = sum(lx) / n
    mean_y = sum(yy) / n
    var_x = sum((x - mean_lx) ** 2 for x in lx)
    if var_x == 0:
        return {"model": "a+b*ln(x)", "n": n, "a": mean_y, "b": 0.0, "r2": None}
    cov = sum((x - mean_lx) * (y - mean_y) for x, y in zip(lx, yy))
    b = cov / var_x
    a = mean_y - b * mean_lx
    pred = [a + b * x for x in lx]
    ss_res = sum((y - p) ** 2 for y, p in zip(yy, pred))
    ss_tot = sum((y - mean_y) ** 2 for y in yy)
    r2 = 1.0 - ss_res / ss_tot if ss_tot else None
    return {"model": "a + b * ln(n_events)", "n": n, "a": a, "b": b, "r2": r2}


def predict(fit: dict, n_events: float) -> float | None:
    if fit.get("a") is None or n_events <= 0:
        return None
    return fit["a"] + fit["b"] * math.log(n_events)


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    session_dirs = sorted(p for p in V2_SESSIONS.iterdir() if p.is_dir())

    per_session: list[dict] = []
    overall_cand = 0
    overall_ret = 0
    total_edges_k_delta = 0
    total_edges_k_only = 0
    total_sym_diff = 0
    total_intersection = 0

    scatter: list[dict] = []

    for sd in session_dirs:
        try:
            trace = find_frida_trace(sd)
        except FileNotFoundError:
            continue
        events, _ = load_frida_trace(trace)
        if not events:
            continue
        cats = [e.category for e in events]
        ts = [e.timestamp_ms for e in events]
        n_ev = len(cats)

        cand = ret = 0
        for i, j, t_i, t_j in candidate_pairs(cats, ts):
            cand += 1
            if (t_j - t_i) / 1000.0 <= DELTA_SEC:
                ret += 1
        overall_cand += cand
        overall_ret += ret
        rate = (ret / cand) if cand else None

        edges_kd = build_full_edge_set(cats, ts, package=sd.name, delta_sec=DELTA_SEC)
        edges_k = build_full_edge_set(cats, ts, package=sd.name, delta_sec=float("inf"))
        only_k = edges_k - edges_kd
        only_kd = edges_kd - edges_k
        both = edges_k & edges_kd
        sym = only_k | only_kd

        total_edges_k_delta += len(edges_kd)
        total_edges_k_only += len(edges_k)
        total_sym_diff += len(sym)
        total_intersection += len(both)

        row = {
            "session": sd.name,
            "n_events": n_ev,
            "k_candidates": cand,
            "delta_retained": ret,
            "delta_retention_rate": rate,
            "edges_k_delta": len(edges_kd),
            "edges_k_only": len(edges_k),
            "sym_diff_count": len(sym),
            "intersection_count": len(both),
        }
        per_session.append(row)
        if rate is not None:
            scatter.append({"n_events": n_ev, "delta_retention_rate": rate, "k_candidates": cand})

    xs = [float(s["n_events"]) for s in scatter]
    ys = [float(s["delta_retention_rate"]) for s in scatter]
    fit = fit_log_retention(xs, ys)
    def clip01(v: float | None) -> float | None:
        if v is None:
            return None
        return float(min(1.0, max(0.0, v)))

    preds_raw = {
        "at_5k": predict(fit, 5000),
        "at_10k": predict(fit, 10000),
        "at_50k": predict(fit, 50000),
    }
    preds = {k: clip01(v) for k, v in preds_raw.items()}
    preds_raw_key = {f"{k}_unclipped": v for k, v in preds_raw.items()}

    # Also fit weighted by k_candidates (session-level rates weighted)
    # and a pooled bin curve
    bins = []
    if scatter:
        # decile bins by n_events
        ordered = sorted(scatter, key=lambda s: s["n_events"])
        n = len(ordered)
        for bi in range(10):
            lo = int(bi * n / 10)
            hi = int((bi + 1) * n / 10)
            chunk = ordered[lo:hi]
            if not chunk:
                continue
            c = sum(s["k_candidates"] for s in chunk)
            # need raw retained — approximate from rate*cand
            rsum = sum(s["delta_retention_rate"] * s["k_candidates"] for s in chunk)
            bins.append(
                {
                    "bin": bi + 1,
                    "n_sessions": len(chunk),
                    "n_events_min": chunk[0]["n_events"],
                    "n_events_max": chunk[-1]["n_events"],
                    "n_events_median": ordered[lo + (hi - lo) // 2]["n_events"] if hi > lo else chunk[0]["n_events"],
                    "k_candidates": c,
                    "delta_retention_rate_pooled": (rsum / c) if c else None,
                }
            )

    summary = {
        "k_burst": K_BURST,
        "delta_sec": DELTA_SEC,
        "n_sessions": len(per_session),
        "edge_instance_totals": {
            "total_edge_instances_k_and_delta": total_edges_k_delta,
            "total_edge_instances_k_only": total_edges_k_only,
            "aggregate_sym_diff_edge_instances": total_sym_diff,
            "aggregate_intersection_edge_instances": total_intersection,
            "sym_diff_fraction_of_k_delta": (
                total_sym_diff / total_edges_k_delta if total_edges_k_delta else None
            ),
            "sym_diff_fraction_of_k_only": (
                total_sym_diff / total_edges_k_only if total_edges_k_only else None
            ),
            "note": (
                "edge-instance = one directed category edge key counted once per session graph; "
                "summed across sessions (same as Step 8 aggregate)."
            ),
        },
        "overall_delta_retention": {
            "k_candidates": overall_cand,
            "delta_retained": overall_ret,
            "delta_retention_rate": (overall_ret / overall_cand) if overall_cand else None,
        },
        "log_fit": fit,
        "fitted_retention_clipped_0_1": preds,
        "fitted_retention_unclipped": preds_raw,
        "decile_bins_by_n_events": bins,
        "scatter_n_points": len(scatter),
    }
    (OUT_DIR / "step3_5d_delta_continuous.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    (OUT_DIR / "step3_5d_scatter.json").write_text(
        json.dumps(scatter, indent=2) + "\n", encoding="utf-8"
    )

    # Simple SVG scatter + fitted curve for the report
    if scatter and fit.get("a") is not None:
        w, h = 720, 420
        pad = 50
        xmax = max(s["n_events"] for s in scatter)
        xmin = min(s["n_events"] for s in scatter)
        # log x scale
        def xmap(n_ev: float) -> float:
            if n_ev <= 0:
                return pad
            return pad + (math.log(n_ev) - math.log(max(xmin, 1))) / (
                math.log(max(xmax, 2)) - math.log(max(xmin, 1)) + 1e-12
            ) * (w - 2 * pad)

        def ymap(r: float) -> float:
            return h - pad - r * (h - 2 * pad)

        pts = "\n".join(
            f'<circle cx="{xmap(s["n_events"]):.2f}" cy="{ymap(s["delta_retention_rate"]):.2f}" r="2.5" fill="#333"/>'
            for s in scatter
        )
        curve_xs = [
            math.exp(
                math.log(max(xmin, 1))
                + t * (math.log(max(xmax, 2)) - math.log(max(xmin, 1)))
            )
            for t in [i / 40 for i in range(41)]
        ]
        curve = " ".join(
            f"{xmap(x):.2f},{ymap(min(1.0, max(0.0, predict(fit, x) or 0))):.2f}" for x in curve_xs
        )
        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}">
  <rect width="100%" height="100%" fill="white"/>
  <text x="{w/2}" y="24" text-anchor="middle" font-size="14">δ-retention vs session event count (log x)</text>
  <line x1="{pad}" y1="{h-pad}" x2="{w-pad}" y2="{h-pad}" stroke="#000"/>
  <line x1="{pad}" y1="{pad}" x2="{pad}" y2="{h-pad}" stroke="#000"/>
  <polyline fill="none" stroke="#c00" stroke-width="2" points="{curve}"/>
  {pts}
  <text x="{pad}" y="{h-15}" font-size="11">n_events (log)</text>
  <text x="12" y="{pad}" font-size="11" transform="rotate(-90 12,{pad})">δ-retention</text>
</svg>
"""
        (OUT_DIR / "step3_5d_scatter.svg").write_text(svg, encoding="utf-8")

    print(json.dumps(summary["edge_instance_totals"], indent=2))
    print("fitted", preds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
