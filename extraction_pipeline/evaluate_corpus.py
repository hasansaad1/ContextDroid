#!/usr/bin/env python3
"""Evaluate benign dynamic trace corpus for behavioral-graph readiness."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import statistics
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# Hook category universe (hook_apis.js v3 — 25 categories)
CATEGORY_UNIVERSE: tuple[str, ...] = (
    "accounts",
    "audio",
    "camera",
    "clipboard",
    "content_access",
    "crypto",
    "database",
    "device_info",
    "dynamic_code_loading",
    "file_io",
    "ipc_intents",
    "lifecycle",
    "location",
    "media",
    "native_code",
    "navigation",
    "network",
    "notifications",
    "package_manager",
    "process",
    "reflection",
    "sms",
    "storage",
    "telephony",
    "webview",
)
LOW_SIGNAL = {"reflection", "lifecycle", "unknown"}
FRAMEWORK_ARTIFACT_APIS = {
    "hook_loaded",
    "Method.invoke",
}

# Graph design parameters under evaluation
K_BURST = 5
DELTA_SEC = 5.0
DELTA_MOTIF_SEC = 10.0
EMPTY_EVENT_THRESHOLD = 3

# Permission → expected behavioral categories (static boundary proxy)
PERM_TO_CATEGORIES: dict[str, set[str]] = {
    "INTERNET": {"network"},
    "ACCESS_NETWORK_STATE": {"network"},
    "CAMERA": {"camera"},
    "RECORD_AUDIO": {"audio"},
    "ACCESS_FINE_LOCATION": {"location"},
    "ACCESS_COARSE_LOCATION": {"location"},
    "ACCESS_BACKGROUND_LOCATION": {"location"},
    "READ_CONTACTS": {"content_access"},
    "WRITE_CONTACTS": {"content_access"},
    "READ_CALL_LOG": {"content_access"},
    "READ_SMS": {"sms", "content_access"},
    "SEND_SMS": {"sms"},
    "RECEIVE_SMS": {"sms"},
    "READ_CALENDAR": {"content_access"},
    "WRITE_CALENDAR": {"content_access"},
    "READ_EXTERNAL_STORAGE": {"file_io"},
    "WRITE_EXTERNAL_STORAGE": {"file_io"},
    "READ_MEDIA_IMAGES": {"file_io", "media"},
    "READ_MEDIA_VIDEO": {"file_io", "media"},
    "READ_MEDIA_AUDIO": {"file_io", "media"},
    "GET_ACCOUNTS": {"accounts"},
    "USE_CREDENTIALS": {"accounts"},
    "READ_PHONE_STATE": {"device_info"},
    "READ_PHONE_NUMBERS": {"device_info"},
    "POST_NOTIFICATIONS": {"notifications"},
    "BLUETOOTH": {"network"},
    "BLUETOOTH_CONNECT": {"network"},
    "NFC": {"network"},
    "FOREGROUND_SERVICE": {"lifecycle"},
}


def _dist(values: list[float]) -> dict[str, float]:
    if not values:
        return {"min": 0.0, "p25": 0.0, "median": 0.0, "p75": 0.0, "max": 0.0, "iqr": 0.0, "n": 0}
    vals = sorted(values)
    n = len(vals)
    q1 = statistics.quantiles(vals, n=4)[0] if n >= 4 else vals[0]
    q3 = statistics.quantiles(vals, n=4)[2] if n >= 4 else vals[-1]
    return {
        "min": vals[0],
        "p25": q1,
        "median": statistics.median(vals),
        "p75": q3,
        "max": vals[-1],
        "iqr": q3 - q1,
        "n": float(n),
    }


def _bottom_decile_packages(values_by_pkg: dict[str, float], higher_is_better: bool = True) -> list[str]:
    if not values_by_pkg:
        return []
    ranked = sorted(values_by_pkg.items(), key=lambda x: x[1], reverse=higher_is_better)
    k = max(1, math.ceil(len(ranked) * 0.1))
    return [pkg for pkg, _ in ranked[:k]]


def _read_csv_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            try:
                rt = int(float(row.get("relative_time") or 0))
            except ValueError:
                rt = 0
            rows.append(
                {
                    "relative_time_ms": rt,
                    "category": (row.get("category") or "").strip(),
                    "api": (row.get("api") or "").strip(),
                }
            )
    return rows


def _category_edges(categories: list[str]) -> set[tuple[str, str]]:
  out: set[tuple[str, str]] = set()
  for i in range(len(categories) - 1):
      a, b = categories[i], categories[i + 1]
      if a and b:
          out.add((a, b))
  return out


def _category_trigrams(categories: list[str]) -> set[tuple[str, str, str]]:
    if len(categories) < 3:
        return set()
    return {tuple(categories[i : i + 3]) for i in range(len(categories) - 2)}


def _edge_weights(categories: list[str]) -> dict[tuple[str, str], int]:
    weights: dict[tuple[str, str], int] = defaultdict(int)
    for i in range(len(categories) - 1):
        a, b = categories[i], categories[i + 1]
        if a and b:
            weights[(a, b)] += 1
    return dict(weights)


def _rank_dict(d: dict[Any, float]) -> dict[Any, float]:
    if not d:
        return {}
    items = sorted(d.items(), key=lambda x: (-x[1], str(x[0])))
    n = len(items)
    if n == 1:
        return {items[0][0]: 1.0}
    return {k: 1.0 - i / (n - 1) for i, (k, _) in enumerate(items)}


def _spearman(a: dict[Any, float], b: dict[Any, float]) -> float:
    keys = sorted(set(a) & set(b), key=str)
    if len(keys) < 2:
        return 1.0 if keys and a.get(keys[0], 0) == b.get(keys[0], 0) else 0.0
    ra = [_rank_dict({k: a[k] for k in keys})[k] for k in keys]
    rb = [_rank_dict({k: b[k] for k in keys})[k] for k in keys]
    mean_a = sum(ra) / len(ra)
    mean_b = sum(rb) / len(rb)
    num = sum((x - mean_a) * (y - mean_b) for x, y in zip(ra, rb))
    den_a = math.sqrt(sum((x - mean_a) ** 2 for x in ra))
    den_b = math.sqrt(sum((y - mean_b) ** 2 for y in rb))
    if den_a == 0 or den_b == 0:
        return 0.0
    return num / (den_a * den_b)


def _ged_edge_sets(a: set[tuple[str, str]], b: set[tuple[str, str]]) -> int:
    return len(a ^ b)


def _aapt_permissions(apk_path: Path) -> list[str]:
    try:
        out = subprocess.check_output(
            ["aapt", "dump", "permissions", str(apk_path)],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=20,
        )
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return []
    perms: list[str] = []
    for line in out.splitlines():
        m = re.search(r"permission:([^\s]+)", line)
        if m:
            perms.append(m.group(1).split(".")[-1].upper())
    return sorted(set(perms))


def _expected_categories_from_perms(perms: list[str]) -> set[str]:
    out: set[str] = set()
    for p in perms:
        out |= PERM_TO_CATEGORIES.get(p.upper(), set())
    return out


def _load_metadata(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _inter_event_stats(events: list[dict[str, Any]]) -> dict[str, float]:
    if len(events) < 2:
        return {"median_gap_ms": 0.0, "p90_gap_ms": 0.0, "pct_under_5s": 0.0, "pct_over_5s": 0.0}
    gaps = [
        max(0, events[i]["relative_time_ms"] - events[i - 1]["relative_time_ms"])
        for i in range(1, len(events))
    ]
    gaps_sorted = sorted(gaps)
    p90 = gaps_sorted[int(0.9 * (len(gaps_sorted) - 1))]
    under_5s = sum(1 for g in gaps if g <= DELTA_SEC * 1000) / len(gaps)
    return {
        "median_gap_ms": statistics.median(gaps),
        "p90_gap_ms": float(p90),
        "pct_under_5s": under_5s,
        "pct_over_5s": 1.0 - under_5s,
    }


def _burst_stats(events: list[dict[str, Any]]) -> dict[str, float]:
    if not events:
        return {"max_burst": 0.0, "pct_bursts_ge_k": 0.0}
    window_ms = DELTA_SEC * 1000
    max_burst = 1
    bursts_ge_k = 0
    for i in range(len(events)):
        t0 = events[i]["relative_time_ms"]
        count = 1
        for j in range(i + 1, len(events)):
            if events[j]["relative_time_ms"] - t0 <= window_ms:
                count += 1
            else:
                break
        max_burst = max(max_burst, count)
        if count >= K_BURST:
            bursts_ge_k += 1
    return {
        "max_burst": float(max_burst),
        "pct_bursts_ge_k": bursts_ge_k / len(events),
    }


def _motif_completion_within_delta(events: list[dict[str, Any]]) -> float:
    """Fraction of category trigrams whose span fits within δ_motif."""
    if len(events) < 3:
        return 0.0
    ok = 0
    total = 0
    for i in range(len(events) - 2):
        span = events[i + 2]["relative_time_ms"] - events[i]["relative_time_ms"]
        total += 1
        if span <= DELTA_MOTIF_SEC * 1000:
            ok += 1
    return ok / total if total else 0.0


def _within_session_growth_curve(categories: list[str]) -> tuple[list[int], list[int], list[int]]:
    """Return cumulative event indices vs new edges and new motifs discovered."""
    edges_seen: set[tuple[str, str]] = set()
    motifs_seen: set[tuple[str, str, str]] = set()
    x: list[int] = []
    edge_counts: list[int] = []
    motif_counts: list[int] = []
    for i, _ in enumerate(categories, start=1):
        prefix = categories[:i]
        edges_seen |= _category_edges(prefix)
        motifs_seen |= _category_trigrams(prefix)
        x.append(i)
        edge_counts.append(len(edges_seen))
        motif_counts.append(len(motifs_seen))
    return x, edge_counts, motif_counts


def _stabilization_index(edge_counts: list[int], tol: float = 0.05) -> int | None:
    if len(edge_counts) < 10:
        return None
    final = edge_counts[-1]
    if final == 0:
        return None
    for i in range(len(edge_counts) - 1, 8, -1):
        window = edge_counts[max(0, i - 10) : i + 1]
        if max(window) - min(window) <= max(1, tol * final):
            return i + 1
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--corpus-name", default="bulk_llm_benign_v6")
    args = parser.parse_args()

    index_path = Path(args.index)
    rows: list[dict[str, str]] = []
    with index_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    success_rows = [r for r in rows if (r.get("status") or "") == "success"]
    session_records: list[dict[str, Any]] = []

    for row in rows:
        meta = _load_metadata(Path((row.get("metadata_path") or "").strip()))
        csv_path = Path((row.get("frida_csv_path") or "").strip())
        quality_path = Path((row.get("frida_quality_path") or "").strip())
        events = _read_csv_events(csv_path)
        meaningful = [e for e in events if e["category"] not in LOW_SIGNAL]
        categories_all = [e["category"] for e in events if e["category"]]
        categories_meaningful = [e["category"] for e in meaningful]
        duration_sec = float(row.get("duration_sec") or meta.get("duration_sec") or 0)
        elapsed_sec = float(meta.get("elapsed_sec") or duration_sec)
        hook_rate = len(events) / elapsed_sec if elapsed_sec > 0 else 0.0
        quality = {}
        if quality_path.exists():
            try:
                quality = json.loads(quality_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                quality = {}

        apk_path = Path(meta.get("apk_path") or "")
        perms = _aapt_permissions(apk_path) if apk_path.exists() else []
        expected_cats = _expected_categories_from_perms(perms)
        dynamic_cats = set(categories_meaningful)
        declared_hit = len(dynamic_cats & expected_cats) / len(dynamic_cats) if dynamic_cats else 0.0
        undeclared_active = dynamic_cats - expected_cats
        never_exercised = expected_cats - dynamic_cats

        framework_events = sum(1 for e in events if e["api"] in FRAMEWORK_ARTIFACT_APIS)
        inter = _inter_event_stats(meaningful)
        burst = _burst_stats(meaningful)
        motif_complete = _motif_completion_within_delta(meaningful)
        _, edge_curve, motif_curve = _within_session_growth_curve(categories_meaningful)
        stab_idx = _stabilization_index(edge_curve)

        session_records.append(
            {
                "package_name": row.get("package_name", ""),
                "sample_id": row.get("sample_id", ""),
                "status": row.get("status", ""),
                "data_quality_status": row.get("data_quality_status") or meta.get("data_quality_status", ""),
                "llm_simulation_status": row.get("llm_simulation_status") or meta.get("llm_simulation_status", ""),
                "metadata_source": row.get("metadata_source") or meta.get("metadata_source", ""),
                "app_category": (meta.get("app_context") or {}).get("category", "Unknown"),
                "events_total": len(events),
                "events_meaningful": len(meaningful),
                "distinct_categories": len(set(categories_all)),
                "distinct_meaningful_categories": len(set(categories_meaningful)),
                "universe_fraction": len(set(categories_meaningful)) / len(CATEGORY_UNIVERSE),
                "hook_rate_per_sec": hook_rate,
                "is_empty": len(events) < EMPTY_EVENT_THRESHOLD,
                "framework_event_fraction": framework_events / len(events) if events else 0.0,
                "edge_count": len(_category_edges(categories_meaningful)),
                "motif_count": len(_category_trigrams(categories_meaningful)),
                "edge_curve": edge_curve,
                "motif_curve": motif_curve,
                "stabilization_event_index": stab_idx,
                "inter_event_median_ms": inter["median_gap_ms"],
                "inter_event_p90_ms": inter["p90_gap_ms"],
                "pct_gaps_under_5s": inter["pct_under_5s"],
                "max_burst_in_5s": burst["max_burst"],
                "pct_positions_burst_ge_k": burst["pct_bursts_ge_k"],
                "motif_complete_fraction": motif_complete,
                "session_duration_sec": elapsed_sec,
                "declared_perm_count": len(perms),
                "expected_category_count": len(expected_cats),
                "dynamic_declared_overlap": declared_hit,
                "undeclared_active_categories": sorted(undeclared_active),
                "never_exercised_declared_categories": sorted(never_exercised),
                "llm_actions_count": int(meta.get("llm_actions_count") or 0),
                "webview_dominant": bool(meta.get("webview_dominant")),
                "analysis_exit_code": int(meta.get("analysis_exit_code") or -1),
            }
        )

    success_recs = [r for r in session_records if r["status"] == "success"]
    good_recs = [r for r in success_recs if r["data_quality_status"] == "good"]

    # Corpus-wide category activation
    corpus_categories: set[str] = set()
    for r in success_recs:
        corpus_categories |= set()  # placeholder
    for row in success_rows:
        csv_path = Path((row.get("frida_csv_path") or "").strip())
        for e in _read_csv_events(csv_path):
            if e["category"] not in LOW_SIGNAL:
                corpus_categories.add(e["category"])

    per_app_categories: dict[str, set[str]] = defaultdict(set)
    for row in success_rows:
        pkg = row.get("package_name", "")
        for e in _read_csv_events(Path((row.get("frida_csv_path") or "").strip())):
            if e["category"] not in LOW_SIGNAL:
                per_app_categories[pkg].add(e["category"])

    # Aspect 1 distributions
    def sess_metric(key: str, subset: list[dict[str, Any]] | None = None) -> dict[str, float]:
        data = subset if subset is not None else session_records
        return _dist([float(r[key]) for r in data])

    app_universe_fracs = {
        pkg: len(cats) / len(CATEGORY_UNIVERSE) for pkg, cats in per_app_categories.items()
    }

    # Aspect 2: within-session pseudo-convergence (only 1 session/app in this corpus)
    growth_slopes: list[float] = []
    never_stabilize: list[str] = []
    for r in success_recs:
        curve = r["edge_curve"]
        if len(curve) < 5:
            never_stabilize.append(r["package_name"])
            continue
        # slope of last 25% of curve
        tail_start = int(len(curve) * 0.75)
        tail = curve[tail_start:]
        if len(tail) >= 2:
            growth_slopes.append((tail[-1] - tail[0]) / max(1, len(tail) - 1))
        if r["stabilization_event_index"] is None:
            never_stabilize.append(r["package_name"])

    # Aspect 3: cross-session — unavailable for single-session corpus; check duplicates
    by_pkg_sessions: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in session_records:
        if r["status"] == "success":
            by_pkg_sessions[r["package_name"]].append(r)

    pairwise_jaccard: list[float] = []
    pairwise_ged: list[float] = []
    pairwise_spearman: list[float] = []
    high_variance_apps: list[str] = []
    multi_session_pkgs = [p for p, xs in by_pkg_sessions.items() if len(xs) > 1]

    for pkg, xs in by_pkg_sessions.items():
        if len(xs) < 2:
            continue
        # load edge weights per session from csv paths via stored metrics only — re-read
        pass

    # Re-read for multi-session pairs (if any)
    pkg_csvs: dict[str, list[list[dict[str, Any]]]] = defaultdict(list)
    for row in success_rows:
        pkg = row.get("package_name", "")
        pkg_csvs[pkg].append(_read_csv_events(Path((row.get("frida_csv_path") or "").strip())))

    for pkg, ev_lists in pkg_csvs.items():
        if len(ev_lists) < 2:
            continue
        for i in range(len(ev_lists)):
            for j in range(i + 1, len(ev_lists)):
                c1 = [e["category"] for e in ev_lists[i] if e["category"] not in LOW_SIGNAL]
                c2 = [e["category"] for e in ev_lists[j] if e["category"] not in LOW_SIGNAL]
                e1 = _category_edges(c1)
                e2 = _category_edges(c2)
                pairwise_jaccard.append(len(e1 & e2) / len(e1 | e2) if (e1 or e2) else 1.0)
                pairwise_ged.append(float(_ged_edge_sets(e1, e2)))
                w1 = _edge_weights(c1)
                w2 = _edge_weights(c2)
                keys = set(w1) | set(w2)
                pairwise_spearman.append(_spearman({k: float(w1.get(k, 0)) for k in keys}, {k: float(w2.get(k, 0)) for k in keys}))

    # Aspect 6 composition
    source_counts = Counter(r["metadata_source"] for r in success_recs)
    app_cat_counts = Counter(r["app_category"] for r in success_recs)
    network_apps = 0
    offline_apps = 0
    for row in success_rows:
        meta = _load_metadata(Path((row.get("metadata_path") or "").strip()))
        apk_path = Path(meta.get("apk_path") or "")
        perms = _aapt_permissions(apk_path) if apk_path.exists() else []
        if "INTERNET" in perms:
            network_apps += 1
        else:
            offline_apps += 1

    # version counts from apk filenames in benign dir
    benign_dir = Path("data/apks/benign")
    pkg_versions: Counter[str] = Counter()
    if benign_dir.exists():
        for apk in benign_dir.glob("*.apk"):
            m = re.match(r"(.+)_\d+\.apk$", apk.name)
            if m:
                pkg_versions[m.group(1)] += 1

    pkgs_with_multi_version = sum(1 for c in pkg_versions.values() if c >= 2)

    # Aspect 7 pipeline integrity
    failed_rows = [r for r in rows if r.get("status") != "success"]
    crash_rate = len(failed_rows) / len(rows) if rows else 0.0
    sim_status_counts = Counter(r.get("llm_simulation_status", "unknown") for r in rows)
    dq_counts = Counter(r.get("data_quality_status", "unknown") for r in rows)

    # Flag unsuitable apps
    flagged: list[dict[str, str]] = []
    for r in success_recs:
        reasons: list[str] = []
        if r["is_empty"]:
            reasons.append("empty_trace")
        if r["events_meaningful"] < 10:
            reasons.append("low_meaningful_events")
        if r["distinct_meaningful_categories"] < 2:
            reasons.append("single_category")
        if r["data_quality_status"] != "good":
            reasons.append(r["data_quality_status"])
        if str(r["llm_simulation_status"]).startswith("failed"):
            reasons.append(r["llm_simulation_status"])
        if r["framework_event_fraction"] > 0.5:
            reasons.append("framework_dominated")
        if reasons:
            flagged.append({"package": r["package_name"], "reasons": ";".join(reasons)})

    report = {
        "corpus": args.corpus_name,
        "index_rows": len(rows),
        "success_sessions": len(success_recs),
        "good_quality_sessions": len(good_recs),
        "category_universe_size": len(CATEGORY_UNIVERSE),
        "corpus_categories_activated": sorted(corpus_categories),
        "corpus_universe_fraction": len(corpus_categories) / len(CATEGORY_UNIVERSE),
        "aspect1_trace_richness": {
            "events_per_session": sess_metric("events_total", success_recs),
            "meaningful_events_per_session": sess_metric("events_meaningful", success_recs),
            "distinct_categories_per_session": sess_metric("distinct_meaningful_categories", success_recs),
            "universe_fraction_per_app": _dist(list(app_universe_fracs.values())),
            "hook_rate_per_sec": sess_metric("hook_rate_per_sec", success_recs),
            "empty_session_fraction": sum(1 for r in success_recs if r["is_empty"]) / max(1, len(success_recs)),
            "bottom_decile_events": _bottom_decile_packages({r["package_name"]: float(r["events_meaningful"]) for r in success_recs}),
            "bottom_decile_categories": _bottom_decile_packages(
                {r["package_name"]: float(r["distinct_meaningful_categories"]) for r in success_recs}
            ),
        },
        "aspect2_per_app_coverage": {
            "note": "Corpus has 1 session/app; convergence measured within-session by cumulative event index.",
            "tail_edge_growth_slope": _dist(growth_slopes),
            "never_stabilize_count": len(never_stabilize),
            "never_stabilize_packages": never_stabilize[:20],
            "median_stabilization_event_index": _dist(
                [float(r["stabilization_event_index"]) for r in success_recs if r["stabilization_event_index"]]
            ),
            "bottom_decile_motifs": _bottom_decile_packages({r["package_name"]: float(r["motif_count"]) for r in success_recs}),
        },
        "aspect3_cross_session_consistency": {
            "multi_session_packages": multi_session_pkgs,
            "pairwise_edge_jaccard": _dist(pairwise_jaccard),
            "pairwise_graph_edit_distance": _dist(pairwise_ged),
            "pairwise_w_cum_spearman": _dist(pairwise_spearman),
            "note": "No same-app multi-session pairs in this corpus; metrics empty unless SESSIONS_PER_APP>1.",
        },
        "aspect4_temporal_structure": {
            "inter_event_median_ms": sess_metric("inter_event_median_ms", success_recs),
            "inter_event_p90_ms": sess_metric("inter_event_p90_ms", success_recs),
            "pct_inter_event_gaps_under_5s": sess_metric("pct_gaps_under_5s", success_recs),
            "max_burst_within_5s": sess_metric("max_burst_in_5s", success_recs),
            "pct_event_positions_in_burst_ge_k": sess_metric("pct_positions_burst_ge_k", success_recs),
            "motif_completion_within_10s_fraction": sess_metric("motif_complete_fraction", success_recs),
            "session_duration_sec": sess_metric("session_duration_sec", success_recs),
        },
        "aspect5_static_dynamic_alignment": {
            "dynamic_declared_overlap_fraction": sess_metric("dynamic_declared_overlap", success_recs),
            "never_exercised_declared_categories_median_count": _dist(
                [float(len(r["never_exercised_declared_categories"])) for r in success_recs]
            ),
            "note": "Static proxy = aapt permissions mapped to categories; no Androguard component graph in corpus.",
        },
        "aspect6_corpus_composition": {
            "metadata_source_counts": dict(source_counts),
            "app_category_counts": dict(app_cat_counts),
            "network_dependent_apps": network_apps,
            "offline_apps": offline_apps,
            "offline_fraction": offline_apps / max(1, network_apps + offline_apps),
            "benign_apk_packages_with_ge_2_versions": pkgs_with_multi_version,
            "total_benign_apk_files": sum(pkg_versions.values()) if pkg_versions else 0,
        },
        "aspect7_pipeline_integrity": {
            "analyze_failure_rate": crash_rate,
            "failed_count": len(failed_rows),
            "llm_simulation_status_counts": dict(sim_status_counts),
            "data_quality_status_counts": dict(dq_counts),
            "framework_artifact_fraction": sess_metric("framework_event_fraction", success_recs),
            "human_ux_success_count": sum(1 for r in success_recs if r["llm_simulation_status"] == "success"),
        },
        "flagged_unsuitable": flagged,
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
