#!/usr/bin/env python3
"""Steps 3–7: format verify, map, graphs, confound, AndroZoo linkage."""

from __future__ import annotations

import csv
import json
import math
import random
import re
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional

import paths  # noqa: F401
from paths import EXTRACT_DIR, OUT_DIR

from abrg.registry import GRAPH_CATEGORY_UNIVERSE
from adapter import androct_callee_to_graph_category, class_prefix, parse_androct_signature
from edges import build_k_only_graph
from trace_parse import call_line_has_timestamp_field, is_call_line, parse_call_line

RNG = random.Random(20260806)

# AndroCT signature interior must look fully qualified
_CALLEE_INTERIOR = re.compile(
    r"^[A-Za-z0-9_$.]+(\.[A-Za-z0-9_$.]+)*:\s+\S+\s+[A-Za-z0-9_<>$]+\([^)]*\)$"
)


def _percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return float("nan")
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    k = (len(sorted_vals) - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(sorted_vals[int(k)])
    return float(sorted_vals[f] * (c - k) + sorted_vals[c] * (k - f))


def dist(vals: list[float]) -> dict[str, Any]:
    if not vals:
        return {"n": 0, "min": None, "p25": None, "median": None, "p75": None, "max": None}
    s = sorted(vals)
    return {
        "n": len(s),
        "min": s[0],
        "p25": _percentile(s, 0.25),
        "median": statistics.median(s),
        "p75": _percentile(s, 0.75),
        "max": s[-1],
    }


def find_class_files(cls: str) -> list[Path]:
    """Locate per-app *.apk.logcat files for benign|malware under EXTRACT_DIR."""
    if not EXTRACT_DIR.is_dir():
        return []
    files: list[Path] = []
    for p in EXTRACT_DIR.rglob("*.apk.logcat"):
        rel = str(p.relative_to(EXTRACT_DIR)).lower()
        if cls == "benign" and "benign" in rel:
            files.append(p)
        elif cls == "malware" and "malware" in rel:
            files.append(p)
    return sorted(set(files))


def is_logcat_header(line: str) -> bool:
    s = line.strip()
    return s.startswith("--------- beginning of")


def is_icc_block_line(line: str) -> bool:
    s = line.strip()
    if s == "[ Intent sent ]":
        return True
    if s.startswith("caller=") or s.startswith("callsite="):
        return True
    # tab-indented Intent fields
    if line.startswith("\t") and "=" in s:
        return True
    return False


def classify_line(line: str) -> str:
    """call | icc | header | empty | other."""
    s = line.strip()
    if not s:
        return "empty"
    if is_logcat_header(s):
        return "header"
    if is_call_line(s):
        return "call"
    if is_icc_block_line(line):
        return "icc"
    return "other"


def step3_format_verify(benign_files: list[Path], malware_files: list[Path]) -> dict:
    report: dict[str, Any] = {"ok": True, "errors": [], "per_class": {}}
    for cls, files in (("benign", benign_files), ("malware", malware_files)):
        if len(files) < 20:
            report["ok"] = False
            report["errors"].append(f"{cls}: need >=20 files, got {len(files)}")
            continue
        sample = RNG.sample(files, 20)
        line_counts: list[int] = []
        examples: list[str] = []
        icc_examples: list[str] = []
        header_examples: list[str] = []
        other_examples: list[str] = []
        n_call = 0
        n_icc = 0
        n_header = 0
        n_other = 0
        n_ts_fail = 0
        n_callee_fail = 0

        for path in sample:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            line_counts.append(len(lines))
            for i, line in enumerate(lines):
                kind = classify_line(line)
                if kind == "empty":
                    continue
                if kind == "header":
                    n_header += 1
                    if len(header_examples) < 6:
                        header_examples.append(line.strip())
                    continue
                if kind == "icc":
                    n_icc += 1
                    if len(icc_examples) < 15:
                        icc_examples.append(repr(line))
                    continue
                if kind == "call":
                    n_call += 1
                    cl = parse_call_line(line)
                    assert cl is not None
                    if call_line_has_timestamp_field(line):
                        n_ts_fail += 1
                        report["ok"] = False
                        report["errors"].append(
                            f"timestamp field on call line: {path.name}: {line[:200]}"
                        )
                    if not _CALLEE_INTERIOR.match(cl.callee):
                        n_callee_fail += 1
                        report["ok"] = False
                        report["errors"].append(
                            f"callee not fully-qualified form: {path.name}: <{cl.callee[:180]}>"
                        )
                    if len(examples) < 5:
                        examples.append(line)
                    continue
                # other — fail closed
                n_other += 1
                if len(other_examples) < 10:
                    other_examples.append(f"{path.name}:{i}:{line[:200]}")
                report["ok"] = False
                report["errors"].append(
                    f"{cls}: non-call/non-ICC/non-header line: {path.name}:{i}: {line[:160]}"
                )

        report["per_class"][cls] = {
            "n_sampled_files": 20,
            "line_count_dist": dist([float(x) for x in line_counts]),
            "n_call_lines": n_call,
            "n_icc_lines": n_icc,
            "n_header_lines": n_header,
            "n_other_nonempty": n_other,
            "n_timestamp_field_fails": n_ts_fail,
            "n_callee_fq_fails": n_callee_fail,
            "verbatim_call_examples": examples,
            "icc_block_line_examples": icc_examples,
            "header_examples": header_examples,
            "other_examples": other_examples,
        }
        if n_ts_fail or n_callee_fail or n_other:
            report["ok"] = False
        if n_call == 0 and n_other == 0:
            # all empty/header sample possible for malware; not a form deviation
            report["per_class"][cls]["note"] = "sample contained zero call lines"

    return report


def step4_map(benign_files: list[Path], malware_files: list[Path]) -> dict:
    out: dict[str, Any] = {"per_class": {}}
    for cls, files in (("benign", benign_files), ("malware", malware_files)):
        total_calls = 0
        mapped_events = 0
        mapped_per_app: list[int] = []
        cat_event_counts: Counter[str] = Counter()
        cat_app_counts: Counter[str] = Counter()
        unmapped_prefixes: Counter[str] = Counter()
        active_nodes_per_app: list[int] = []
        per_app_rows: list[dict] = []

        for path in files:
            app_mapped = 0
            app_cats: set[str] = set()
            app_calls = 0
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                cl = parse_call_line(line)
                if cl is None:
                    continue
                app_calls += 1
                total_calls += 1
                cat = androct_callee_to_graph_category("<" + cl.callee + ">")
                if cat is None:
                    unmapped_prefixes[class_prefix("<" + cl.callee + ">")] += 1
                    continue
                mapped_events += 1
                app_mapped += 1
                cat_event_counts[cat] += 1
                app_cats.add(cat)
            for c in app_cats:
                cat_app_counts[c] += 1
            mapped_per_app.append(app_mapped)
            active_nodes_per_app.append(len(app_cats))
            per_app_rows.append(
                {
                    "file": path.name,
                    "n_call_lines": app_calls,
                    "n_mapped": app_mapped,
                    "n_active_nodes": len(app_cats),
                    "categories": ",".join(sorted(app_cats)),
                }
            )

        fires = sum(1 for c in GRAPH_CATEGORY_UNIVERSE if cat_event_counts[c] > 0)
        out["per_class"][cls] = {
            "n_apps": len(files),
            "total_call_lines": total_calls,
            "mapped_events": mapped_events,
            "mapped_event_rate": (mapped_events / total_calls) if total_calls else None,
            "mapped_events_per_app": dist([float(x) for x in mapped_per_app]),
            "category_event_counts": {c: cat_event_counts[c] for c in GRAPH_CATEGORY_UNIVERSE},
            "category_app_counts": {c: cat_app_counts[c] for c in GRAPH_CATEGORY_UNIVERSE},
            "category_fire_coverage_of_22": fires,
            "active_nodes_per_app": dist([float(x) for x in active_nodes_per_app]),
            "top50_unmapped_class_prefixes": unmapped_prefixes.most_common(50),
        }
        csv_path = OUT_DIR / f"step4_per_app_{cls}.csv"
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(per_app_rows[0].keys()) if per_app_rows else [])
            if per_app_rows:
                w.writeheader()
                w.writerows(per_app_rows)
        # stash arrays for step5/6
        out["per_class"][cls]["_mapped_per_app"] = mapped_per_app
        out["per_class"][cls]["_active_nodes"] = active_nodes_per_app
        out["per_class"][cls]["_files"] = [str(p) for p in files]
    return out


def step5_graphs(step4: dict) -> dict:
    out: dict[str, Any] = {"per_class": {}}
    for cls, pdata in step4["per_class"].items():
        edges_n: list[int] = []
        degrees: list[int] = []
        degenerate = 0
        per_app: list[dict] = []
        for path_s, n_active in zip(pdata["_files"], pdata["_active_nodes"]):
            path = Path(path_s)
            cats: list[str] = []
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                cl = parse_call_line(line)
                if cl is None:
                    continue
                cat = androct_callee_to_graph_category("<" + cl.callee + ">")
                if cat is not None:
                    cats.append(cat)
            g = build_k_only_graph(cats, package=path.stem)
            n_edges = len(g.edges)
            edges_n.append(n_edges)
            act = g.active_nodes()
            if len(act) <= 1:
                degenerate += 1
            # degree: out+in per active node
            deg: Counter[str] = Counter()
            for u, v in g.edges:
                deg[u] += 1
                deg[v] += 1
            degrees.extend(deg.values())
            per_app.append(
                {
                    "file": path.name,
                    "n_mapped_events": len(cats),
                    "n_active_nodes": len(act),
                    "n_edges": n_edges,
                }
            )
        n_apps = len(edges_n)
        frac_le2 = (sum(1 for e in edges_n if e <= 2) / n_apps) if n_apps else None
        out["per_class"][cls] = {
            "edges_per_graph": dist([float(x) for x in edges_n]),
            "fraction_graphs_le_2_edges": frac_le2,
            "node_degree_distribution": dist([float(x) for x in degrees]),
            "n_degenerate_0_or_1_active_node": degenerate,
            "n_apps": n_apps,
        }
        with (OUT_DIR / f"step5_per_app_{cls}.csv").open("w", newline="", encoding="utf-8") as fh:
            if per_app:
                w = csv.DictWriter(fh, fieldnames=list(per_app[0].keys()))
                w.writeheader()
                w.writerows(per_app)
        out["per_class"][cls]["_edges"] = edges_n
        out["per_class"][cls]["_active"] = [r["n_active_nodes"] for r in per_app]
        out["per_class"][cls]["_trace_lens"] = []
        for path_s in pdata["_files"]:
            nlines = sum(
                1
                for _ in Path(path_s).read_text(encoding="utf-8", errors="replace").splitlines()
            )
            out["per_class"][cls]["_trace_lens"].append(nlines)
        out["per_class"][cls]["_mapped"] = list(pdata["_mapped_per_app"])
    return out


def mann_whitney_u(x: list[float], y: list[float]) -> tuple[float, float]:
    """Return (U, two-sided p) via scipy if available, else (U, nan)."""
    try:
        from scipy.stats import mannwhitneyu

        res = mannwhitneyu(x, y, alternative="two-sided")
        return float(res.statistic), float(res.pvalue)
    except Exception:
        # Manual U without p
        n1, n2 = len(x), len(y)
        combined = sorted([(v, 0) for v in x] + [(v, 1) for v in y])
        ranks = list(range(1, len(combined) + 1))
        # tie average
        i = 0
        while i < len(combined):
            j = i
            while j < len(combined) and combined[j][0] == combined[i][0]:
                j += 1
            avg = sum(ranks[i:j]) / (j - i)
            for k in range(i, j):
                ranks[k] = avg
            i = j
        r1 = sum(ranks[i] for i, (_, g) in enumerate(combined) if g == 0)
        u1 = r1 - n1 * (n1 + 1) / 2
        return float(u1), float("nan")


def cliffs_delta(x: list[float], y: list[float]) -> float:
    """Cliff's delta effect size."""
    if not x or not y:
        return float("nan")
    gt = lt = 0
    for a in x:
        for b in y:
            if a > b:
                gt += 1
            elif a < b:
                lt += 1
    return (gt - lt) / (len(x) * len(y))


def auc_roc(scores: list[float], labels: list[int]) -> float:
    """AUC-ROC; labels 1=positive (malware). Tie-aware Mann-Whitney form."""
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    if not pos or not neg:
        return float("nan")
    # AUC = P(score_pos > score_neg) + 0.5 P(equal)
    gt = eq = 0
    for p in pos:
        for n in neg:
            if p > n:
                gt += 1
            elif p == n:
                eq += 1
    return (gt + 0.5 * eq) / (len(pos) * len(neg))


def step6_confound(step5: dict) -> dict:
    b = step5["per_class"]["benign"]
    m = step5["per_class"]["malware"]

    def compare(name: str, xb: list[float], xm: list[float]) -> dict:
        u, p = mann_whitney_u(xb, xm)
        return {
            "metric": name,
            "benign": dist(xb),
            "malware": dist(xm),
            "mann_whitney_U": u,
            "mann_whitney_p": p,
            "cliffs_delta": cliffs_delta(xb, xm),
        }

    metrics = [
        compare("trace_length_lines", [float(x) for x in b["_trace_lens"]], [float(x) for x in m["_trace_lens"]]),
        compare("mapped_event_count", [float(x) for x in b["_mapped"]], [float(x) for x in m["_mapped"]]),
        compare("active_node_count", [float(x) for x in b["_active"]], [float(x) for x in m["_active"]]),
        compare("edge_count", [float(x) for x in b["_edges"]], [float(x) for x in m["_edges"]]),
    ]

    # labels: malware=1
    scores_len = b["_trace_lens"] + m["_trace_lens"]
    scores_act = b["_active"] + m["_active"]
    scores_edge = b["_edges"] + m["_edges"]
    labels = [0] * len(b["_trace_lens"]) + [1] * len(m["_trace_lens"])

    aucs = {
        "AUC_ROC_trace_length_only": auc_roc([float(x) for x in scores_len], labels),
        "AUC_ROC_active_node_count_only": auc_roc([float(x) for x in scores_act], labels),
        "AUC_ROC_edge_count_only": auc_roc([float(x) for x in scores_edge], labels),
    }
    # Also try inverted scores (shorter = more malware-like) — report both raw and inverted
    aucs_inv = {
        "AUC_ROC_neg_trace_length": auc_roc([-float(x) for x in scores_len], labels),
        "AUC_ROC_neg_active_node_count": auc_roc([-float(x) for x in scores_act], labels),
        "AUC_ROC_neg_edge_count": auc_roc([-float(x) for x in scores_edge], labels),
    }
    return {"comparisons": metrics, "baseline_auc_raw_score": aucs, "baseline_auc_negated_score": aucs_inv}


def extract_hash_from_filename(name: str) -> Optional[str]:
    # Common: sha256 hex 64 chars, or md5 32
    m = re.search(r"\b([a-fA-F0-9]{64})\b", name)
    if m:
        return m.group(1).lower()
    m = re.search(r"\b([a-fA-F0-9]{32})\b", name)
    if m:
        return m.group(1).lower()
    # strip extension
    stem = Path(name).stem
    if re.fullmatch(r"[a-fA-F0-9]{64}", stem):
        return stem.lower()
    if re.fullmatch(r"[a-fA-F0-9]{32}", stem):
        return stem.lower()
    return None


def step7_androzoo(benign_files: list[Path], malware_files: list[Path]) -> dict:
    """Metadata lookup only — no APK download."""
    report: dict[str, Any] = {
        "hash_recoverable_from_filename": None,
        "naming_scheme_notes": [],
        "lookups": {"benign": [], "malware": []},
        "ok": True,
        "errors": [],
    }
    # Inspect naming
    for cls, files in (("benign", benign_files), ("malware", malware_files)):
        names = [f.name for f in files[:20]]
        report["naming_scheme_notes"].append({cls: names[:5]})
        hashes = [extract_hash_from_filename(f.name) for f in files]
        n_ok = sum(1 for h in hashes if h)
        report.setdefault("hash_stats", {})[cls] = {
            "n_files": len(files),
            "n_with_hash_in_name": n_ok,
        }

    # Prefer AndroZoo index under repo data/androzoo/, then ~/androzoo/
    ctx_root = Path(__file__).resolve().parents[2]
    index_paths = [
        ctx_root / "data/androzoo/latest.csv.gz",
        ctx_root / "data/androzoo/latest.csv",
        Path.home() / "androzoo" / "latest.csv.gz",
        Path.home() / "androzoo" / "latest.csv",
    ]
    index = next((p for p in index_paths if p.is_file()), None)
    report["androzoo_index"] = str(index) if index else None

    def lookup_hash(h: str) -> dict:
        if index is None:
            return {"sha256": h, "found": None, "error": "no local AndroZoo index"}
        # stream scan — fail closed if not found after full scan for these few
        import gzip

        open_fn = gzip.open if index.suffix == ".gz" else open
        mode = "rt"
        with open_fn(index, mode, encoding="utf-8", errors="replace") as fh:  # type: ignore
            reader = csv.DictReader(fh)
            # AndroZoo columns typically include sha256
            for row in reader:
                sha = (row.get("sha256") or row.get("SHA256") or "").lower()
                if sha == h:
                    return {
                        "sha256": h,
                        "found": True,
                        "pkg_name": row.get("pkg_name") or row.get("package_name"),
                        "vt_detection": row.get("vt_detection"),
                        "markets": row.get("markets"),
                        "dex_date": row.get("dex_date"),
                    }
        return {"sha256": h, "found": False}

    for cls, files in (("benign", benign_files), ("malware", malware_files)):
        picked = []
        for f in files:
            h = extract_hash_from_filename(f.name)
            if h and h not in picked:
                picked.append(h)
            if len(picked) >= 5:
                break
        if len(picked) < 5:
            report["ok"] = False
            report["errors"].append(f"{cls}: could not recover 5 hashes from filenames")
            report["hash_recoverable_from_filename"] = False
        else:
            report["hash_recoverable_from_filename"] = True
        for h in picked[:5]:
            report["lookups"][cls].append(lookup_hash(h))

    return report


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    benign_files = find_class_files("benign")
    malware_files = find_class_files("malware")

    inventory = {
        "benign_n": len(benign_files),
        "malware_n": len(malware_files),
        "extract_dir": str(EXTRACT_DIR),
        "benign_sample_names": [f.name for f in benign_files[:5]],
        "malware_sample_names": [f.name for f in malware_files[:5]],
        "benign_parent_dirs": sorted({str(f.parent.relative_to(EXTRACT_DIR)) for f in benign_files}),
        "malware_parent_dirs": sorted({str(f.parent.relative_to(EXTRACT_DIR)) for f in malware_files}),
        "paper_expected_benign_2019": 1361,
        "paper_expected_malware_2019": 1106,
    }
    (OUT_DIR / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
    print("inventory", inventory)

    if not benign_files or not malware_files:
        print("FAIL: extracted traces not found", inventory)
        return 2

    s3 = step3_format_verify(benign_files, malware_files)
    (OUT_DIR / "step3_format.json").write_text(json.dumps(s3, indent=2) + "\n")
    if not s3["ok"]:
        print("FAIL step3:", s3["errors"][:20])
        return 3

    print("step3 OK")
    s4 = step4_map(benign_files, malware_files)
    # strip private keys for json dump
    s4_pub = {
        "per_class": {
            k: {kk: vv for kk, vv in v.items() if not kk.startswith("_")}
            for k, v in s4["per_class"].items()
        }
    }
    (OUT_DIR / "step4_map.json").write_text(json.dumps(s4_pub, indent=2) + "\n")
    print("step4 OK")

    s5 = step5_graphs(s4)
    s5_pub = {
        "per_class": {
            k: {kk: vv for kk, vv in v.items() if not kk.startswith("_")}
            for k, v in s5["per_class"].items()
        }
    }
    (OUT_DIR / "step5_graphs.json").write_text(json.dumps(s5_pub, indent=2) + "\n")
    print("step5 OK")

    s6 = step6_confound(s5)
    (OUT_DIR / "step6_confound.json").write_text(json.dumps(s6, indent=2) + "\n")
    print("step6 AUCs:", s6["baseline_auc_raw_score"], s6["baseline_auc_negated_score"])

    s7 = step7_androzoo(benign_files, malware_files)
    (OUT_DIR / "step7_androzoo.json").write_text(json.dumps(s7, indent=2) + "\n")
    if not s7["ok"]:
        print("FAIL step7:", s7["errors"])
        return 7
    print("step7 OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
