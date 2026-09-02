#!/usr/bin/env python3
"""Step 3.5a+b — AndroZoo provenance + emptiness characterization."""

from __future__ import annotations

import csv
import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

import paths  # noqa: F401
from paths import CONTEXTDROID_ROOT, EXTRACT_DIR, OUT_DIR
from droidfax_filter import iter_trace_files, scan_file, sha256_from_filename

# Reuse ContextDroid AndroZoo index helper without modifying it — import by path.
sys.path.insert(0, str(CONTEXTDROID_ROOT / "scripts" / "corpus"))
from androzoo_index import iter_rows  # noqa: E402

INDEX = CONTEXTDROID_ROOT / "data" / "androzoo" / "latest.csv.gz"


def _dist(vals: list[float]) -> dict:
    if not vals:
        return {"n": 0, "min": None, "p25": None, "median": None, "p75": None, "max": None}
    s = sorted(vals)
    n = len(s)

    def pct(p: float) -> float:
        if n == 1:
            return float(s[0])
        k = (n - 1) * p
        f, c = math.floor(k), math.ceil(k)
        if f == c:
            return float(s[int(k)])
        return float(s[f] * (c - k) + s[c] * (k - f))

    return {
        "n": n,
        "min": s[0],
        "p25": pct(0.25),
        "median": statistics.median(s),
        "p75": pct(0.75),
        "max": s[-1],
    }


def year_from_dex_date(dex_date: str | None) -> str | None:
    if not dex_date:
        return None
    d = dex_date.strip()
    if len(d) >= 4 and d[:4].isdigit():
        return d[:4]
    return None


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if not INDEX.is_file():
        print(f"FAIL: AndroZoo index missing: {INDEX}", file=sys.stderr)
        return 2
    if not EXTRACT_DIR.is_dir():
        print(f"FAIL: extract dir missing: {EXTRACT_DIR}", file=sys.stderr)
        return 2

    # Collect files + hashes
    by_class: dict[str, list[Path]] = {"benign": [], "malware": []}
    hash_to_meta: dict[str, dict] = {}  # sha -> {cls, path, ...}
    for cls, path in iter_trace_files(EXTRACT_DIR):
        by_class[cls].append(path)
        h = sha256_from_filename(path.name)
        if h is None:
            continue
        hash_to_meta[h] = {"class": cls, "path": str(path), "filename": path.name}

    needed = set(hash_to_meta.keys())
    print(f"hashes needed: {len(needed)} benign={len(by_class['benign'])} malware={len(by_class['malware'])}")

    found: dict[str, dict] = {}
    for i, row in enumerate(iter_rows(str(INDEX), skip_bogus=False, progress_every=2_000_000)):
        sha = (row.get("sha256") or "").strip().lower()
        if sha in needed and sha not in found:
            found[sha] = {
                "dex_date": row.get("dex_date") or "",
                "vt_detection": row.get("vt_detection") or "",
                "pkg_name": row.get("pkg_name") or "",
                "apk_size": row.get("apk_size") or "",
                "markets": row.get("markets") or "",
            }
            if len(found) == len(needed):
                break
        if i and i % 5_000_000 == 0:
            print(f"  scanned {i} index rows, found {len(found)}/{len(needed)}", flush=True)

    print(f"AndroZoo hits: {len(found)}/{len(needed)}")

    # --- 3.5a provenance ---
    year_dist: dict[str, Counter] = {"benign": Counter(), "malware": Counter()}
    vt_dist: dict[str, Counter] = {"benign": Counter(), "malware": Counter()}
    absent: dict[str, list[str]] = {"benign": [], "malware": []}
    benign_vt_gt0: list[dict] = []
    malware_vt_lt10: list[dict] = []
    per_hash_rows: list[dict] = []

    for h, meta in sorted(hash_to_meta.items()):
        cls = meta["class"]
        az = found.get(h)
        if az is None:
            absent[cls].append(h)
            year_dist[cls]["ABSENT"] += 1
            vt_dist[cls]["ABSENT"] += 1
            per_hash_rows.append(
                {
                    "sha256": h,
                    "class": cls,
                    "in_androzoo": False,
                    "dex_date": "",
                    "year": "",
                    "vt_detection": "",
                    "pkg_name": "",
                    "apk_size": "",
                }
            )
            continue
        year = year_from_dex_date(az["dex_date"]) or "UNKNOWN"
        year_dist[cls][year] += 1
        vt_raw = az["vt_detection"].strip()
        try:
            vt = int(vt_raw) if vt_raw != "" else None
        except ValueError:
            vt = None
        vt_key = str(vt) if vt is not None else "UNPARSEABLE"
        vt_dist[cls][vt_key] += 1
        if cls == "benign" and vt is not None and vt > 0:
            benign_vt_gt0.append({"sha256": h, "vt_detection": vt, "dex_date": az["dex_date"]})
        if cls == "malware" and vt is not None and vt < 10:
            malware_vt_lt10.append({"sha256": h, "vt_detection": vt, "dex_date": az["dex_date"]})
        per_hash_rows.append(
            {
                "sha256": h,
                "class": cls,
                "in_androzoo": True,
                "dex_date": az["dex_date"],
                "year": year,
                "vt_detection": vt_key,
                "pkg_name": az["pkg_name"],
                "apk_size": az["apk_size"],
            }
        )

    benign_hashes = {h for h, m in hash_to_meta.items() if m["class"] == "benign"}
    malware_hashes = {h for h, m in hash_to_meta.items() if m["class"] == "malware"}
    overlap = sorted(benign_hashes & malware_hashes)

    # Year overlap gate
    byears = {y for y in year_dist["benign"] if y not in ("ABSENT", "UNKNOWN")}
    myears = {y for y in year_dist["malware"] if y not in ("ABSENT", "UNKNOWN")}
    year_intersection = sorted(byears & myears)
    # "substantially overlap": intersection non-empty AND share of each class in intersection years
    b_in = sum(year_dist["benign"][y] for y in year_intersection)
    m_in = sum(year_dist["malware"][y] for y in year_intersection)
    b_tot = sum(v for k, v in year_dist["benign"].items() if k not in ("ABSENT",))
    m_tot = sum(v for k, v in year_dist["malware"].items() if k not in ("ABSENT",))
    b_frac = (b_in / b_tot) if b_tot else 0.0
    m_frac = (m_in / m_tot) if m_tot else 0.0
    # Fail closed if intersection empty OR either class has <25% of its dated apps in shared years
    year_gate_pass = bool(year_intersection) and b_frac >= 0.25 and m_frac >= 0.25

    provenance = {
        "n_benign_files": len(by_class["benign"]),
        "n_malware_files": len(by_class["malware"]),
        "n_hashes": len(needed),
        "androzoo_index": str(INDEX),
        "n_found": len(found),
        "n_absent": {c: len(absent[c]) for c in ("benign", "malware")},
        "absent_hashes": {c: absent[c][:50] for c in ("benign", "malware")},
        "overlap_hashes": overlap,
        "year_distribution": {c: dict(sorted(year_dist[c].items())) for c in ("benign", "malware")},
        "vt_detection_distribution": {
            c: dict(sorted(vt_dist[c].items(), key=lambda x: (x[0] not in ("ABSENT", "UNPARSEABLE"), int(x[0]) if x[0].lstrip("-").isdigit() else 999)))
            for c in ("benign", "malware")
        },
        "paper_criteria_violations": {
            "benign_vt_detection_gt_0_count": len(benign_vt_gt0),
            "malware_vt_detection_lt_10_count": len(malware_vt_lt10),
            "benign_vt_gt0_examples": benign_vt_gt0[:20],
            "malware_vt_lt10_examples": malware_vt_lt10[:20],
        },
        "year_overlap_gate": {
            "benign_years": sorted(byears),
            "malware_years": sorted(myears),
            "intersection_years": year_intersection,
            "benign_frac_in_intersection": b_frac,
            "malware_frac_in_intersection": m_frac,
            "threshold_frac": 0.25,
            "pass": year_gate_pass,
        },
    }
    (OUT_DIR / "step3_5a_provenance.json").write_text(
        json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
    )
    with (OUT_DIR / "step3_5a_per_hash.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(per_hash_rows[0].keys()))
        w.writeheader()
        w.writerows(per_hash_rows)
    print("year_gate_pass", year_gate_pass, "intersection", year_intersection, "b_frac", b_frac, "m_frac", m_frac)
    print("benign_vt>0", len(benign_vt_gt0), "malware_vt<10", len(malware_vt_lt10))

    # --- allowlist drop counts + emptiness (3.5b) ---
    drop_rows: list[dict] = []
    empty_malware: list[dict] = []
    nonempty_malware: list[dict] = []
    empty_benign: list[dict] = []
    nonempty_benign: list[dict] = []
    agg_dropped = {"benign": 0, "malware": 0}
    agg_calls = {"benign": 0, "malware": 0}
    agg_reflection = {"benign": 0, "malware": 0}

    for cls, paths in by_class.items():
        for path in paths:
            st = scan_file(path)
            h = sha256_from_filename(path.name) or ""
            az = found.get(h, {})
            year = year_from_dex_date(az.get("dex_date")) if az else None
            vt_raw = (az.get("vt_detection") or "").strip() if az else ""
            try:
                vt = int(vt_raw) if vt_raw else None
            except ValueError:
                vt = None
            size = path.stat().st_size
            row = {
                "sha256": h,
                "class": cls,
                "file": path.name,
                "file_size_bytes": size,
                "n_total_lines": st.n_total,
                "n_empty": st.n_empty,
                "n_call": st.n_call,
                "n_reflection_tag": st.n_reflection_tag,
                "n_icc": st.n_icc,
                "n_header": st.n_header,
                "n_dropped": st.n_dropped,
                "dropped_examples": "|".join(st.dropped_examples),
                "year": year or "",
                "vt_detection": vt if vt is not None else "",
                "pkg_name": az.get("pkg_name", "") if az else "",
                "zero_call": st.n_call == 0,
                "has_droidfax_markers": (st.n_call + st.n_icc + st.n_reflection_tag) > 0,
            }
            drop_rows.append(row)
            agg_dropped[cls] += st.n_dropped
            agg_calls[cls] += st.n_call
            agg_reflection[cls] += st.n_reflection_tag
            bucket = empty_malware if (cls == "malware" and st.n_call == 0) else None
            if cls == "malware" and st.n_call == 0:
                empty_malware.append(row)
            elif cls == "malware":
                nonempty_malware.append(row)
            if cls == "benign" and st.n_call == 0:
                empty_benign.append(row)
            elif cls == "benign":
                nonempty_benign.append(row)

    def summarize_set(rows: list[dict], label: str) -> dict:
        sizes = [float(r["file_size_bytes"]) for r in rows]
        totals = [float(r["n_total_lines"]) for r in rows]
        dropped = [float(r["n_dropped"]) for r in rows]
        years = Counter(r["year"] or "UNKNOWN" for r in rows)
        vts = Counter(str(r["vt_detection"]) if r["vt_detection"] != "" else "UNKNOWN" for r in rows)
        markers = sum(1 for r in rows if r["has_droidfax_markers"])
        only_headers = sum(
            1
            for r in rows
            if r["n_call"] == 0
            and r["n_icc"] == 0
            and r["n_reflection_tag"] == 0
            and r["n_header"] > 0
            and r["n_dropped"] == 0
        )
        only_dropped = sum(
            1
            for r in rows
            if r["n_call"] == 0 and r["n_dropped"] > 0 and r["n_icc"] == 0 and r["n_reflection_tag"] == 0
        )
        truly_emptyish = sum(1 for r in rows if r["n_total_lines"] == 0 or (r["n_total_lines"] == r["n_empty"]))
        return {
            "label": label,
            "n": len(rows),
            "file_size_bytes": _dist(sizes),
            "n_total_lines": _dist(totals),
            "n_dropped_lines": _dist(dropped),
            "year_distribution": dict(sorted(years.items())),
            "vt_detection_distribution": dict(sorted(vts.items(), key=lambda x: x[0])),
            "n_with_any_droidfax_marker": markers,
            "n_header_only_no_calls_icc_reflection_drop": only_headers,
            "n_dropped_pollution_only_no_calls": only_dropped,
            "n_truly_empty_or_whitespace_only": truly_emptyish,
        }

    emptiness = {
        "allowlist_aggregate_dropped_lines": agg_dropped,
        "allowlist_aggregate_call_lines": agg_calls,
        "allowlist_aggregate_reflection_tags": agg_reflection,
        "benign_zero_call_count": len(empty_benign),
        "malware_zero_call_count": len(empty_malware),
        "benign_nonzero_call_count": len(nonempty_benign),
        "malware_nonzero_call_count": len(nonempty_malware),
        "malware_empty": summarize_set(empty_malware, "malware_zero_call"),
        "malware_nonempty": summarize_set(nonempty_malware, "malware_nonzero_call"),
        "benign_empty": summarize_set(empty_benign, "benign_zero_call"),
        "benign_nonempty": summarize_set(nonempty_benign, "benign_nonzero_call"),
    }
    (OUT_DIR / "step3_5b_emptiness.json").write_text(
        json.dumps(emptiness, indent=2) + "\n", encoding="utf-8"
    )
    with (OUT_DIR / "step3_5_per_file_allowlist.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(drop_rows[0].keys()))
        w.writeheader()
        w.writerows(drop_rows)

    print("benign_zero_call", len(empty_benign), "malware_zero_call", len(empty_malware))
    print("agg_dropped", agg_dropped)

    if not year_gate_pass:
        print("GATE FAIL: year distributions do not substantially overlap — STOP before graph construction")
        (OUT_DIR / "step3_5_GATE.json").write_text(
            json.dumps({"year_overlap_gate": provenance["year_overlap_gate"], "stop": True}, indent=2)
            + "\n"
        )
        return 3

    (OUT_DIR / "step3_5_GATE.json").write_text(
        json.dumps({"year_overlap_gate": provenance["year_overlap_gate"], "stop": False}, indent=2)
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
