#!/usr/bin/env python3
"""Step 3.5b allowlist + emptiness scan (no AndroZoo). Join provenance later."""

from __future__ import annotations

import csv
import json
import math
import statistics
from collections import Counter
from pathlib import Path

from paths import EXTRACT_DIR, OUT_DIR
from droidfax_filter import iter_trace_files, scan_file, sha256_from_filename


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


def summarize_set(rows: list[dict], label: str) -> dict:
    sizes = [float(r["file_size_bytes"]) for r in rows]
    totals = [float(r["n_total_lines"]) for r in rows]
    dropped = [float(r["n_dropped"]) for r in rows]
    headers = [float(r["n_header"]) for r in rows]
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
        if r["n_call"] == 0
        and r["n_dropped"] > 0
        and r["n_icc"] == 0
        and r["n_reflection_tag"] == 0
    )
    header_plus_drop = sum(
        1
        for r in rows
        if r["n_call"] == 0
        and r["n_header"] > 0
        and r["n_dropped"] > 0
        and r["n_icc"] == 0
        and r["n_reflection_tag"] == 0
    )
    truly_emptyish = sum(
        1 for r in rows if r["n_total_lines"] == 0 or (r["n_total_lines"] == r["n_empty"])
    )
    return {
        "label": label,
        "n": len(rows),
        "file_size_bytes": _dist(sizes),
        "n_total_lines": _dist(totals),
        "n_dropped_lines": _dist(dropped),
        "n_header_lines": _dist(headers),
        "n_with_any_droidfax_marker_call_icc_or_reflection": markers,
        "n_header_only": only_headers,
        "n_dropped_pollution_only": only_dropped,
        "n_header_plus_dropped_no_calls": header_plus_drop,
        "n_truly_empty_or_whitespace_only": truly_emptyish,
    }


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    by_class: dict[str, list] = {"benign": [], "malware": []}
    for cls, path in iter_trace_files(EXTRACT_DIR):
        by_class[cls].append(path)

    drop_rows: list[dict] = []
    buckets = {
        "benign_empty": [],
        "benign_nonempty": [],
        "malware_empty": [],
        "malware_nonempty": [],
    }
    agg_dropped = {"benign": 0, "malware": 0}
    agg_calls = {"benign": 0, "malware": 0}
    agg_reflection = {"benign": 0, "malware": 0}
    agg_icc = {"benign": 0, "malware": 0}
    agg_header = {"benign": 0, "malware": 0}
    agg_total = {"benign": 0, "malware": 0}

    for cls, paths in by_class.items():
        for path in paths:
            st = scan_file(path)
            h = sha256_from_filename(path.name) or ""
            size = path.stat().st_size
            row = {
                "sha256": h,
                "class": cls,
                "file": path.name,
                "relpath": str(path.relative_to(EXTRACT_DIR)),
                "file_size_bytes": size,
                "n_total_lines": st.n_total,
                "n_empty": st.n_empty,
                "n_call": st.n_call,
                "n_reflection_tag": st.n_reflection_tag,
                "n_icc": st.n_icc,
                "n_header": st.n_header,
                "n_dropped": st.n_dropped,
                "dropped_examples": "|".join(st.dropped_examples),
                "zero_call": st.n_call == 0,
                "has_droidfax_markers": (st.n_call + st.n_icc + st.n_reflection_tag) > 0,
            }
            drop_rows.append(row)
            agg_dropped[cls] += st.n_dropped
            agg_calls[cls] += st.n_call
            agg_reflection[cls] += st.n_reflection_tag
            agg_icc[cls] += st.n_icc
            agg_header[cls] += st.n_header
            agg_total[cls] += st.n_total
            key = f"{cls}_{'empty' if st.n_call == 0 else 'nonempty'}"
            buckets[key].append(row)

    emptiness = {
        "allowlist_definition": {
            "keep": [
                "call: <sig> -> <sig>",
                "reflection_tag: +through reflection",
                "icc: [ Intent sent|received ], caller=, callsite=, tab-indented fields",
                "header: --------- beginning of ...",
            ],
            "drop": "everything else (explicit count, no silent skip)",
        },
        "n_files": {c: len(by_class[c]) for c in ("benign", "malware")},
        "aggregate_line_counts": {
            "total": agg_total,
            "call": agg_calls,
            "reflection_tag": agg_reflection,
            "icc": agg_icc,
            "header": agg_header,
            "dropped": agg_dropped,
        },
        "benign_zero_call_count": len(buckets["benign_empty"]),
        "malware_zero_call_count": len(buckets["malware_empty"]),
        "benign_nonzero_call_count": len(buckets["benign_nonempty"]),
        "malware_nonzero_call_count": len(buckets["malware_nonempty"]),
        "malware_empty": summarize_set(buckets["malware_empty"], "malware_zero_call"),
        "malware_nonempty": summarize_set(buckets["malware_nonempty"], "malware_nonzero_call"),
        "benign_empty": summarize_set(buckets["benign_empty"], "benign_zero_call"),
        "benign_nonempty": summarize_set(buckets["benign_nonempty"], "benign_nonzero_call"),
    }
    (OUT_DIR / "step3_5b_emptiness.json").write_text(
        json.dumps(emptiness, indent=2) + "\n", encoding="utf-8"
    )
    with (OUT_DIR / "step3_5_per_file_allowlist.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(drop_rows[0].keys()))
        w.writeheader()
        w.writerows(drop_rows)

    # also emit hash list for later AndroZoo join
    hashes = {
        "benign": [sha256_from_filename(p.name) for p in by_class["benign"]],
        "malware": [sha256_from_filename(p.name) for p in by_class["malware"]],
    }
    (OUT_DIR / "step3_5_hash_lists.json").write_text(json.dumps(hashes) + "\n")

    print(json.dumps({
        "benign_zero": len(buckets["benign_empty"]),
        "malware_zero": len(buckets["malware_empty"]),
        "agg_dropped": agg_dropped,
        "agg_calls": agg_calls,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
