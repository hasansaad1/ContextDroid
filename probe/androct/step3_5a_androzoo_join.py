#!/usr/bin/env python3
"""Step 3.5a — join hashes against AndroZoo index (run after index is intact)."""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

from paths import CONTEXTDROID_ROOT, OUT_DIR

sys.path.insert(0, str(CONTEXTDROID_ROOT / "scripts" / "corpus"))
from androzoo_index import iter_rows  # noqa: E402

INDEX = CONTEXTDROID_ROOT / "data" / "androzoo" / "latest.csv.gz"


def year_from_dex_date(dex_date: str | None) -> str | None:
    if not dex_date:
        return None
    d = dex_date.strip()
    if len(d) >= 4 and d[:4].isdigit():
        return d[:4]
    return None


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    hash_lists = json.loads((OUT_DIR / "step3_5_hash_lists.json").read_text())
    class_of: dict[str, str] = {}
    for cls, hs in hash_lists.items():
        for h in hs:
            if h:
                class_of[h.lower()] = cls
    needed = set(class_of)
    print(f"looking up {len(needed)} hashes in {INDEX}")

    # Verify gzip first
    import gzip

    try:
        with gzip.open(INDEX, "rb") as gz:
            gz.read(64)
            # seek end stream check: read a bit more
            while gz.read(1 << 20):
                pass
        print("gzip OK")
    except EOFError as e:
        print(f"FAIL: index truncated: {e}", file=sys.stderr)
        return 2

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
                print(f"all found at row {i}")
                break

    year_dist: dict[str, Counter] = {"benign": Counter(), "malware": Counter()}
    vt_dist: dict[str, Counter] = {"benign": Counter(), "malware": Counter()}
    absent: dict[str, list[str]] = {"benign": [], "malware": []}
    benign_vt_gt0: list[dict] = []
    malware_vt_lt10: list[dict] = []
    per_hash_rows: list[dict] = []

    for h, cls in sorted(class_of.items()):
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

    benign_hashes = {h for h, c in class_of.items() if c == "benign"}
    malware_hashes = {h for h, c in class_of.items() if c == "malware"}
    overlap = sorted(benign_hashes & malware_hashes)

    byears = {y for y in year_dist["benign"] if y not in ("ABSENT", "UNKNOWN")}
    myears = {y for y in year_dist["malware"] if y not in ("ABSENT", "UNKNOWN")}
    year_intersection = sorted(byears & myears)
    b_in = sum(year_dist["benign"][y] for y in year_intersection)
    m_in = sum(year_dist["malware"][y] for y in year_intersection)
    b_tot = sum(v for k, v in year_dist["benign"].items() if k != "ABSENT")
    m_tot = sum(v for k, v in year_dist["malware"].items() if k != "ABSENT")
    b_frac = (b_in / b_tot) if b_tot else 0.0
    m_frac = (m_in / m_tot) if m_tot else 0.0
    year_gate_pass = bool(year_intersection) and b_frac >= 0.25 and m_frac >= 0.25

    provenance = {
        "n_hashes": len(needed),
        "n_found": len(found),
        "n_absent": {c: len(absent[c]) for c in ("benign", "malware")},
        "absent_hashes_sample": {c: absent[c][:50] for c in ("benign", "malware")},
        "overlap_hashes": overlap,
        "year_distribution": {c: dict(sorted(year_dist[c].items())) for c in ("benign", "malware")},
        "vt_detection_distribution": {
            c: dict(
                sorted(
                    vt_dist[c].items(),
                    key=lambda x: (
                        x[0] not in ("ABSENT", "UNPARSEABLE"),
                        int(x[0]) if x[0].lstrip("-").isdigit() else 999,
                    ),
                )
            )
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

    # Join year/vt onto emptiness per-file CSV if present
    empty_path = OUT_DIR / "step3_5_per_file_allowlist.csv"
    if empty_path.is_file():
        joined = []
        with empty_path.open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                h = row["sha256"].lower()
                az = found.get(h)
                if az:
                    row["year"] = year_from_dex_date(az["dex_date"]) or ""
                    row["vt_detection"] = az["vt_detection"]
                    row["pkg_name"] = az["pkg_name"]
                    row["apk_size"] = az["apk_size"]
                    row["in_androzoo"] = "1"
                else:
                    row["year"] = ""
                    row["vt_detection"] = ""
                    row["pkg_name"] = ""
                    row["apk_size"] = ""
                    row["in_androzoo"] = "0"
                joined.append(row)
        with (OUT_DIR / "step3_5_per_file_joined.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(joined[0].keys()))
            w.writeheader()
            w.writerows(joined)

        # emptiness year/vt splits
        def split_stats(rows: list[dict]) -> dict:
            years = Counter(r.get("year") or "UNKNOWN" for r in rows)
            vts = Counter(r.get("vt_detection") or "UNKNOWN" for r in rows)
            return {
                "n": len(rows),
                "year_distribution": dict(sorted(years.items())),
                "vt_detection_distribution": dict(sorted(vts.items())),
            }

        empty_m = [r for r in joined if r["class"] == "malware" and r["zero_call"] == "True"]
        non_m = [r for r in joined if r["class"] == "malware" and r["zero_call"] == "False"]
        empty_b = [r for r in joined if r["class"] == "benign" and r["zero_call"] == "True"]
        non_b = [r for r in joined if r["class"] == "benign" and r["zero_call"] == "False"]
        join_summary = {
            "malware_empty": split_stats(empty_m),
            "malware_nonempty": split_stats(non_m),
            "benign_empty": split_stats(empty_b),
            "benign_nonempty": split_stats(non_b),
        }
        (OUT_DIR / "step3_5b_emptiness_by_year_vt.json").write_text(
            json.dumps(join_summary, indent=2) + "\n"
        )

    (OUT_DIR / "step3_5_GATE.json").write_text(
        json.dumps(
            {"year_overlap_gate": provenance["year_overlap_gate"], "stop": not year_gate_pass},
            indent=2,
        )
        + "\n"
    )
    print("year_gate_pass", year_gate_pass)
    print("absent", provenance["n_absent"])
    print("benign_vt>0", len(benign_vt_gt0), "malware_vt<10", len(malware_vt_lt10))
    print("years", provenance["year_distribution"])
    return 0 if year_gate_pass else 3


if __name__ == "__main__":
    raise SystemExit(main())
