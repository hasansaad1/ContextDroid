#!/usr/bin/env python3
"""Inspect AndroZoo index header and vt_detection>=10 population stats (Phase 2.1/2.2)."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts" / "corpus"))

from androzoo_index import DEFAULT_INDEX_URL, iter_rows, inspect_header  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", default=DEFAULT_INDEX_URL)
    parser.add_argument("--vt-min", type=int, default=10)
    parser.add_argument("--sample-limit", type=int, default=5)
    parser.add_argument("--out-json", type=Path, default=REPO_ROOT / "manifest" / "androzoo_index_scan.json")
    parser.add_argument("--max-rows", type=int, default=0, help="Optional cap on rows scanned (0=all)")
    args = parser.parse_args(argv)

    info = inspect_header(args.index)
    print("=== AndroZoo index header inspect ===")
    print(json.dumps(info, indent=2))

    vt_ge = 0
    vt_total = 0
    vt_hist = Counter()
    market_tail = Counter()
    sample_rows = []

    for row in iter_rows(args.index, progress_every=500_000, max_rows=args.max_rows):
        vt_total += 1
        try:
            vt = int(row.get("vt_detection") or -1)
        except ValueError:
            vt = -1
        if vt >= 0:
            vt_hist[min(vt, 20)] += 1
        if vt >= args.vt_min:
            vt_ge += 1
            if len(sample_rows) < args.sample_limit:
                sample_rows.append({k: row.get(k, "") for k in row.keys()})
            mk = (row.get("markets") or "").split("|")[0][:40]
            market_tail[mk] += 1

    print("\n=== vt_detection population ===")
    print(json.dumps({"rows_scanned": vt_total, f"vt>={args.vt_min}": vt_ge}, indent=2))
    print("vt_detection histogram (capped at 20+):")
    for k in sorted(vt_hist.keys()):
        print(f"  vt={k}: {vt_hist[k]}")
    print("\nSample rows vt>=", args.vt_min)
    print(json.dumps(sample_rows, indent=2))
    print("\nTop markets (first segment) in vt>= slice:")
    for m, c in market_tail.most_common(10):
        print(f"  {m!r}: {c}")

    payload = {
        "header": info,
        "rows_scanned": vt_total,
        f"vt_ge_{args.vt_min}": vt_ge,
        "vt_detection_histogram_capped_20": dict(sorted(vt_hist.items())),
        "sample_rows_vt_ge": sample_rows,
        "top_markets_vt_ge": market_tail.most_common(20),
        "family_columns_in_header": info.get("family_columns_present", []),
    }
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\nwrote {args.out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
