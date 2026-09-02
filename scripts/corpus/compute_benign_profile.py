#!/usr/bin/env python3
"""Compute benign corpus profile from local APK directory (Phase 2.3)."""

from __future__ import annotations

import argparse
import json
import re
import statistics
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_APK_DIR = REPO_ROOT / "data" / "apks" / "benign"
DEFAULT_OUT = REPO_ROOT / "manifest" / "benign_profile.json"


def find_aapt() -> str:
    env = Path(__file__).resolve().parents[2]
    candidates = [
        Path.home() / "Library" / "Android" / "sdk" / "build-tools",
    ]
    for root in candidates:
        if not root.is_dir():
            continue
        for aapt in sorted(root.glob("*/aapt"), reverse=True):
            if aapt.is_file():
                return str(aapt)
    found = __import__("shutil").which("aapt")
    if found:
        return found
    raise RuntimeError("aapt not found")


def permission_count(aapt: str, apk: Path) -> int:
    proc = subprocess.run(
        [aapt, "dump", "permissions", str(apk)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return 0
    perms = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("uses-permission:"):
            perms.append(line)
        elif line.startswith("permission:"):
            perms.append(line)
    return len(perms)


def dex_info(apk: Path) -> tuple[int, str | None]:
    try:
        with zipfile.ZipFile(apk) as zf:
            names = [n for n in zf.namelist() if n.endswith("classes.dex") or n == "classes.dex"]
            if not names:
                return 0, None
            name = "classes.dex" if "classes.dex" in names else names[0]
            info = zf.getinfo(name)
            # ZIP date_time is (year, month, day, ...)
            dt = info.date_time
            dex_date = f"{dt[0]:04d}-{dt[1]:02d}-{dt[2]:02d}"
            return info.file_size, dex_date
    except (zipfile.BadZipFile, KeyError, OSError):
        return 0, None


def quantiles(values: list[float]) -> dict[str, float]:
    if not values:
        return {"min": 0, "q1": 0, "median": 0, "q3": 0, "max": 0, "mean": 0, "stdev": 0}
    qs = statistics.quantiles(values, n=4) if len(values) >= 4 else values
    return {
        "min": min(values),
        "q1": qs[0] if len(values) >= 4 else min(values),
        "median": statistics.median(values),
        "q3": qs[2] if len(values) >= 4 else max(values),
        "max": max(values),
        "mean": statistics.mean(values),
        "stdev": statistics.pstdev(values) if len(values) > 1 else 0.0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk-dir", type=Path, default=DEFAULT_APK_DIR)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)

    apk_dir = args.apk_dir.resolve()
    if not apk_dir.is_dir():
        print(f"APK dir missing: {apk_dir}", file=sys.stderr)
        return 1

    aapt = find_aapt()
    apks = sorted(apk_dir.glob("*.apk"))
    records = []
    apk_sizes: list[float] = []
    dex_sizes: list[float] = []
    perm_counts: list[float] = []
    dex_dates: list[str] = []

    for apk in apks:
        apk_size = apk.stat().st_size
        dsize, ddate = dex_info(apk)
        pc = permission_count(aapt, apk)
        records.append(
            {
                "apk": apk.name,
                "apk_size": apk_size,
                "dex_size": dsize,
                "dex_date": ddate,
                "permission_count": pc,
            }
        )
        apk_sizes.append(float(apk_size))
        dex_sizes.append(float(dsize))
        perm_counts.append(float(pc))
        if ddate:
            dex_dates.append(ddate)

    # dex_date range: exclude obvious sentinel 1980/1981 if minority; report both raw and filtered
    year_counts: dict[str, int] = {}
    for d in dex_dates:
        year_counts[d[:4]] = year_counts.get(d[:4], 0) + 1

    non_sentinel_dates = [d for d in dex_dates if not d.startswith(("1980", "1981"))]
    dex_date_range = {
        "raw_min": min(dex_dates) if dex_dates else None,
        "raw_max": max(dex_dates) if dex_dates else None,
        "filtered_min": min(non_sentinel_dates) if non_sentinel_dates else None,
        "filtered_max": max(non_sentinel_dates) if non_sentinel_dates else None,
        "sentinel_1980_1981_count": len([d for d in dex_dates if d.startswith(("1980", "1981"))]),
        "year_histogram": year_counts,
        "note": "AndroZoo warns dex_date is often 1980/1981 for Play apps; benign profile uses ZIP entry dates from local APKs.",
    }

    profile = {
        "generated_at_utc": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_dir": str(apk_dir),
        "apk_count": len(apks),
        "apk_size_bytes": quantiles(apk_sizes),
        "dex_size_bytes": quantiles(dex_sizes),
        "permission_count": quantiles(perm_counts),
        "dex_date": dex_date_range,
        "selection_iqr": {
            "apk_size_low": quantiles(apk_sizes)["q1"],
            "apk_size_high": quantiles(apk_sizes)["q3"],
            "dex_size_low": quantiles(dex_sizes)["q1"],
            "dex_size_high": quantiles(dex_sizes)["q3"],
        },
        "records": records,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
