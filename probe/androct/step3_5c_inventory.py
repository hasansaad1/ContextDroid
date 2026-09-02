#!/usr/bin/env python3
"""Step 3.5c — inventory 2017/2018 archives: extract listings + zero-call counts."""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

from paths import DATA_DIR, OUT_DIR
from droidfax_filter import scan_file, sha256_from_filename

ARCH_DIR = DATA_DIR / "archives_2017_2018"
EXTRACT = DATA_DIR / "extracted_2017_2018"

ARCHIVES = [
    "trace-benign-2017.tar.gz",
    "trace-malware-2017.tar.gz",
    "trace-benign-2018.tar.gz",
    "trace-malware-2018.tar.gz",
]


def inventory_archive(name: str) -> dict:
    path = ARCH_DIR / name
    out: dict = {"declared_name": name, "present": path.is_file()}
    if not path.is_file():
        out["error"] = "missing"
        return out
    out["size_bytes"] = path.stat().st_size
    dest = EXTRACT / name.replace(".tar.gz", "")
    dest.mkdir(parents=True, exist_ok=True)
    # Extract if not already
    marker = dest / ".extracted_ok"
    if not marker.is_file():
        with tarfile.open(path, "r:gz") as tf:
            tf.extractall(dest)
        marker.write_text("ok\n")

    # dirs + files
    dirs = sorted({str(p.relative_to(dest)) for p in dest.rglob("*") if p.is_dir()})
    files = sorted(dest.rglob("*.apk.logcat"))
    # also any other files?
    all_files = [p for p in dest.rglob("*") if p.is_file() and p.name != ".extracted_ok"]
    out["top_level"] = sorted(p.name for p in dest.iterdir() if p.name != ".extracted_ok")
    out["dir_labels"] = dirs[:50]
    out["n_apk_logcat"] = len(files)
    out["n_all_files"] = len(all_files)
    out["sample_names"] = [f.name for f in files[:5]]

    # zero-call via allowlist scan (lightweight; not full parse/mapping)
    zero = 0
    for f in files:
        st = scan_file(f)
        if st.n_call == 0:
            zero += 1
    out["n_zero_call"] = zero
    out["n_nonzero_call"] = len(files) - zero

    # parent dir label histogram
    from collections import Counter

    parents = Counter(str(f.parent.relative_to(dest)) for f in files)
    out["parent_dir_counts"] = dict(parents)
    return out


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    EXTRACT.mkdir(parents=True, exist_ok=True)
    results = {}
    for name in ARCHIVES:
        print("inventory", name, flush=True)
        results[name] = inventory_archive(name)
        print(json.dumps(results[name], indent=2), flush=True)
    # also inventory already-extracted 2019 for comparison
    from paths import EXTRACT_DIR
    from droidfax_filter import iter_trace_files

    y2019 = {"benign": 0, "malware": 0, "benign_zero": 0, "malware_zero": 0, "dirs": set()}
    for cls, p in iter_trace_files(EXTRACT_DIR):
        y2019[cls] += 1
        y2019["dirs"].add(str(p.parent.relative_to(EXTRACT_DIR)))
        if scan_file(p).n_call == 0:
            y2019[f"{cls}_zero"] += 1
    results["2019_already_extracted_comparison"] = {
        "benign_n": y2019["benign"],
        "malware_n": y2019["malware"],
        "benign_zero_call": y2019["benign_zero"],
        "malware_zero_call": y2019["malware_zero"],
        "dir_labels": sorted(y2019["dirs"]),
    }
    (OUT_DIR / "step3_5c_archive_inventory.json").write_text(
        json.dumps(results, indent=2, default=list) + "\n"
    )
    print("wrote step3_5c_archive_inventory.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
