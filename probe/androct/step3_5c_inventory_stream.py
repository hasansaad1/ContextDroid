#!/usr/bin/env python3
"""Step 3.5c — inventory archives via tar stream (no full extract; disk-safe)."""

from __future__ import annotations

import json
import tarfile
from collections import Counter
from pathlib import Path

from paths import DATA_DIR, EXTRACT_DIR, OUT_DIR
from droidfax_filter import CALL_RE, classify_allowlisted, iter_trace_files, scan_file

ARCH_DIR = DATA_DIR / "archives_2017_2018"
ARCHIVES = [
    "trace-benign-2017.tar.gz",
    "trace-malware-2017.tar.gz",
    "trace-benign-2018.tar.gz",
    "trace-malware-2018.tar.gz",
]


def zero_call_from_bytes(raw: bytes) -> tuple[bool, int, int]:
    """Return (is_zero_call, n_call, n_dropped) scanning allowlist."""
    text = raw.decode("utf-8", errors="replace")
    n_call = n_dropped = 0
    for line in text.splitlines():
        kind = classify_allowlisted(line)
        if kind == "call":
            n_call += 1
        elif kind == "drop":
            n_dropped += 1
    return n_call == 0, n_call, n_dropped


def inventory_tar(name: str) -> dict:
    path = ARCH_DIR / name
    out: dict = {"declared_name": name, "present": path.is_file()}
    if not path.is_file():
        out["error"] = "missing"
        return out
    out["size_bytes"] = path.stat().st_size
    parents: Counter[str] = Counter()
    top: set[str] = set()
    n_files = 0
    n_zero = 0
    samples: list[str] = []
    with tarfile.open(path, "r:gz") as tf:
        for m in tf:
            if not m.isfile():
                continue
            # path parts
            parts = Path(m.name).parts
            if parts:
                top.add(parts[0])
            parent = str(Path(m.name).parent)
            name_only = Path(m.name).name
            if not name_only.endswith(".apk.logcat"):
                continue
            n_files += 1
            parents[parent] += 1
            if len(samples) < 5:
                samples.append(name_only)
            fobj = tf.extractfile(m)
            if fobj is None:
                continue
            raw = fobj.read()
            is_zero, _, _ = zero_call_from_bytes(raw)
            if is_zero:
                n_zero += 1
    out["top_level"] = sorted(top)
    out["dir_labels"] = sorted(parents.keys())
    out["parent_dir_counts"] = dict(parents)
    out["n_apk_logcat"] = n_files
    out["n_zero_call"] = n_zero
    out["n_nonzero_call"] = n_files - n_zero
    out["sample_names"] = samples
    return out


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    results = {}
    for name in ARCHIVES:
        print("inventory", name, flush=True)
        results[name] = inventory_tar(name)
        print(json.dumps(results[name], indent=2), flush=True)

    # 2019 comparison from already-extracted set
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
    md5 = OUT_DIR / "step3_5c_md5.json"
    if md5.is_file():
        results["md5"] = json.loads(md5.read_text())
    (OUT_DIR / "step3_5c_archive_inventory.json").write_text(
        json.dumps(results, indent=2) + "\n"
    )
    print("wrote step3_5c_archive_inventory.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
