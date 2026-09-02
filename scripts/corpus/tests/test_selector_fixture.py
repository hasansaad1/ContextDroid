#!/usr/bin/env python3
"""Fixture test: selector determinism and expected output."""

from __future__ import annotations

import csv
import filecmp
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FIX = ROOT / "scripts" / "corpus" / "fixtures"


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def run_once(out_file: Path) -> None:
    cmd = [
        "python3",
        str(ROOT / "scripts" / "corpus" / "select_malware.py"),
        "--index",
        str(FIX / "selector_fixture_index.csv.gz"),
        "--profile",
        str(FIX / "selector_fixture_profile.json"),
        "--out",
        str(out_file),
        "--target-min",
        "1",
        "--target-max",
        "8",
        "--family-column",
        "family_tag",
        "--family-cap",
        "2",
        "--vt-min",
        "10",
    ]
    subprocess.run(cmd, check=True, cwd=ROOT)


def main() -> int:
    expected = FIX / "selector_expected.csv"
    with tempfile.TemporaryDirectory(prefix="selector_fixture_") as td:
        out1 = Path(td) / "out1.csv"
        out2 = Path(td) / "out2.csv"
        run_once(out1)
        run_once(out2)
        assert filecmp.cmp(out1, out2, shallow=False), "selector output is not byte-identical across reruns"
        assert filecmp.cmp(out1, expected, shallow=False), "selector output drifted from expected fixture"
        rows = read_rows(out1)
        assert len(rows) == 8, f"expected 8 rows, got {len(rows)}"
        selected_sha = {row["sha256"] for row in rows}
        fam_counts: dict[str, int] = {}
        for row in rows:
            fam = row["family"]
            fam_counts[fam] = fam_counts.get(fam, 0) + 1
            assert int(row["vt_detection"]) >= 10, "vt filter violated"
            size = int(row["apk_size"])
            assert 2400000 <= size <= 20000000, "apk_size IQR filter violated"
        # Explicit red/green checks for the three negative fixture rows:
        # - below IQR: ...0013 (apk_size=2_000_000)
        # - above IQR: ...0012 (apk_size=22_000_000)
        # - vt below threshold: ...0008 (vt_detection=9)
        assert "0000000000000000000000000000000000000000000000000000000000000013" not in selected_sha
        assert "0000000000000000000000000000000000000000000000000000000000000012" not in selected_sha
        assert "0000000000000000000000000000000000000000000000000000000000000008" not in selected_sha
        assert all(v <= 2 for v in fam_counts.values()), f"family cap violated: {fam_counts}"
    print("SELECTOR_FIXTURE_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
