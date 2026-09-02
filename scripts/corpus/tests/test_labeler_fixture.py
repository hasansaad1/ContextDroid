#!/usr/bin/env python3
"""Fixture test: label assignment and unmatched->none behavior."""

from __future__ import annotations

import csv
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FIX = ROOT / "scripts" / "corpus" / "fixtures"


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="labeler_fixture_") as td:
        out_csv = Path(td) / "labelled.csv"
        out_json = Path(td) / "report.json"
        cmd = [
            "python3",
            str(ROOT / "scripts" / "corpus" / "label_samples.py"),
            "--candidates",
            str(FIX / "label_fixture_candidates.csv"),
            "--out-csv",
            str(out_csv),
            "--out-json",
            str(out_json),
            "--malradar-file",
            str(FIX / "label_fixture_malradar.csv"),
            "--malradar-sha-col",
            "sha256",
            "--malradar-family-col",
            "family",
            "--amd-file",
            str(FIX / "label_fixture_amd.csv"),
            "--amd-sha-col",
            "sample_sha256",
            "--amd-family-col",
            "malware_family",
            "--drebin-file",
            str(FIX / "label_fixture_drebin.csv"),
            "--drebin-sha-col",
            "sha256",
            "--drebin-family-col",
            "family",
        ]
        subprocess.run(cmd, check=True, cwd=ROOT)
        rows = read_rows(out_csv)
        assert len(rows) == 5, f"expected 5 rows, got {len(rows)}"
        by_sha = {r["sha256"]: r for r in rows}
        assert by_sha["a" * 64]["family"] == "Triada" and by_sha["a" * 64]["family_source"] == "malradar"
        assert by_sha["b" * 64]["family"] == "DroidKungFu" and by_sha["b" * 64]["family_source"] == "amd"
        assert by_sha["c" * 64]["family"] == "Plankton" and by_sha["c" * 64]["family_source"] == "drebin"
        assert by_sha["d" * 64]["family_source"] == "none" and by_sha["d" * 64]["family_confidence"] == "none"
        assert by_sha["e" * 64]["family_source"] == "none" and by_sha["e" * 64]["family_confidence"] == "none"
        report = json.loads(out_json.read_text(encoding="utf-8"))
        assert report["counts_by_source"] == {"malradar": 1, "amd": 1, "drebin": 1, "none": 2}
    print("LABELER_FIXTURE_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
