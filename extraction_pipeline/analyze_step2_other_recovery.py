#!/usr/bin/env python3
"""Analyze Step 2 impact on high_back_wait OTHER cohort (44 sessions).

Uses verified_start.xml replay with the post-Step-2 candidate builder to estimate
how many sessions would admit anonymous clickables (other_cands > 0) at launch screen.
Does not re-run devices; live conversion requires fresh collection.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from llm_agent.dialogs import _bfs_filter_expand_candidates
from llm_agent.navigation import _build_bfs_candidates, _build_tab_targets
from llm_agent.screen import _filter_widgets_for_target, _normalized_elements

METRICS = Path("experiment/phase_aware_metrics.json")
WORKING = Path("experiment/working_dataset.csv")


def _artifact_dir(pkg: str) -> Path | None:
    import csv

    for row in csv.DictReader(WORKING.open(encoding="utf-8")):
        if row["package"] == pkg:
            return Path(row["artifact_dir"])
    return None


def _verified_start_elements(base: Path, pkg: str) -> list[dict[str, str]]:
    xml_path = base / f"{pkg}_verified_start.xml"
    if not xml_path.exists():
        return []
    elements = _normalized_elements(xml_path.read_text(encoding="utf-8", errors="replace"))
    return _filter_widgets_for_target(elements, pkg)


def main() -> int:
    data = json.loads(METRICS.read_text(encoding="utf-8"))
    sessions = (data.get("working_dataset_129") or {}).get("sessions") or data.get("sessions") or []
    other_sessions = [s for s in sessions if s.get("cross_tab_bucket") == "high_back_wait_other"]

    rows: list[dict] = []
    would_gain = 0
    for s in other_sessions:
        pkg = str(s["package"])
        base = _artifact_dir(pkg)
        if base is None:
            continue
        elements = _verified_start_elements(base, pkg)
        nav, other = _build_bfs_candidates(elements)
        tabs = _build_tab_targets(elements)
        expand = _bfs_filter_expand_candidates(other, pkg, set())
        old_functional = int(s.get("explore_metrics", {}).get("explore_functional_tap_count") or 0)
        old_bw = float(s.get("explore_metrics", {}).get("explore_back_wait_ratio") or 0)
        gains = len(other) > 0 and old_functional == 0 and old_bw >= 0.75
        if gains:
            would_gain += 1
        rows.append(
            {
                "package": pkg,
                "iec": len(elements),
                "nav": len(nav),
                "other": len(other),
                "expand": len(expand),
                "tabs": len(tabs),
                "old_functional_taps": old_functional,
                "old_back_wait_ratio": old_bw,
                "would_gain_candidates_at_start": len(other) > 0,
            }
        )

    print(f"OTHER cohort sessions: {len(other_sessions)}")
    print(f"Analyzed with verified_start.xml: {len(rows)}")
    print(f"Would admit other_cands>0 at launch (verified_start): {sum(1 for r in rows if r['would_gain_candidates_at_start'])}")
    print(
        f"Subset with old functional_taps=0 and back_wait>=0.75 that gain candidates: {would_gain}"
    )
    print()
    print("package,iec,other,expand,old_ft,old_bw,gain_at_start")
    for r in sorted(rows, key=lambda x: (-x["other"], x["package"])):
        print(
            f"{r['package']},{r['iec']},{r['other']},{r['expand']},"
            f"{r['old_functional_taps']},{r['old_back_wait_ratio']:.2f},"
            f"{int(r['would_gain_candidates_at_start'])}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
