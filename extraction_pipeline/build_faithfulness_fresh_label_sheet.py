#!/usr/bin/env python3
"""Build fresh human label sheet for faithfulness judge validation (Step 7.9-PREP)."""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_faithfulness_label_sheet import VALIDATION_SAMPLE, _action_summary, _purpose
from evaluate_scenario_level import _load_actions
from quality_rules import _explore_metrics

FRESH_STRATA_TARGETS = {
    "clearly_rich": 5,
    "clearly_stalled_failed": 5,
    "borderline_thin": 8,
}
FRESH_TOTAL_MIN = 15
FRESH_TOTAL_MAX = 20

# Borderline diversity quotas within the fresh set (never overlap VALIDATION_SAMPLE).
BORDERLINE_QUOTAS: list[tuple[str, str, int]] = [
    ("failed:partial:foreground_mismatch", "fg_mismatch_engaged", 2),
    ("failed:bad_handoff", "bad_handoff_engaged", 1),
    ("failed:bad_handoff", "bad_handoff_flail", 1),
    ("failed:ux_quality_gate", "uxq_engaged", 2),
    ("failed:ux_quality_gate", "uxq_flail", 1),
    ("success", "success_moderate", 1),
    ("failed:skip:login_required", "login_gate", 1),
    ("failed:partial:agent_stuck", "agent_stuck", 1),
]


def _validation_packages() -> set[str]:
    out: set[str] = set()
    for packages in VALIDATION_SAMPLE.values():
        out.update(packages)
    return out


def _distinct_screens(actions: list[dict[str, Any]]) -> int:
    return len(
        {a.get("screen_hash") for a in actions if a.get("screen_hash")}
        | {a.get("screen_hash_after") for a in actions if a.get("screen_hash_after")}
    )


def _borderline_subtype(sim: str, explore: dict[str, Any]) -> str:
    ft = int(explore.get("explore_functional_tap_count") or 0)
    bw = float(explore.get("explore_back_wait_ratio") or 0)
    if sim == "failed:partial:foreground_mismatch" and ft >= 5:
        return "fg_mismatch_engaged"
    if sim == "failed:bad_handoff" and ft >= 3:
        return "bad_handoff_engaged"
    if sim == "failed:bad_handoff" and bw >= 0.5:
        return "bad_handoff_flail"
    if sim == "failed:ux_quality_gate" and ft >= 5:
        return "uxq_engaged"
    if sim == "failed:ux_quality_gate":
        return "uxq_flail"
    if sim == "success" and ft < 10:
        return "success_moderate"
    if sim == "failed:skip:login_required":
        return "login_gate"
    if sim == "failed:partial:agent_stuck":
        return "agent_stuck"
    return "other"


def _stratum_hint(sim: str, explore: dict[str, Any], screens: int, actions_n: int) -> str:
    ft = int(explore.get("explore_functional_tap_count") or 0)
    bw = float(explore.get("explore_back_wait_ratio") or 0)
    if sim == "success" and ft >= 10 and screens >= 5:
        return "clearly_rich"
    if sim in {"failed:partial:agent_stuck", "failed:skip:login_required"}:
        return "clearly_stalled_failed" if sim == "failed:partial:agent_stuck" else "borderline_thin"
    if sim == "failed:bad_handoff" and ft <= 2 and bw >= 0.5:
        return "clearly_stalled_failed"
    if sim == "failed:partial:foreground_mismatch" and ft >= 5:
        return "borderline_thin"
    if sim == "failed:ux_quality_gate":
        return "borderline_thin"
    if sim == "success" and ft >= 3:
        return "borderline_thin"
    if bw >= 0.6 and ft <= 2:
        return "clearly_stalled_failed"
    return "borderline_thin"


def _rank_key(row: dict[str, Any]) -> tuple:
    explore = row["_explore"]
    return (
        int(explore.get("explore_functional_tap_count") or 0),
        _distinct_screens(row["_actions"]),
        float(row.get("_duration") or 0),
    )


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    exclude = _validation_packages()
    index = list(csv.DictReader((root / "logs/bulk_llm_benign_v6/dataset_index.csv").open(encoding="utf-8")))

    candidates: list[dict[str, Any]] = []
    for row in index:
        if row.get("status") != "success":
            continue
        pkg = row["package_name"]
        if pkg in exclude:
            continue
        base = Path(row["metadata_path"]).parent
        meta = json.loads(Path(row["metadata_path"]).read_text(encoding="utf-8"))
        actions = _load_actions(base / f"{pkg}_llm_actions.jsonl")
        explore = _explore_metrics(actions)
        sim = str(meta.get("llm_simulation_status") or row.get("llm_simulation_status") or "")
        screens = _distinct_screens(actions)
        stratum = _stratum_hint(sim, explore, screens, len(actions))
        candidates.append(
            {
                **row,
                "_actions": actions,
                "_explore": explore,
                "_duration": float(meta.get("elapsed_sec") or meta.get("duration_sec") or 0),
                "_stratum": stratum,
                "_screens": screens,
                "_meta": meta,
                "_base": base,
            }
        )

    picked: list[dict[str, Any]] = []
    picked_pkgs: set[str] = set()
    by_stratum: dict[str, list[dict[str, Any]]] = {k: [] for k in FRESH_STRATA_TARGETS}
    by_borderline: dict[str, list[dict[str, Any]]] = {}
    for c in candidates:
        by_stratum[c["_stratum"]].append(c)
        if c["_stratum"] == "borderline_thin":
            subtype = _borderline_subtype(
                str(c["_meta"].get("llm_simulation_status") or c.get("llm_simulation_status") or ""),
                c["_explore"],
            )
            c["_borderline_subtype"] = subtype
            by_borderline.setdefault(subtype, []).append(c)

    for stratum in ("clearly_rich", "clearly_stalled_failed"):
        target_n = FRESH_STRATA_TARGETS[stratum]
        pool = sorted(by_stratum.get(stratum, []), key=_rank_key, reverse=(stratum == "clearly_rich"))
        for c in pool:
            if len([p for p in picked if p["_stratum"] == stratum]) >= target_n:
                break
            if c["package_name"] in picked_pkgs:
                continue
            picked.append(c)
            picked_pkgs.add(c["package_name"])

    for _sim, subtype, quota in BORDERLINE_QUOTAS:
        pool = sorted(by_borderline.get(subtype, []), key=_rank_key, reverse=True)
        n = 0
        for c in pool:
            if c["package_name"] in picked_pkgs:
                continue
            picked.append(c)
            picked_pkgs.add(c["package_name"])
            n += 1
            if n >= quota:
                break

    borderline_n = sum(1 for p in picked if p["_stratum"] == "borderline_thin")
    if borderline_n < FRESH_STRATA_TARGETS["borderline_thin"]:
        for c in sorted(by_stratum.get("borderline_thin", []), key=_rank_key, reverse=True):
            if c["package_name"] in picked_pkgs:
                continue
            picked.append(c)
            picked_pkgs.add(c["package_name"])
            borderline_n += 1
            if borderline_n >= FRESH_STRATA_TARGETS["borderline_thin"]:
                break

    if len(picked) < FRESH_TOTAL_MIN:
        for c in sorted(candidates, key=_rank_key, reverse=True):
            if c["package_name"] in picked_pkgs:
                continue
            picked.append(c)
            picked_pkgs.add(c["package_name"])
            if len(picked) >= FRESH_TOTAL_MIN:
                break

    picked = picked[:FRESH_TOTAL_MAX]

    overlap = picked_pkgs & exclude
    if overlap:
        raise SystemExit(f"fresh set overlaps validation packages: {sorted(overlap)}")

    rows_out: list[dict[str, str]] = []
    for c in picked:
        pkg = c["package_name"]
        explore = c["_explore"]
        rows_out.append(
            {
                "stratum": c["_stratum"],
                "package": pkg,
                "session_id": c.get("session_id") or c["_meta"].get("session_id") or "",
                "artifact_path": str(c["_base"]),
                "app_purpose": _purpose(c["_meta"]),
                "distinct_screens": str(c["_screens"]),
                "sim_status": str(c["_meta"].get("llm_simulation_status") or c.get("llm_simulation_status") or ""),
                "duration_sec": str(round(c["_duration"], 1)),
                "action_count": str(len(c["_actions"])),
                "explore_functional_tap_count": str(explore.get("explore_functional_tap_count", 0)),
                "explore_back_wait_ratio": str(explore.get("explore_back_wait_ratio", 0)),
                "action_summary": _action_summary(c["_actions"]),
                "human_label": "",
            }
        )

    out = root / "experiment/faithfulness_fresh_label_sheet.csv"
    fields = [
        "stratum",
        "package",
        "session_id",
        "artifact_path",
        "app_purpose",
        "distinct_screens",
        "sim_status",
        "duration_sec",
        "action_count",
        "explore_functional_tap_count",
        "explore_back_wait_ratio",
        "action_summary",
        "human_label",
    ]
    with out.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows_out)

    strata_counts = {s: sum(1 for r in rows_out if r["stratum"] == s) for s in FRESH_STRATA_TARGETS}
    borderline_subtypes = Counter(
        _borderline_subtype(r["sim_status"], {"explore_functional_tap_count": int(r["explore_functional_tap_count"]), "explore_back_wait_ratio": float(r["explore_back_wait_ratio"])})
        for r in rows_out
        if r["stratum"] == "borderline_thin"
    )
    print(f"wrote {out} ({len(rows_out)} sessions)")
    print(f"validation overlap: {len(overlap)} packages (must be 0)")
    print(f"excluded validation packages: {len(exclude)}")
    print(f"strata: {strata_counts}")
    print(f"borderline subtypes: {dict(borderline_subtypes)}")
    print("packages:")
    for r in rows_out:
        print(f"  [{r['stratum']}] {r['package']} sim={r['sim_status']} ft={r['explore_functional_tap_count']} bw={r['explore_back_wait_ratio']}")


if __name__ == "__main__":
    main()
