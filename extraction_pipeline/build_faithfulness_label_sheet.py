#!/usr/bin/env python3
"""Build human label sheet for faithfulness judge validation."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluate_scenario_level import _load_actions

VALIDATION_SAMPLE: dict[str, list[str]] = {
    "clearly_rich": [
        "ch.protonvpn.android",
        "com.abhijitvalluri.android.fitnotifications",
        "code.name.monkey.retromusic",
        "ch.mydoli.focal",
        "app.fedilab.nitterizemelite",
    ],
    "clearly_stalled_failed": [
        "ch.blinkenlights.android.vanilla",
        "S.N.A.K.E",
        "app.cclauncher",
        "ch.blinkenlights.android.vanillaplug",
        "com.aerotoad.thud",
    ],
    "borderline_thin": [
        "chromahub.rhythm.app",
        "ch.rmy.android.statusbar_tacho",
        "cl.coders.faketraveler",
        "ch.threema.app.libre",
        "ch.hgdev.toposuite",
        "click.dummer.yidkey",
        "com.Sommerlichter.social",
        "ch.famoser.mensa",
        "com.GTP.eveminer",
        "ch.bubendorf.locusaddon.gsakdatabase",
    ],
}


def _purpose(meta: dict[str, Any]) -> str:
    ctx = meta.get("app_context") or {}
    cat = str(ctx.get("category") or "Unknown")
    purpose = str(ctx.get("purpose") or "").strip()
    if purpose in ("", "No description available"):
        purpose = str(ctx.get("app_name") or meta.get("package_name") or "")
    return f"{cat}: {purpose}"[:120]


def _action_summary(actions: list[dict[str, Any]], n: int = 5) -> str:
  if not actions:
      return "No actions recorded."
  lines: list[str] = []
  picks = []
  if len(actions) <= n:
      picks = actions
  else:
      idxs = [0, len(actions) // 4, len(actions) // 2, 3 * len(actions) // 4, len(actions) - 1]
      picks = [actions[i] for i in idxs]
  for act in picks:
      pa = act.get("parsed_action") or {}
      at = pa.get("action_type") or act.get("execution_kind") or "?"
      phase = act.get("pipeline_phase") or "?"
      ok = act.get("action_success")
      target = pa.get("target_content_desc") or pa.get("target_resource_id") or pa.get("target_text") or ""
      target = str(target).split("/")[-1][:40]
      reason = str(pa.get("reason") or "")[:30]
      lines.append(
          f"step{act.get('step')}[{phase}] {at} ok={ok} target={target or '-'} reason={reason or '-'}"
      )
  return " | ".join(lines)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    index = list(csv.DictReader((root / "logs/bulk_llm_benign_v6/dataset_index.csv").open(encoding="utf-8")))
    by_pkg = {r["package_name"]: r for r in index if r.get("status") == "success"}

    rows_out: list[dict[str, str]] = []
    for stratum, packages in VALIDATION_SAMPLE.items():
        for pkg in packages:
            row = by_pkg[pkg]
            base = Path(row["metadata_path"]).parent
            meta = json.loads(Path(row["metadata_path"]).read_text(encoding="utf-8"))
            actions = _load_actions(base / f"{pkg}_llm_actions.jsonl")
            screens = len(
                {a.get("screen_hash") for a in actions if a.get("screen_hash")}
                | {a.get("screen_hash_after") for a in actions if a.get("screen_hash_after")}
            )
            rows_out.append(
                {
                    "stratum": stratum,
                    "package": pkg,
                    "session_id": row.get("session_id") or meta.get("session_id") or "",
                    "artifact_path": str(base),
                    "app_purpose": _purpose(meta),
                    "distinct_screens": str(screens),
                    "sim_status": str(meta.get("llm_simulation_status") or row.get("llm_simulation_status") or ""),
                    "duration_sec": str(round(float(meta.get("elapsed_sec") or meta.get("duration_sec") or 0), 1)),
                    "action_count": str(len(actions)),
                    "action_summary": _action_summary(actions),
                    "human_label": "",
                }
            )

    out = root / "experiment/faithfulness_human_label_sheet.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
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
        "action_summary",
        "human_label",
    ]
    with out.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows_out)
    print(f"wrote {out} ({len(rows_out)} sessions)")


if __name__ == "__main__":
    main()
