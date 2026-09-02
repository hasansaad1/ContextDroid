#!/usr/bin/env python3
"""Score a Frida trace for activation / malware-signal (plan 5.4).

Outputs: activated | not_activated | inconclusive with evidence.
Benign utilities should land not_activated on the malware-signal axis.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "extraction_pipeline"))

LOW_SIGNAL = {"reflection", "lifecycle", "unknown"}
FRAMEWORK_ARTIFACT_APIS = {"hook_loaded", "Method.invoke"}
MALWARE_SIGNAL_CATEGORIES = frozenset({"sms", "telephony", "dynamic_code_loading"})

# Benign quality bar from plan §5.4 / SAFETY.md.
EVENT_TARGET = 500
HOOK_COVERAGE_RATIO_TARGET = 0.70  # unique fired APIs / hooked API count


def _hooked_api_count(hook_script: Path | None = None) -> int:
    path = hook_script or (REPO_ROOT / "frida_scripts" / "hook_apis.js")
    if not path.is_file():
        return 58  # SAFETY.md documented count
    text = path.read_text(encoding="utf-8", errors="ignore")
    return len(set(re.findall(r'logEvent\(\s*"([^"]+)"', text))) or 58


def load_frida_events(trace_path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with trace_path.open(encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") != "event":
                continue
            events.append(obj)
    return events


def score_trace(
    trace_path: Path,
    *,
    hooked_api_count: int | None = None,
) -> dict[str, Any]:
    events = load_frida_events(trace_path)
    categories: set[str] = set()
    hooks: set[str] = set()
    meaningful = 0
    malware_signal_hits: dict[str, int] = {c: 0 for c in sorted(MALWARE_SIGNAL_CATEGORIES)}

    for obj in events:
        cat = obj.get("category")
        api = obj.get("api")
        if isinstance(api, str) and api and api not in FRAMEWORK_ARTIFACT_APIS:
            hooks.add(api)
        if isinstance(cat, str) and cat:
            categories.add(cat)
            if cat not in LOW_SIGNAL and (
                not isinstance(api, str) or api not in FRAMEWORK_ARTIFACT_APIS
            ):
                meaningful += 1
            if cat in MALWARE_SIGNAL_CATEGORIES:
                malware_signal_hits[cat] += 1

    hooked = hooked_api_count if hooked_api_count is not None else _hooked_api_count()
    hook_coverage = len(hooks)
    hook_coverage_ratio = (hook_coverage / hooked) if hooked else 0.0
    event_count = len(events)

    # Overall activation (collection quality bar).
    meets_events = event_count >= EVENT_TARGET
    meets_hooks = hook_coverage_ratio >= HOOK_COVERAGE_RATIO_TARGET
    if meets_events and meets_hooks:
        overall = "activated"
    elif not meets_events and not meets_hooks:
        overall = "not_activated"
    else:
        overall = "inconclusive"

    # Malware-signal axis: any of sms/telephony/dynamic_code_loading.
    malware_signal_total = sum(malware_signal_hits.values())
    if malware_signal_total > 0:
        malware_axis = "activated"
    else:
        malware_axis = "not_activated"

    return {
        "trace_path": str(trace_path),
        "overall": overall,
        "malware_signal_axis": malware_axis,
        "evidence": {
            "event_count": event_count,
            "meaningful_event_count": meaningful,
            "hook_coverage": hook_coverage,
            "hooked_api_count": hooked,
            "hook_coverage_ratio": round(hook_coverage_ratio, 4),
            "event_target": EVENT_TARGET,
            "hook_coverage_ratio_target": HOOK_COVERAGE_RATIO_TARGET,
            "categories": sorted(categories),
            "malware_signal_hits": malware_signal_hits,
            "malware_signal_total": malware_signal_total,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate activation from a Frida JSONL trace")
    parser.add_argument("--trace", type=Path, required=True, help="Path to *_frida.jsonl")
    parser.add_argument(
        "--expect-malware-axis",
        choices=("activated", "not_activated"),
        default=None,
        help="Optional assertion on malware-signal axis (for canary/benign calibration)",
    )
    parser.add_argument("--json", action="store_true", help="Print full JSON result")
    args = parser.parse_args(argv)

    if not args.trace.is_file():
        print(f"VALIDATE_ACTIVATION_FAIL missing_trace={args.trace}", file=sys.stderr)
        return 2

    result = score_trace(args.trace)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        ev = result["evidence"]
        print(
            f"VALIDATE_ACTIVATION overall={result['overall']} "
            f"malware_signal_axis={result['malware_signal_axis']} "
            f"events={ev['event_count']} hooks={ev['hook_coverage']}/{ev['hooked_api_count']} "
            f"hook_ratio={ev['hook_coverage_ratio']:.3f} "
            f"malware_hits={ev['malware_signal_total']}"
        )

    if args.expect_malware_axis and result["malware_signal_axis"] != args.expect_malware_axis:
        print(
            f"VALIDATE_ACTIVATION_EXPECT_FAIL expected_malware_axis={args.expect_malware_axis} "
            f"got={result['malware_signal_axis']}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
