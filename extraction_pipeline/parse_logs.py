#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
from collections import Counter
from pathlib import Path

import pandas as pd


def configure_logging() -> None:
    log_file = Path("pipeline.log")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_file, encoding="utf-8"),
        ],
    )


def parse_frida_jsonl(frida_log: Path) -> tuple[list[dict], dict]:
    events: list[dict] = []
    malformed = 0
    non_event = 0
    total = 0

    with frida_log.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                start = line.find("{")
                end = line.rfind("}")
                if start != -1 and end != -1 and end > start:
                    try:
                        obj = json.loads(line[start : end + 1])
                    except json.JSONDecodeError:
                        malformed += 1
                        continue
                else:
                    malformed += 1
                    continue

            if obj.get("type", "event") != "event":
                non_event += 1
                continue

            timestamp = obj.get("timestamp")
            api = obj.get("api", "")
            category = obj.get("category", "")
            args = obj.get("args", {})

            if timestamp is None or api == "" or category == "":
                malformed += 1
                continue

            events.append(
                {
                    "timestamp": int(timestamp),
                    "api": str(api),
                    "category": str(category),
                    "args_str": json.dumps(args, ensure_ascii=False, sort_keys=True),
                }
            )

    low_signal_categories = {"reflection", "lifecycle", "unknown"}
    meaningful_events = [event for event in events if event["category"] not in low_signal_categories]
    quality = {
        "total_lines": total,
        "valid_events": len(events),
        "meaningful_events": len(meaningful_events),
        "malformed_lines": malformed,
        "non_event_lines": non_event,
        "valid_ratio": (len(events) / total) if total else 0.0,
        "meaningful_ratio": (len(meaningful_events) / len(events)) if events else 0.0,
        "unique_categories": len({event["category"] for event in events}),
        "meaningful_categories": len({event["category"] for event in meaningful_events}),
    }
    return events, quality


def write_csv(events: list[dict], output: Path) -> None:
    first_ts = events[0]["timestamp"]
    records = [
        {
            "relative_time": int(e["timestamp"] - first_ts),
            "category": e["category"],
            "api": e["api"],
            "args_str": e["args_str"],
        }
        for e in events
    ]
    pd.DataFrame(records, columns=["relative_time", "category", "api", "args_str"]).to_csv(output, index=False)


def print_summary(events: list[dict]) -> None:
    if not events:
        logging.warning("No valid events found in log.")
        return
    category_counter = Counter(event["category"] for event in events)
    span_ms = events[-1]["timestamp"] - events[0]["timestamp"]
    logging.info("Total events: %d", len(events))
    logging.info("Time span: %d ms", span_ms)
    for category, count in sorted(category_counter.items(), key=lambda x: (-x[1], x[0])):
        logging.info("category=%s count=%d", category, count)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Parse Frida JSONL log into CSV.")
    parser.add_argument("--frida-log", required=True, help="Path to Frida JSONL file")
    parser.add_argument("--output", required=True, help="Output CSV path")
    parser.add_argument("--quality-output", default="", help="Optional JSON path for parse quality metrics")
    return parser.parse_args()


def main() -> None:
    configure_logging()
    args = parse_args()
    frida_log = Path(args.frida_log).resolve()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    if not frida_log.exists() or frida_log.stat().st_size == 0:
        pd.DataFrame(columns=["relative_time", "category", "api", "args_str"]).to_csv(output, index=False)
        return

    events, quality = parse_frida_jsonl(frida_log)
    quality_path = Path(args.quality_output).resolve() if args.quality_output else output.with_suffix(".quality.json")
    quality_path.write_text(json.dumps(quality, ensure_ascii=False, indent=2), encoding="utf-8")

    if not events:
        pd.DataFrame(columns=["relative_time", "category", "api", "args_str"]).to_csv(output, index=False)
        return

    write_csv(events, output)
    print_summary(events)


if __name__ == "__main__":
    main()
