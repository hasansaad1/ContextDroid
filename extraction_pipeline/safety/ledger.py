"""Append-only run ledger for ABRG / ContextDroid corpus collection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

REQUIRED_FIELDS: tuple[str, ...] = (
    "run_id",
    "utc_start",
    "utc_end",
    "sample_sha256",
    "tier",
    "avd_name",
    "avd_fingerprint",
    "snapshot_id",
    "config_hash",
    "hooks_version",
    "network_mode",
    "adb_device_serial",
    "adb_device_count",
    "outcome",
    "trace_path",
    "notes",
)

DEFAULT_LEDGER_PATH = Path(__file__).resolve().parents[2] / "logs" / "ledger" / "run_ledger.jsonl"


class LedgerValidationError(ValueError):
    """Raised when a ledger record fails schema validation."""


def validate_ledger(record: Mapping[str, Any]) -> None:
    """Validate one ledger record. Raises LedgerValidationError on failure."""
    if not isinstance(record, Mapping):
        raise LedgerValidationError("record must be a mapping")
    missing = [f for f in REQUIRED_FIELDS if f not in record]
    if missing:
        raise LedgerValidationError(f"missing required field(s): {', '.join(missing)}")
    if record.get("sample_sha256") in (None, ""):
        raise LedgerValidationError("sample_sha256 must be a non-empty string")
    if not isinstance(record["sample_sha256"], str):
        raise LedgerValidationError("sample_sha256 must be a string")
    count = record.get("adb_device_count")
    if not isinstance(count, int) or isinstance(count, bool):
        raise LedgerValidationError("adb_device_count must be an int")


def append_run(
    record: Mapping[str, Any],
    *,
    ledger_path: Path | None = None,
) -> Path:
    """Validate and append one JSON object to the ledger. Returns the ledger path."""
    validate_ledger(record)
    path = Path(ledger_path) if ledger_path is not None else DEFAULT_LEDGER_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(dict(record), sort_keys=True, ensure_ascii=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    return path
