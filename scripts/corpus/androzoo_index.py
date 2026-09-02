"""AndroZoo index helpers — parse latest.csv.gz by header name (never by column index)."""

from __future__ import annotations

import csv
import gzip
import io
import sys
from typing import Iterator
from urllib.request import urlopen
from pathlib import Path

DEFAULT_INDEX_URL = "https://androzoo.uni.lu/static/lists/latest.csv.gz"

# Observed 2026-07-27 from live latest.csv.gz first line (do not assume without verify).
OBSERVED_HEADER = (
    "sha256",
    "sha1",
    "md5",
    "dex_date",
    "apk_size",
    "pkg_name",
    "vercode",
    "vt_detection",
    "vt_scan_date",
    "dex_size",
    "markets",
)

REQUIRED_FIELDS = OBSERVED_HEADER


def open_index(path_or_url: str):
    """Open local .csv.gz path or https URL as text CSV stream."""
    if path_or_url.startswith(("http://", "https://")):
        resp = urlopen(path_or_url, timeout=120)  # noqa: S310 — fixed AndroZoo URL
        raw = resp
        gz = gzip.GzipFile(fileobj=raw)
    else:
        src = Path(path_or_url)
        if src.suffix == ".gz":
            gz = gzip.open(path_or_url, "rb")
        else:
            gz = src.open("rb")
    text = io.TextIOWrapper(gz, encoding="utf-8", errors="replace", newline="")
    return text


def read_header(path_or_url: str) -> list[str]:
    with open_index(path_or_url) as fh:
        first = fh.readline().strip()
    if not first:
        raise ValueError("empty index")
    fields = [c.strip() for c in first.split(",")]
    return fields


def iter_rows(
    path_or_url: str,
    *,
    skip_bogus: bool = True,
    progress_every: int = 0,
    max_rows: int = 0,
) -> Iterator[dict[str, str]]:
    """Yield dict rows keyed by header names. First line must be header."""
    with open_index(path_or_url) as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise ValueError("missing header row")
        header = [h.strip() for h in reader.fieldnames]
        missing = [f for f in REQUIRED_FIELDS if f not in header]
        if missing:
            raise ValueError(f"unexpected index header {header!r}; missing {missing}")
        for i, row in enumerate(reader, start=1):
            if max_rows and i > max_rows:
                break
            if progress_every and i % progress_every == 0:
                print(f"[androzoo_index] rows={i}", file=sys.stderr)
            pkg = (row.get("pkg_name") or "").strip()
            if skip_bogus and ",snaggamea" in pkg:
                continue
            yield {k: (row.get(k) or "").strip() for k in header}


def iter_rows_resilient(
    path_or_url: str,
    *,
    skip_bogus: bool = True,
    progress_every: int = 0,
    max_rows: int = 0,
    max_attempts: int = 5,
) -> Iterator[dict[str, str]]:
    """Stream rows; on HTTP reset retry (metadata URL only). Local paths pass through."""
    if not str(path_or_url).startswith(("http://", "https://")):
        yield from iter_rows(path_or_url, skip_bogus=skip_bogus, progress_every=progress_every, max_rows=max_rows)
        return
    import time

    seen = 0
    for attempt in range(1, max_attempts + 1):
        try:
            for row in iter_rows(path_or_url, skip_bogus=skip_bogus, progress_every=progress_every, max_rows=max_rows):
                seen += 1
                yield row
            return
        except (ConnectionResetError, TimeoutError, OSError) as exc:
            print(f"[androzoo_index] stream attempt {attempt} failed after {seen} rows: {exc}", file=sys.stderr)
            if attempt >= max_attempts:
                raise
            time.sleep(min(30, 5 * attempt))


def inspect_header(path_or_url: str) -> dict:
    header = read_header(path_or_url)
    return {
        "source": path_or_url,
        "header_fields": header,
        "field_count": len(header),
        "matches_observed_2026_07_27": header == list(OBSERVED_HEADER),
        "family_columns_present": [c for c in header if "family" in c.lower() or "avclass" in c.lower()],
    }
