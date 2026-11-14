"""Parquet I/O for the events table."""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from gaphunter.schema import EVENTS_SCHEMA


def dedupe_and_sort(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop duplicate (channel, record_id) pairs and order by time, then record id."""
    seen: set[tuple[str, int]] = set()
    unique: list[dict[str, Any]] = []
    for row in rows:
        key = (row["channel"], row["record_id"])
        if key not in seen:
            seen.add(key)
            unique.append(row)
    unique.sort(key=lambda r: (r["ts_utc"], r["channel"], r["record_id"]))
    return unique


def write_events(rows: list[dict[str, Any]], path: Path) -> int:
    """Write rows with the canonical schema (atomic replace). Returns the row count."""
    path.parent.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist(rows, schema=EVENTS_SCHEMA)
    tmp = path.with_suffix(path.suffix + ".tmp")
    pq.write_table(table, tmp, compression="zstd")
    os.replace(tmp, path)
    return int(table.num_rows)


def read_events(path: Path) -> pa.Table:
    return pq.read_table(path, schema=EVENTS_SCHEMA)


def write_events_frame(frame: pd.DataFrame, path: Path) -> int:
    """Write a pandas frame with the canonical schema (atomic replace)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pandas(frame, schema=EVENTS_SCHEMA, preserve_index=False)
    tmp = path.with_suffix(path.suffix + ".tmp")
    pq.write_table(table, tmp, compression="zstd")
    os.replace(tmp, path)
    return int(table.num_rows)
