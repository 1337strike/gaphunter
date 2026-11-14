"""Arrow schemas for the Parquet tables. One place, so every module agrees on types."""

from __future__ import annotations

import pyarrow as pa

_TS = pa.timestamp("us", tz="UTC")

# One row per Windows event-log record, normalised across channels.
EVENTS_SCHEMA = pa.schema(
    [
        # identity
        pa.field("execution_id", pa.string(), nullable=False),
        pa.field("host", pa.string()),
        pa.field("channel", pa.string(), nullable=False),
        pa.field("provider", pa.string()),
        pa.field("event_id", pa.int32(), nullable=False),
        pa.field("record_id", pa.int64(), nullable=False),
        pa.field("ts_utc", _TS, nullable=False),
        # acting process
        pa.field("process_guid", pa.string()),
        pa.field("pid", pa.int64()),
        pa.field("image", pa.string()),
        pa.field("command_line", pa.string()),
        pa.field("parent_process_guid", pa.string()),
        pa.field("parent_pid", pa.int64()),
        pa.field("parent_image", pa.string()),
        pa.field("parent_command_line", pa.string()),
        pa.field("user", pa.string()),
        pa.field("integrity_level", pa.string()),
        # targets
        pa.field("target_image", pa.string()),
        pa.field("target_filename", pa.string()),
        pa.field("target_object", pa.string()),
        pa.field("dest_ip", pa.string()),
        pa.field("dest_port", pa.int32()),
        pa.field("script_block_text", pa.string()),
        # audit only: sysmon-modular puts ATT&CK IDs here, so it must never be a feature
        pa.field("rule_name", pa.string()),
        # every EventData field as a JSON object, for anything not promoted to a column
        pa.field("raw", pa.string()),
        # filled by the labeler (phase 2)
        pa.field("label", pa.bool_()),
        pa.field("technique_id", pa.string()),
        pa.field("label_reason", pa.string()),
    ]
)

# One row per collection session (an emulation run or a slice of benign baseline).
EXECUTIONS_SCHEMA = pa.schema(
    [
        pa.field("execution_id", pa.string(), nullable=False),
        pa.field("kind", pa.string(), nullable=False),  # "attack" | "baseline"
        pa.field("technique_id", pa.string()),
        pa.field("test_number", pa.int32()),
        pa.field("test_guid", pa.string()),
        pa.field("repetition", pa.int32()),
        pa.field("start_utc", _TS, nullable=False),
        pa.field("end_utc", _TS),
        pa.field("exit_code", pa.int32()),
        pa.field("executor_root_pid", pa.int64()),
        # PIDs of GapHunter's own remote-control processes inside the window
        pa.field("control_pids", pa.list_(pa.int64())),
        pa.field("snapshot", pa.string()),
        pa.field("reverted", pa.bool_()),
        pa.field("status", pa.string(), nullable=False),  # "open" | "ended" | "collected"
        pa.field("n_events", pa.int64()),
        pa.field("notes", pa.string()),
    ]
)

# One row per rule alert (Hayabusa output, normalised).
ALERTS_SCHEMA = pa.schema(
    [
        pa.field("execution_id", pa.string(), nullable=False),
        pa.field("ts_utc", _TS, nullable=False),
        pa.field("rule_title", pa.string()),
        pa.field("rule_file", pa.string()),
        pa.field("level", pa.string()),
        pa.field("level_num", pa.int32(), nullable=False),
        pa.field("channel", pa.string()),
        pa.field("event_id", pa.int32()),
        pa.field("record_id", pa.int64()),
        pa.field("mitre_tactics", pa.list_(pa.string())),
        pa.field("mitre_tags", pa.list_(pa.string())),
    ]
)

# Columns of windows.parquet that are not features. Feature columns start with "f_".
WINDOW_META_COLUMNS: tuple[str, ...] = (
    "window_id",
    "execution_id",
    "source",
    "window_start",
    "window_end",
    "label",
    "technique_id",
    "n_events",
    "n_malicious_events",
    "first_malicious_ts",
)

EVENT_COLUMNS: tuple[str, ...] = tuple(EVENTS_SCHEMA.names)
