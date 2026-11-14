from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from gaphunter.collector.parse import (
    flatten_event_data,
    normalize_record,
    normalize_records,
    parse_evtx,
)
from gaphunter.collector.store import dedupe_and_sort, read_events, write_events
from gaphunter.errors import CollectError
from gaphunter.schema import EVENT_COLUMNS, EVENTS_SCHEMA
from gaphunter.timeutil import parse_utc, to_systemtime


def _row(records: list[dict[str, Any]], index: int) -> dict[str, Any]:
    row = normalize_record(records[index], execution_id="x")
    assert row is not None
    return row


def test_sysmon_process_create(records: list[dict[str, Any]]) -> None:
    row = _row(records, 0)
    assert set(row) == set(EVENT_COLUMNS)
    assert row["channel"] == "sysmon"
    assert row["provider"] == "Microsoft-Windows-Sysmon"
    assert row["event_id"] == 1
    assert row["record_id"] == 1001
    assert row["host"] == "GH-WIN10"
    # 7 fractional digits are truncated to microseconds
    assert row["ts_utc"] == datetime(2026, 11, 14, 2, 0, 1, 123456, tzinfo=UTC)
    assert row["process_guid"] == "{11111111-0000-0000-0000-000000000001}"
    assert row["pid"] == 4321
    assert row["image"].endswith("whoami.exe")
    assert row["command_line"] == "whoami /all"
    assert row["parent_pid"] == 4000
    assert row["parent_image"].endswith("cmd.exe")
    assert row["parent_command_line"] == "cmd.exe /c whoami /all"
    assert row["user"] == "GH-WIN10\\labadmin"
    assert row["integrity_level"] == "High"
    assert row["rule_name"].startswith("technique_id=T1033")
    assert '"Hashes": "SHA256=AAAA"' in row["raw"]
    assert row["label"] is None and row["technique_id"] is None


def test_sysmon_network_and_dash_is_null(records: list[dict[str, Any]]) -> None:
    row = _row(records, 1)
    assert row["event_id"] == 3
    assert row["dest_ip"] == "10.66.66.1"
    assert row["dest_port"] == 53
    assert row["rule_name"] is None  # "-" means no rule name


def test_sysmon_process_access_uses_source_fields(records: list[dict[str, Any]]) -> None:
    row = _row(records, 2)
    assert row["process_guid"] == "{11111111-0000-0000-0000-000000000003}"
    assert row["pid"] == 6000
    assert row["image"].endswith("taskmgr.exe")
    assert row["target_image"].endswith("notepad.exe")


def test_sysmon_registry(records: list[dict[str, Any]]) -> None:
    row = _row(records, 3)
    assert row["target_object"] == "HKU\\S-1-5-21-1\\Software\\Example\\Setting"


def test_security_4688_hex_pids_and_integrity(records: list[dict[str, Any]]) -> None:
    row = _row(records, 4)
    assert row["channel"] == "security"
    assert row["pid"] == 0x10E1
    assert row["parent_pid"] == 0xFA0
    assert row["image"].endswith("whoami.exe")
    assert row["command_line"] == "whoami /all"
    assert row["user"] == "GH-WIN10\\labadmin"
    assert row["integrity_level"] == "High"
    assert row["process_guid"] is None  # only Sysmon has GUIDs; phase 2 joins on pid


def test_powershell_script_block(records: list[dict[str, Any]]) -> None:
    row = _row(records, 5)
    assert row["channel"] == "powershell"
    assert row["pid"] == 7000  # from System/Execution
    assert row["script_block_text"] == "Get-ChildItem C:\\Users"
    assert row["target_filename"] is None  # empty Path


def test_powershell_4103_event_id_object_and_host_application(
    records: list[dict[str, Any]],
) -> None:
    row = _row(records, 6)
    assert row["event_id"] == 4103
    assert row["command_line"] == "powershell.exe -NoProfile -Command Get-Date"
    assert row["script_block_text"].startswith("CommandInvocation")


def test_malformed_record_is_dropped(records: list[dict[str, Any]]) -> None:
    assert normalize_record(records[7], execution_id="x") is None
    assert normalize_record({}, execution_id="x") is None
    assert normalize_record({"Event": {"System": "nope"}}, execution_id="x") is None
    assert len(normalize_records(records, execution_id="x")) == 7


def test_flatten_user_data_and_unnamed_data() -> None:
    event = {"UserData": {"#attributes": {}, "LogFileCleared": {"SubjectUserName": "bob"}}}
    assert flatten_event_data(event) == {"SubjectUserName": "bob"}
    event2 = {"EventData": {"Data": {"#text": ["a", "b"]}, "#attributes": {"Name": "x"}}}
    assert flatten_event_data(event2) == {"Data": "a\nb"}
    assert flatten_event_data({"EventData": None}) == {}


def test_parquet_roundtrip_keeps_schema(records: list[dict[str, Any]], tmp_path: Path) -> None:
    rows = normalize_records(records, execution_id="T1033-1-r1")
    rows.append(dict(rows[0]))  # duplicate record
    unique = dedupe_and_sort(rows)
    assert len(unique) == 7
    assert [r["ts_utc"] for r in unique] == sorted(r["ts_utc"] for r in unique)

    out = tmp_path / "events" / "e.parquet"
    assert write_events(unique, out) == 7
    table = read_events(out)
    assert table.schema.equals(EVENTS_SCHEMA)
    assert table.column("execution_id").to_pylist() == ["T1033-1-r1"] * 7
    assert table.column("ts_utc").to_pylist()[0].tzinfo is not None


def test_write_events_empty(tmp_path: Path) -> None:
    out = tmp_path / "empty.parquet"
    assert write_events([], out) == 0
    assert read_events(out).num_rows == 0


def test_parse_evtx_rejects_non_evtx(tmp_path: Path) -> None:
    bogus = tmp_path / "not.evtx"
    bogus.write_bytes(b"this is not an event log")
    with pytest.raises(CollectError):
        parse_evtx(bogus, execution_id="x")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2026-11-14T02:00:01.1234567Z", datetime(2026, 11, 14, 2, 0, 1, 123456, tzinfo=UTC)),
        ("2026-11-14T02:00:01Z", datetime(2026, 11, 14, 2, 0, 1, tzinfo=UTC)),
        ("2026-11-14 02:00:01.120", datetime(2026, 11, 14, 2, 0, 1, 120000, tzinfo=UTC)),
        ("2026-11-14T09:00:01+07:00", datetime(2026, 11, 14, 2, 0, 1, tzinfo=UTC)),
    ],
)
def test_parse_utc(text: str, expected: datetime) -> None:
    assert parse_utc(text) == expected


def test_parse_utc_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        parse_utc("yesterday")


def test_to_systemtime() -> None:
    value = datetime(2026, 11, 14, 2, 0, 1, 987654, tzinfo=UTC)
    assert to_systemtime(value) == "2026-11-14T02:00:01.987Z"
