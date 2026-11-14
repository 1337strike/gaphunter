"""EVTX -> normalised event rows.

The ``evtx`` package (Rust parser) yields each record as JSON. ``normalize_record`` turns
one such record into a flat dict matching ``schema.EVENTS_SCHEMA``. It is a pure function
so the tests can exercise it with small JSON fixtures, no VM and no .evtx file needed.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

from gaphunter.errors import CollectError
from gaphunter.log import get_logger
from gaphunter.schema import EVENT_COLUMNS
from gaphunter.timeutil import parse_utc

log = get_logger(__name__)

CHANNEL_ALIASES: dict[str, str] = {
    "microsoft-windows-sysmon/operational": "sysmon",
    "security": "security",
    "microsoft-windows-powershell/operational": "powershell",
}

# Mandatory-label SIDs in Security 4688 -> the names Sysmon uses.
_INTEGRITY_SIDS: dict[str, str] = {
    "S-1-16-0": "Untrusted",
    "S-1-16-4096": "Low",
    "S-1-16-8192": "Medium",
    "S-1-16-8448": "Medium",
    "S-1-16-12288": "High",
    "S-1-16-16384": "System",
    "S-1-16-20480": "System",
}

_EMPTY = {"", "-"}


def _scalar(value: Any) -> str | None:
    """Collapse the JSON shapes the parser emits into a plain string (or None)."""
    if value is None:
        return None
    if isinstance(value, Mapping):
        if "#text" in value:
            return _scalar(value["#text"])
        rest = {k: v for k, v in value.items() if k != "#attributes"}
        return json.dumps(rest, sort_keys=True) if rest else None
    if isinstance(value, list):
        parts = [p for p in (_scalar(v) for v in value) if p is not None]
        return "\n".join(parts) if parts else None
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return None if stripped in _EMPTY else stripped


def _int(value: Any) -> int | None:
    """Parse decimal or 0x-prefixed hex (Security events use hex PIDs)."""
    text = _scalar(value)
    if text is None:
        return None
    text = text.strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def flatten_event_data(event: Mapping[str, Any]) -> dict[str, str]:
    """Flatten EventData (or UserData) into ``{field: text}``."""
    data = event.get("EventData")
    if not isinstance(data, Mapping):
        user = event.get("UserData")
        data = None
        if isinstance(user, Mapping):
            # UserData wraps the fields in one provider-specific element.
            for key, inner in user.items():
                if key != "#attributes" and isinstance(inner, Mapping):
                    data = inner
                    break
    if not isinstance(data, Mapping):
        return {}
    flat: dict[str, str] = {}
    for key, value in data.items():
        if key == "#attributes":
            continue
        text = _scalar(value)
        if text is not None:
            flat[str(key)] = text
    return flat


def _first(data: Mapping[str, str], *names: str) -> str | None:
    for name in names:
        value = _clean(data.get(name))
        if value is not None:
            return value
    return None


def _join_user(domain: str | None, name: str | None) -> str | None:
    if name is None:
        return None
    return f"{domain}\\{name}" if domain else name


def _host_application(context_info: str | None) -> str | None:
    """Pull 'Host Application = ...' out of a PowerShell 4103 ContextInfo block."""
    if not context_info:
        return None
    for line in context_info.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip().lower() == "host application":
            return _clean(value)
    return None


def normalize_record(record: Mapping[str, Any], *, execution_id: str) -> dict[str, Any] | None:
    """Normalise one parsed record. Returns None if the record lacks the mandatory fields."""
    event = record.get("Event")
    if not isinstance(event, Mapping):
        return None
    system = event.get("System")
    if not isinstance(system, Mapping):
        return None

    event_id = _int(system.get("EventID"))
    record_id = _int(system.get("EventRecordID"))
    time_created = system.get("TimeCreated")
    system_time = (
        time_created.get("#attributes", {}).get("SystemTime")
        if isinstance(time_created, Mapping)
        else None
    )
    if event_id is None or record_id is None or not system_time:
        return None
    try:
        ts_utc = parse_utc(str(system_time))
    except ValueError:
        return None

    channel_raw = _scalar(system.get("Channel")) or ""
    channel = CHANNEL_ALIASES.get(channel_raw.lower(), channel_raw or "unknown")
    provider_el = system.get("Provider")
    provider = (
        provider_el.get("#attributes", {}).get("Name") if isinstance(provider_el, Mapping) else None
    )
    execution = system.get("Execution")
    system_pid = (
        _int(execution.get("#attributes", {}).get("ProcessID"))
        if isinstance(execution, Mapping)
        else None
    )

    data = flatten_event_data(event)
    row: dict[str, Any] = dict.fromkeys(EVENT_COLUMNS)
    row.update(
        execution_id=execution_id,
        host=_scalar(system.get("Computer")),
        channel=channel,
        provider=provider,
        event_id=event_id,
        record_id=record_id,
        ts_utc=ts_utc,
        raw=json.dumps(data, sort_keys=True, ensure_ascii=False) if data else None,
    )

    if channel == "sysmon":
        row.update(
            # ProcessAccess (10) and CreateRemoteThread (8) name the actor "Source*"
            process_guid=_first(data, "ProcessGuid", "SourceProcessGuid", "SourceProcessGUID"),
            pid=_int(_first(data, "ProcessId", "SourceProcessId")),
            image=_first(data, "Image", "SourceImage"),
            command_line=_first(data, "CommandLine"),
            parent_process_guid=_first(data, "ParentProcessGuid"),
            parent_pid=_int(_first(data, "ParentProcessId")),
            parent_image=_first(data, "ParentImage"),
            parent_command_line=_first(data, "ParentCommandLine"),
            user=_first(data, "User", "SourceUser"),
            integrity_level=_first(data, "IntegrityLevel"),
            target_image=_first(data, "TargetImage"),
            target_filename=_first(data, "TargetFilename", "ImageLoaded"),
            target_object=_first(data, "TargetObject"),
            dest_ip=_first(data, "DestinationIp"),
            dest_port=_int(_first(data, "DestinationPort")),
            rule_name=_first(data, "RuleName"),
        )
    elif channel == "security":
        label = _first(data, "MandatoryLabel")
        if event_id == 4688:  # process creation
            row.update(
                pid=_int(_first(data, "NewProcessId")),
                image=_first(data, "NewProcessName"),
                command_line=_first(data, "CommandLine"),
                parent_pid=_int(_first(data, "ProcessId")),
                parent_image=_first(data, "ParentProcessName"),
            )
        else:
            row.update(
                pid=_int(_first(data, "ProcessId")),
                image=_first(data, "ProcessName"),
            )
        row.update(
            user=_join_user(_first(data, "SubjectDomainName"), _first(data, "SubjectUserName")),
            integrity_level=_INTEGRITY_SIDS.get(label, label) if label else None,
            target_object=_first(data, "ObjectName"),
            dest_ip=_first(data, "DestAddress"),
            dest_port=_int(_first(data, "DestPort")),
        )
    elif channel == "powershell":
        row.update(
            pid=system_pid,
            script_block_text=_first(data, "ScriptBlockText", "Payload"),
            command_line=_host_application(data.get("ContextInfo")),
            target_filename=_first(data, "Path"),
        )
    else:
        row.update(pid=system_pid)
    return row


def iter_evtx_records(path: Path) -> Iterator[Mapping[str, Any]]:
    """Yield parsed records from an .evtx file, skipping records the parser cannot read."""
    try:
        from evtx import PyEvtxParser
    except ImportError as exc:  # pragma: no cover - dependency is mandatory
        raise CollectError("the 'evtx' package is required to read .evtx files") from exc
    try:
        parser = PyEvtxParser(str(path))
    except (OSError, RuntimeError) as exc:
        raise CollectError(f"cannot open {path}: {exc}") from exc
    bad = 0
    iterator: Iterator[Any] = iter(parser.records_json())
    while True:
        try:
            item = next(iterator)
        except StopIteration:
            break
        except (RuntimeError, OSError):
            bad += 1
            continue
        try:
            parsed: Mapping[str, Any] = json.loads(item["data"])
        except (KeyError, TypeError, json.JSONDecodeError):
            bad += 1
            continue
        yield parsed
    if bad:
        log.warning("parse.skipped_records", path=str(path), skipped=bad)


def normalize_records(
    records: Iterable[Mapping[str, Any]], *, execution_id: str
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    dropped = 0
    for record in records:
        row = normalize_record(record, execution_id=execution_id)
        if row is None:
            dropped += 1
        else:
            rows.append(row)
    if dropped:
        log.warning("parse.dropped_records", dropped=dropped)
    return rows


def parse_evtx(path: Path, *, execution_id: str) -> list[dict[str, Any]]:
    """Parse one .evtx file into normalised rows."""
    return normalize_records(iter_evtx_records(path), execution_id=execution_id)
