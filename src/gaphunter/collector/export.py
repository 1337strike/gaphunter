"""Export event logs for a time window from the VM and turn them into Parquet.

Steps for one session: ``wevtutil epl`` per channel with a time filter -> scp the .evtx
files to the run directory -> parse -> one Parquet file. The raw .evtx files are kept
because the rule-based detector (Hayabusa) reads them directly.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from typing import Any

from gaphunter.collector.parse import parse_evtx
from gaphunter.collector.store import dedupe_and_sort, write_events
from gaphunter.config import CollectorConfig
from gaphunter.errors import CollectError, RemoteError
from gaphunter.log import get_logger
from gaphunter.remote import Remote, ps_quote
from gaphunter.rundir import RunDir, Session
from gaphunter.timeutil import to_systemtime

log = get_logger(__name__)


def time_filter_xpath(start: datetime, end: datetime) -> str:
    """XPath query selecting events with ``start <= TimeCreated <= end``."""
    if end < start:
        raise CollectError(f"window ends before it starts: {start} .. {end}")
    return (
        "*[System[TimeCreated[@SystemTime>='"
        + to_systemtime(start)
        + "' and @SystemTime<='"
        + to_systemtime(end)
        + "']]]"
    )


def remote_evtx_path(remote_dir: str, alias: str) -> str:
    return remote_dir.rstrip("\\/") + "\\" + alias + ".evtx"


def build_export_script(
    channels: Mapping[str, str], remote_dir: str, start: datetime, end: datetime
) -> str:
    """PowerShell that exports each channel's window to ``<remote_dir>\\<alias>.evtx``."""
    query = time_filter_xpath(start, end)
    lines = [
        f"$dir = {ps_quote(remote_dir)}",
        "New-Item -ItemType Directory -Force -Path $dir | Out-Null",
        # The query holds single quotes but no '$', so a double-quoted string is safe.
        f'$query = "{query}"',
    ]
    for alias, channel in channels.items():
        target = ps_quote(remote_evtx_path(remote_dir, alias))
        lines += [
            f'& wevtutil.exe epl {ps_quote(channel)} {target} "/q:$query" /ow:true',
            "if ($LASTEXITCODE -ne 0) { throw ('wevtutil failed for "
            + alias
            + ": exit ' + $LASTEXITCODE) }",
        ]
    return "\n".join(lines)


def build_cleanup_script(remote_dir: str) -> str:
    return f"Remove-Item -Recurse -Force -Path {ps_quote(remote_dir)} -ErrorAction SilentlyContinue"


def collect_session(
    remote: Remote,
    run: RunDir,
    session: Session,
    cfg: CollectorConfig,
    *,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Export, copy and parse the logs for one ended session. Returns the event count.

    Safe to call again after a failure: every step overwrites its previous output.
    """
    if session.end_utc is None:
        raise CollectError(f"session {session.execution_id} has no end time yet")
    start = session.start_utc - timedelta(seconds=cfg.pad_before_s)
    end = session.end_utc + timedelta(seconds=cfg.pad_after_s)

    if cfg.flush_wait_s:
        sleep(cfg.flush_wait_s)

    log.info(
        "collect.export",
        execution_id=session.execution_id,
        start=to_systemtime(start),
        end=to_systemtime(end),
    )
    try:
        remote.run_powershell(build_export_script(cfg.channels, cfg.remote_dir, start, end))
        evtx_dir = run.evtx_dir(session.execution_id)
        evtx_dir.mkdir(parents=True, exist_ok=True)
        for alias in cfg.channels:
            remote.fetch(remote_evtx_path(cfg.remote_dir, alias), evtx_dir / f"{alias}.evtx")
        remote.run_powershell(build_cleanup_script(cfg.remote_dir), check=False)
    except RemoteError as exc:
        raise CollectError(f"log export failed for {session.execution_id}: {exc}") from exc

    rows: list[dict[str, Any]] = []
    per_channel: dict[str, int] = {}
    for alias in cfg.channels:
        channel_rows = parse_evtx(evtx_dir / f"{alias}.evtx", execution_id=session.execution_id)
        per_channel[alias] = len(channel_rows)
        rows.extend(channel_rows)
    count = write_events(dedupe_and_sort(rows), run.events_path(session.execution_id))
    log.info("collect.parsed", execution_id=session.execution_id, events=count, **per_channel)
    if per_channel.get("sysmon", 1) == 0:
        log.warning(
            "collect.no_sysmon_events",
            execution_id=session.execution_id,
            hint="check that Sysmon is running in the snapshot",
        )
    return count
