"""Finding the root process of an emulation session after the fact.

Labels need the PID of the process the test was started from (``session end --root-pid``).
If it was not recorded, or recorded wrongly, the session's own process-creation events
show the process trees that started inside the window, and the right root can be picked
from them.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from gaphunter.collector.store import read_events
from gaphunter.errors import RunStateError
from gaphunter.features import basename
from gaphunter.rundir import RunDir, Session


@dataclass(frozen=True)
class ProcessStart:
    ts: pd.Timestamp
    pid: int | None
    parent_pid: int | None
    image: str
    parent_image: str
    command_line: str
    control: bool


def _int(value: object) -> int | None:
    if value is None or isinstance(value, str):
        return None
    try:
        return None if pd.isna(value) else int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return None


def process_starts(run: RunDir, session: Session) -> list[ProcessStart]:
    """Process creations inside the session window, oldest first (Sysmon, else Security)."""
    path = run.events_path(session.execution_id)
    if not path.is_file():
        raise RunStateError(f"no events collected for {session.execution_id}")
    events = read_events(path).to_pandas()
    creates = events[(events["channel"] == "sysmon") & (events["event_id"] == 1)]
    if creates.empty:
        creates = events[(events["channel"] == "security") & (events["event_id"] == 4688)]
    start = pd.Timestamp(session.start_utc)
    end = pd.Timestamp(session.end_utc) if session.end_utc else creates["ts_utc"].max()
    creates = creates[(creates["ts_utc"] >= start) & (creates["ts_utc"] <= end)]
    control = set(session.control_pids)
    rows: list[ProcessStart] = []
    for record in creates.sort_values("ts_utc").itertuples(index=False):
        pid, parent = _int(record.pid), _int(record.parent_pid)
        rows.append(
            ProcessStart(
                ts=record.ts_utc,
                pid=pid,
                parent_pid=parent,
                image=basename(record.image),
                parent_image=basename(record.parent_image),
                command_line=record.command_line if isinstance(record.command_line, str) else "",
                control=pid in control or parent in control,
            )
        )
    return rows


def set_root(run: RunDir, execution_id: str, root_pid: int) -> Session:
    """Record a corrected root PID and drop the old labels so ``label`` redoes them."""
    session = run.get(execution_id)
    if session is None:
        raise RunStateError(f"no such session: {execution_id}")
    if session.kind != "attack":
        raise RunStateError(f"{execution_id} is a baseline session; it has no root process")
    updated = session.model_copy(update={"executor_root_pid": root_pid})
    run.upsert(updated)
    run.labeled_path(execution_id).unlink(missing_ok=True)
    return updated
