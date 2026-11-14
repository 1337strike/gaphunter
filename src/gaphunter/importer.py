"""Import existing .evtx exports into a run.

This is how a team trains on its own environment instead of (or in addition to) the lab
baseline: export Sysmon / Security / PowerShell logs from a machine that is known to be
clean, import them as ``baseline``, and the detectors learn what normal looks like there.
Logs of a red-team exercise can be imported as ``attack`` sessions for evaluation.

One import must come from one host; import each machine under its own name.
"""

from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path

import pandas as pd

from gaphunter.collector.store import write_events_frame
from gaphunter.errors import GapHunterError
from gaphunter.log import get_logger
from gaphunter.rundir import _SAFE_ID, RunDir, Session, make_execution_id

log = get_logger(__name__)


def _single_host(events: pd.DataFrame) -> str | None:
    hosts = sorted({str(h) for h in events["host"].dropna().unique()})
    if len(hosts) > 1:
        raise GapHunterError(
            f"the files contain events from {len(hosts)} hosts ({', '.join(hosts[:4])}); "
            "import each host separately"
        )
    return hosts[0] if hosts else None


def _store(run: RunDir, events: pd.DataFrame, session: Session) -> None:
    part = events.copy()
    part["execution_id"] = session.execution_id
    part["label"] = None
    count = write_events_frame(part, run.events_path(session.execution_id))
    run.upsert(session.model_copy(update={"status": "collected", "n_events": count}))


def import_baseline(
    run: RunDir,
    events: pd.DataFrame,
    *,
    name: str,
    slice_minutes: float,
    evtx_files: list[Path] | None = None,
) -> list[str]:
    """Add benign logs as consecutive baseline sessions of ``slice_minutes`` each."""
    if events.empty:
        raise GapHunterError("no events to import")
    host = _single_host(events)
    group = _SAFE_ID.sub("_", name)
    if any(s.import_group == group for s in run.sessions()):
        raise GapHunterError(f"an import named {group!r} already exists in this run")
    width = pd.Timedelta(minutes=slice_minutes)
    first = events["ts_utc"].min()
    index = ((events["ts_utc"] - first) // width).astype(int)
    created: list[str] = []
    for number, (k, part) in enumerate(events.groupby(index, sort=True), start=1):
        start = first + int(k) * width
        end = min(start + width, events["ts_utc"].max())
        session = Session(
            execution_id=make_execution_id("baseline", name=f"{group}-{number:04d}"),
            kind="baseline",
            start_utc=start.to_pydatetime(),
            end_utc=end.to_pydatetime(),
            import_group=group,
            notes=f"imported; host={host}",
        )
        _store(run, part, session)
        created.append(session.execution_id)
    if evtx_files:
        target = run.import_evtx_dir(group)
        target.mkdir(parents=True, exist_ok=True)
        for path in evtx_files:
            shutil.copyfile(path, target / path.name)
    log.info("import.baseline", name=group, sessions=len(created), events=len(events), host=host)
    return created


def import_attack(
    run: RunDir,
    events: pd.DataFrame,
    *,
    technique: str,
    test: int,
    rep: int,
    root_pid: int | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    evtx_files: list[Path] | None = None,
) -> str:
    """Add the logs of one emulated technique run as an attack session."""
    if events.empty:
        raise GapHunterError("no events to import")
    host = _single_host(events)
    execution_id = make_execution_id(
        "attack", technique_id=technique, test_number=test, repetition=rep
    )
    if run.get(execution_id) is not None:
        raise GapHunterError(f"session {execution_id} already exists in this run")
    session = Session(
        execution_id=execution_id,
        kind="attack",
        technique_id=technique,
        test_number=test,
        repetition=rep,
        start_utc=start or events["ts_utc"].min().to_pydatetime(),
        end_utc=end or events["ts_utc"].max().to_pydatetime(),
        executor_root_pid=root_pid,
        notes=f"imported; host={host}",
    )
    if session.end_utc is not None and session.end_utc < session.start_utc:
        raise GapHunterError("--end is before --start")
    _store(run, events, session)
    if evtx_files:
        target = run.evtx_dir(execution_id)
        target.mkdir(parents=True, exist_ok=True)
        for path in evtx_files:
            shutil.copyfile(path, target / path.name)
    log.info("import.attack", execution_id=execution_id, events=len(events), host=host)
    return execution_id
