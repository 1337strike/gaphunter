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


def _single_host(events: pd.DataFrame, same_host: bool) -> str | None:
    """The host the events come from. More than one name is an error unless ``same_host``.

    A machine that was renamed (Windows setup names it WIN-XXXX first) logs under both
    names, so one export can legitimately carry two.
    """
    hosts = sorted({str(h) for h in events["host"].dropna().unique()})
    if len(hosts) > 1 and not same_host:
        raise GapHunterError(
            f"the files contain events from {len(hosts)} host names ({', '.join(hosts[:4])}). "
            "Import each host separately, or pass --same-host if this is one machine "
            "that was renamed."
        )
    if len(hosts) > 1:
        log.warning("import.multiple_host_names", hosts=hosts)
        return "+".join(hosts)
    return hosts[0] if hosts else None


def _store(run: RunDir, events: pd.DataFrame, session: Session) -> Session:
    """Write a session's events; the caller records the returned session in the run."""
    part = events.copy()
    part["execution_id"] = session.execution_id
    part["label"] = None
    count = write_events_frame(part, run.events_path(session.execution_id))
    return session.model_copy(update={"status": "collected", "n_events": count})


def import_baseline(
    run: RunDir,
    events: pd.DataFrame,
    *,
    name: str,
    slice_minutes: float,
    evtx_files: list[Path] | None = None,
    same_host: bool = False,
) -> list[str]:
    """Add benign logs as consecutive baseline sessions of ``slice_minutes`` each."""
    if events.empty:
        raise GapHunterError("no events to import")
    host = _single_host(events, same_host)
    group = _SAFE_ID.sub("_", name)
    if any(s.import_group == group for s in run.sessions()):
        raise GapHunterError(f"an import named {group!r} already exists in this run")
    width = pd.Timedelta(minutes=slice_minutes)
    first = events["ts_utc"].min()
    index = ((events["ts_utc"] - first) // width).astype(int)
    stored: list[Session] = []
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
        stored.append(_store(run, part, session))
    run.upsert_many(stored)  # one state write, however many slices
    created = [s.execution_id for s in stored]
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
    same_host: bool = False,
) -> str:
    """Add the logs of one emulated technique run as an attack session."""
    if events.empty:
        raise GapHunterError("no events to import")
    host = _single_host(events, same_host)
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
    run.upsert(_store(run, events, session))
    if evtx_files:
        target = run.evtx_dir(execution_id)
        target.mkdir(parents=True, exist_ok=True)
        for path in evtx_files:
            shutil.copyfile(path, target / path.name)
    log.info("import.attack", execution_id=execution_id, events=len(events), host=host)
    return execution_id
