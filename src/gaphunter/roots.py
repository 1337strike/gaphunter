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


# -- automatic detection -------------------------------------------------------------

_SSHD = frozenset({"sshd.exe", "sshd-session.exe"})
_SHELLS = frozenset({"powershell.exe", "pwsh.exe", "cmd.exe"})
# GapHunter's own remote commands run as `powershell.exe ... -NonInteractive -Command -`.
_HARNESS_MARK = "-noninteractive -command -"


@dataclass(frozen=True)
class RootGuess:
    pid: int | None
    reason: str
    candidates: tuple[int, ...] = ()


def detect_root(starts: list[ProcessStart]) -> RootGuess:
    """Find the interactive shell the test was typed into.

    The analyst connects with ``ssh ... powershell``, so the window contains
    sshd -> [cmd.exe /c "powershell" ->] powershell.exe, and the test's processes are that
    shell's descendants. A candidate is the innermost shell of such a chain that is not
    GapHunter's own non-interactive command and that started at least one other process.
    """
    by_pid = {p.pid: p for p in starts if p.pid is not None}
    children: dict[int, list[ProcessStart]] = {}
    for p in starts:
        if p.parent_pid is not None:
            children.setdefault(p.parent_pid, []).append(p)

    def from_ssh(p: ProcessStart) -> bool:
        if p.parent_image in _SSHD:
            return True
        parent = by_pid.get(p.parent_pid) if p.parent_pid is not None else None
        return (
            parent is not None
            and parent.image in _SHELLS
            and parent.parent_image in _SSHD
            and _HARNESS_MARK not in parent.command_line.lower()
        )

    shells = [
        p
        for p in starts
        if p.pid is not None
        and not p.control
        and p.image in _SHELLS
        and _HARNESS_MARK not in p.command_line.lower()
        and from_ssh(p)
    ]
    # Keep only the innermost shell of each chain (powershell, not the cmd that wraps it).
    innermost = [p for p in shells if not any(c in shells for c in children.get(p.pid or -1, []))]
    active = [p for p in innermost if children.get(p.pid or -1)]
    pids = tuple(p.pid for p in active if p.pid is not None)
    if len(pids) == 1:
        shell = active[0]
        return RootGuess(pids[0], f"{shell.image} started over SSH at {shell.ts:%H:%M:%S}", pids)
    if pids:
        return RootGuess(None, f"{len(pids)} interactive SSH shells started processes", pids)

    # The shell may have been opened just before the window (for example while
    # 'session begin' was still waiting for the VM to settle): its own creation is then
    # not in the logs, only its children. Accept a PowerShell parent that started inside
    # the window's processes but was not itself started in the window, if it is the only one.
    started_here = set(by_pid)
    outside = sorted(
        {
            p.parent_pid
            for p in starts
            if p.parent_pid is not None
            and not p.control
            and p.parent_pid not in started_here
            and p.parent_image in {"powershell.exe", "pwsh.exe"}
        }
    )
    if len(outside) == 1:
        first = next(p for p in starts if p.parent_pid == outside[0])
        return RootGuess(
            outside[0],
            f"PowerShell opened before the window, first child at {first.ts:%H:%M:%S}",
            tuple(outside),
        )
    if outside:
        return RootGuess(
            None, f"{len(outside)} PowerShell processes from before the window", tuple(outside)
        )
    return RootGuess(None, "no interactive shell that started processes was found in the window")
