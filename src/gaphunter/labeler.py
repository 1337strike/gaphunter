"""Ground-truth labelling of events.

An event is labelled malicious only if BOTH hold:

1. its timestamp lies inside the session window ``[start_utc, end_utc]``, and
2. it was emitted by a process in the lineage rooted at the session's root process
   (the process the emulation ran from, given with ``session end --root-pid``).

Everything else is benign. ``label_reason`` records why a row got its label:

``lineage``        in window and in the lineage (malicious)
``lineage_root``   in window, emitted by the root process itself (malicious; the feature
                   stage can drop these because they are the framework's own host)
``window_only``    no root PID was given: every in-window event was labelled (malicious,
                   noisy; only used when ``labeler.fallback`` is ``window``)
``control``        GapHunter's own remote-control processes (benign, dropped from features)
``control_lineage`` a control session's shell lineage (benign; the null-control "test")
``None``           benign

Control sessions follow the attack procedure with a benign command. Their root process is
found and treated exactly like an attack's (``lineage_root``, dropped from features), but
nothing is labelled malicious.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta

import pandas as pd

from gaphunter.collector.store import read_events, write_events_frame
from gaphunter.config import LabelerConfig
from gaphunter.log import get_logger
from gaphunter.rundir import RunDir, Session

log = get_logger(__name__)

_TS_MIN = pd.Timestamp.min.tz_localize("UTC")
_TS_MAX = pd.Timestamp.max.tz_localize("UTC")


@dataclass(frozen=True)
class LabelStats:
    execution_id: str
    n_events: int
    n_malicious: int
    n_control: int
    # "baseline" | "lineage" | "window_only" | "no_lineage_events" | "skipped"
    mode: str  # also "control" for null-control sessions


def _control_mask(events: pd.DataFrame, control_pids: list[int]) -> pd.Series:
    if not control_pids:
        return pd.Series(False, index=events.index)
    own = events["pid"].isin(control_pids)
    # conhost etc. started by the probe process
    children = events["parent_pid"].isin(control_pids) & events["event_id"].isin([1, 4688])
    return own | children


def lineage(events: pd.DataFrame, root_pid: int) -> tuple[set[str], set[str]]:
    """Return ``(root_guids, descendant_guids)`` from Sysmon process-create events.

    The root's own creation is usually outside the exported window, so its GUID is also
    recovered from children that name it as parent.
    """
    creates = events[(events["channel"] == "sysmon") & (events["event_id"] == 1)]
    roots: set[str] = set(creates.loc[creates["pid"] == root_pid, "process_guid"].dropna())
    roots |= set(creates.loc[creates["parent_pid"] == root_pid, "parent_process_guid"].dropna())
    children: dict[str, list[str]] = defaultdict(list)
    for guid, parent in zip(creates["process_guid"], creates["parent_process_guid"], strict=True):
        if isinstance(guid, str) and isinstance(parent, str):
            children[parent].append(guid)
    descendants: set[str] = set()
    queue = deque(roots)
    while queue:
        for child in children.get(queue.popleft(), ()):
            if child not in descendants and child not in roots:
                descendants.add(child)
                queue.append(child)
    return roots, descendants


def _lifetimes(
    events: pd.DataFrame, guids: set[str]
) -> dict[int, list[tuple[pd.Timestamp, pd.Timestamp]]]:
    """PID -> list of [created, terminated] intervals for the given process GUIDs."""
    sysmon = events[(events["channel"] == "sysmon") & events["process_guid"].isin(guids)]
    created = sysmon[sysmon["event_id"] == 1].groupby("process_guid")["ts_utc"].min()
    ended = sysmon[sysmon["event_id"] == 5].groupby("process_guid")["ts_utc"].max()
    pid_of = sysmon.dropna(subset=["pid"]).groupby("process_guid")["pid"].first()
    out: dict[int, list[tuple[pd.Timestamp, pd.Timestamp]]] = defaultdict(list)
    for guid, pid in pid_of.items():
        out[int(pid)].append((created.get(guid, _TS_MIN), ended.get(guid, _TS_MAX)))
    return out


def _pid_mask(
    events: pd.DataFrame,
    lifetimes: dict[int, list[tuple[pd.Timestamp, pd.Timestamp]]],
    slack: timedelta,
) -> pd.Series:
    mask = pd.Series(False, index=events.index)
    ts = events["ts_utc"]
    for pid, intervals in lifetimes.items():
        same_pid = events["pid"] == pid
        if not same_pid.any():
            continue
        for start, end in intervals:
            lo = start - slack if start > _TS_MIN + slack else start
            hi = end + slack if end < _TS_MAX - slack else end
            mask |= same_pid & (ts >= lo) & (ts <= hi)
    return mask


def label_events(
    events: pd.DataFrame, session: Session, cfg: LabelerConfig
) -> tuple[pd.DataFrame, LabelStats]:
    """Label one session's events. Returns a new frame and summary statistics."""
    out = events.copy()
    out["label"] = False
    out["technique_id"] = None
    out["label_reason"] = None

    control = _control_mask(out, session.control_pids)
    out.loc[control, "label_reason"] = "control"

    def stats(mode: str) -> LabelStats:
        return LabelStats(
            session.execution_id, len(out), int(out["label"].sum()), int(control.sum()), mode
        )

    if session.kind == "baseline" or session.end_utc is None or out.empty:
        return out, stats("baseline" if session.kind == "baseline" else "skipped")

    start = pd.Timestamp(session.start_utc)
    end = pd.Timestamp(session.end_utc)
    in_window = (out["ts_utc"] >= start) & (out["ts_utc"] <= end) & ~control

    mode = "lineage"
    in_lineage = pd.Series(False, index=out.index)
    root_only = pd.Series(False, index=out.index)
    if session.executor_root_pid is not None:
        root_pid = int(session.executor_root_pid)
        roots, descendants = lineage(out, root_pid)
        slack = timedelta(seconds=cfg.pid_slack_s)
        by_guid = out["process_guid"].isin(descendants)
        by_pid = out["process_guid"].isna() & _pid_mask(out, _lifetimes(out, descendants), slack)
        root_only = out["process_guid"].isin(roots) | (
            out["process_guid"].isna() & (out["pid"] == root_pid)
        )
        in_lineage = by_guid | by_pid | root_only
        if not (in_lineage & in_window).any():
            log.warning(
                "label.root_not_seen",
                execution_id=session.execution_id,
                root_pid=root_pid,
                hint="no in-window event from this PID or its descendants; nothing labelled",
            )
            # The root is known and left no trace: this run has no telemetry. Falling
            # back to window labels here would call unrelated background noise malicious.
            mode = "no_lineage_events"
    else:
        mode = "window_only" if cfg.fallback == "window" else "skipped"
        log.warning(
            "label.no_root_pid",
            execution_id=session.execution_id,
            fallback=cfg.fallback,
            hint="pass --root-pid to 'session end' for lineage-based labels",
        )

    if session.kind == "control":
        if mode == "lineage":
            out.loc[in_window & in_lineage, "label_reason"] = "control_lineage"
            out.loc[in_window & root_only, "label_reason"] = "lineage_root"
        return out, stats("control")

    if mode == "lineage":
        malicious = in_window & in_lineage
        out.loc[malicious, "label_reason"] = "lineage"
        out.loc[malicious & root_only, "label_reason"] = "lineage_root"
    elif mode == "window_only":
        malicious = in_window
        out.loc[malicious, "label_reason"] = "window_only"
    else:
        malicious = pd.Series(False, index=out.index)

    out.loc[malicious, "label"] = True
    out.loc[malicious, "technique_id"] = session.technique_id
    return out, stats(mode)


def label_run(run: RunDir, cfg: LabelerConfig, *, force: bool = False) -> list[LabelStats]:
    """Label every collected session of a run (skipping ones already labelled)."""
    results: list[LabelStats] = []
    for session in run.collected():
        target = run.labeled_path(session.execution_id)
        if target.exists() and not force:
            continue
        source = run.events_path(session.execution_id)
        if not source.is_file():
            log.warning("label.missing_events", execution_id=session.execution_id)
            continue
        events = read_events(source).to_pandas()
        labeled, stats = label_events(events, session, cfg)
        write_events_frame(labeled, target)
        results.append(stats)
        log.info(
            "label.done",
            execution_id=stats.execution_id,
            events=stats.n_events,
            malicious=stats.n_malicious,
            mode=stats.mode,
        )
    return results
