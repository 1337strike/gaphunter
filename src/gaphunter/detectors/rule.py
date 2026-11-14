"""Rule-based detector: Hayabusa (Sigma rules) over the exported .evtx files.

Hayabusa is run once per session directory, so every alert is attributed to its session
by construction. (Timestamps alone would be ambiguous: the guest clock jumps back each
time the snapshot is reverted.)

A window's rule score is the highest alert level inside it (0 = no alert ... 5 =
critical); it counts as detected at or above ``rules.min_level``.
"""

from __future__ import annotations

import csv
import json
import re
import shutil
import subprocess
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from gaphunter.collector.parse import CHANNEL_ALIASES
from gaphunter.collector.store import read_events
from gaphunter.config import RuleConfig
from gaphunter.errors import GapHunterError
from gaphunter.log import get_logger
from gaphunter.rundir import RunDir
from gaphunter.schema import ALERTS_SCHEMA
from gaphunter.timeutil import parse_utc

log = get_logger(__name__)

LEVELS: dict[str, int] = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
_LEVEL_ALIASES: dict[str, str] = {
    "info": "informational",
    "informational": "informational",
    "low": "low",
    "med": "medium",
    "medium": "medium",
    "high": "high",
    "crit": "critical",
    "critical": "critical",
    "emer": "critical",
    "emergency": "critical",
}
# Hayabusa abbreviates channel names in its output.
_CHANNEL_ABBREVIATIONS: dict[str, str] = {
    "sysmon": "sysmon",
    "sec": "security",
    "security": "security",
    "pwsh": "powershell",
    "powershell": "powershell",
}
_TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?", re.I)
_SPLIT = re.compile(r"\s*[¦|,]\s*")
_OFFSET_GAP = re.compile(r"\s+([+-]\d{2}:?\d{2})$")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [part for part in _SPLIT.split(str(value).strip()) if part]


def _get(record: dict[str, Any], *names: str) -> Any:
    lowered = {k.lower(): v for k, v in record.items()}
    for name in names:
        if name.lower() in lowered and lowered[name.lower()] not in (None, ""):
            return lowered[name.lower()]
    return None


_KNOWN_CHANNELS = frozenset({"sysmon", "security", "powershell"})


def _channel(record: dict[str, Any]) -> str | None:
    """GapHunter's channel name for an alert.

    Hayabusa abbreviates channels ("Sec", "Sysmon", "PwSh"). Those map directly; otherwise
    the source file name is used when it is one of GapHunter's own exports
    (``sysmon.evtx`` ...). Imported files can have any name, so the file name alone is
    never trusted over a recognised channel.
    """
    raw = _get(record, "Channel")
    if raw is not None:
        key = str(raw).strip().lower()
        mapped = _CHANNEL_ABBREVIATIONS.get(key) or CHANNEL_ALIASES.get(key)
        if mapped:
            return mapped
    evtx = _get(record, "EvtxFile")
    if evtx:
        stem = Path(str(evtx).replace("\\", "/")).stem.lower()
        if stem in _KNOWN_CHANNELS:
            return stem
    return str(raw).strip().lower() if raw is not None else None


def normalize_alert(record: dict[str, Any], execution_id: str) -> dict[str, Any] | None:
    """Normalise one Hayabusa output record; None if it has no usable timestamp."""
    stamp = _get(record, "Timestamp", "datetime")
    if stamp is None:
        return None
    try:
        ts = parse_utc(_OFFSET_GAP.sub(r"\1", str(stamp)))
    except ValueError:
        return None
    level = _LEVEL_ALIASES.get(str(_get(record, "Level") or "").strip().lower())
    tags = _as_list(_get(record, "MitreTags"))

    def _num(name: str) -> int | None:
        value = _get(record, name)
        try:
            return int(str(value)) if value is not None else None
        except ValueError:
            return None

    return {
        "execution_id": execution_id,
        "ts_utc": ts,
        "rule_title": _get(record, "RuleTitle", "message"),
        "rule_file": _get(record, "RuleFile"),
        "level": level,
        "level_num": LEVELS.get(level or "", 0),
        "channel": _channel(record),
        "event_id": _num("EventID"),
        "record_id": _num("RecordID"),
        "mitre_tactics": _as_list(_get(record, "MitreTactics")),
        "mitre_tags": [t.upper() for tag in tags for t in _TECHNIQUE.findall(tag)],
    }


def read_alert_file(path: Path) -> Iterable[dict[str, Any]]:
    """Read Hayabusa output: JSONL, a JSON array, or CSV."""
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    if text[0] == "[":
        data = json.loads(text)
        return [d for d in data if isinstance(d, dict)]
    if text[0] == "{":
        records: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    records.append(item)
        return records
    return list(csv.DictReader(text.splitlines()))


def parse_alerts(path: Path, execution_id: str) -> list[dict[str, Any]]:
    alerts = (normalize_alert(r, execution_id) for r in read_alert_file(path))
    return [a for a in alerts if a is not None]


def hayabusa_argv(cfg: RuleConfig, evtx_dir: Path, output: Path) -> list[str]:
    return [
        cfg.hayabusa_bin,
        *(a.format(evtx_dir=str(evtx_dir), output=str(output)) for a in cfg.args),
    ]


def hayabusa_version(cfg: RuleConfig, runner: Runner = subprocess.run) -> str:
    """Version line from Hayabusa's banner (it has no --version flag)."""
    try:
        proc = runner(
            [cfg.hayabusa_bin, "help"], capture_output=True, text=True, timeout=20, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    text = _ANSI.sub("", (proc.stdout or "") + "\n" + (proc.stderr or ""))
    for line in text.splitlines():
        if line.strip().lower().startswith("hayabusa v"):
            return line.strip()
    return "unknown"


def _invoke(cfg: RuleConfig, evtx_dir: Path, output: Path, label: str, runner: Runner) -> None:
    """Run Hayabusa on one directory, leaving a (possibly empty) file at ``output``."""
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    argv = hayabusa_argv(cfg, evtx_dir, tmp)
    try:
        proc = runner(argv, capture_output=True, text=True, timeout=cfg.timeout_s, check=False)
    except subprocess.TimeoutExpired as exc:
        raise GapHunterError(f"hayabusa timed out on {label}") from exc
    except FileNotFoundError as exc:
        raise GapHunterError(f"Hayabusa binary {cfg.hayabusa_bin!r} not found") from exc
    if proc.returncode != 0:
        raise GapHunterError(
            f"hayabusa failed on {label} (exit {proc.returncode}): "
            f"{(proc.stderr or proc.stdout or '').strip()[-500:]}\n"
            "If the flags are wrong for your Hayabusa version, adjust rules.args."
        )
    if not tmp.exists():  # no detections: some versions write no file at all
        tmp.write_text("", encoding="utf-8")
    tmp.replace(output)


def require_hayabusa(cfg: RuleConfig) -> None:
    if shutil.which(cfg.hayabusa_bin) is None and not Path(cfg.hayabusa_bin).is_file():
        raise GapHunterError(
            f"Hayabusa binary {cfg.hayabusa_bin!r} not found. Install it and set "
            "rules.hayabusa_bin in the config."
        )


def run_rules(
    run: RunDir, cfg: RuleConfig, *, force: bool = False, runner: Runner = subprocess.run
) -> pd.DataFrame:
    """Run Hayabusa for each collected session (resumable) and write ``alerts.parquet``.

    Sessions that came from one ``import-evtx`` call share their source files, so Hayabusa
    runs once per import and its alerts are assigned to the sessions by time.
    """
    sessions = run.collected()
    own = [s for s in sessions if s.import_group is None]
    groups = sorted({s.import_group for s in sessions if s.import_group is not None})
    todo = [s for s in own if force or not run.alerts_raw_path(s.execution_id).exists()]
    todo_groups = [
        g
        for g in groups
        if run.import_evtx_dir(g).is_dir() and (force or not run.import_alerts_path(g).exists())
    ]
    if todo or todo_groups:
        require_hayabusa(cfg)
        run.record_tool_version("hayabusa", hayabusa_version(cfg, runner))
    for session in todo:
        _invoke(
            cfg,
            run.evtx_dir(session.execution_id),
            run.alerts_raw_path(session.execution_id),
            session.execution_id,
            runner,
        )
        log.info("rules.session", execution_id=session.execution_id)
    for group in todo_groups:
        _invoke(
            cfg,
            run.import_evtx_dir(group),
            run.import_alerts_path(group),
            f"import {group}",
            runner,
        )
        log.info("rules.import", group=group)

    rows: list[dict[str, Any]] = []
    for session in own:
        path = run.alerts_raw_path(session.execution_id)
        if path.exists():
            rows.extend(parse_alerts(path, session.execution_id))
    for group in groups:
        path = run.import_alerts_path(group)
        if not path.exists():
            log.warning("rules.import_without_evtx", group=group, hint="no rule alerts for it")
            continue
        # Latest-starting slice first: an alert exactly on a boundary belongs to the
        # slice that starts there, like the events themselves.
        members = sorted(
            (s for s in sessions if s.import_group == group),
            key=lambda s: s.start_utc,
            reverse=True,
        )
        for alert in parse_alerts(path, group):
            for session in members:
                if session.end_utc is not None and (
                    session.start_utc <= alert["ts_utc"] <= session.end_utc
                ):
                    rows.append({**alert, "execution_id": session.execution_id})
                    break
    table = pa.Table.from_pylist(rows, schema=ALERTS_SCHEMA)
    pq.write_table(table, run.alerts_path)
    log.info("rules.done", alerts=len(rows), sessions=len(sessions))
    return table.to_pandas()


def detect_rule_alerts(
    evtx_files: list[Path], cfg: RuleConfig, workdir: Path, *, runner: Runner = subprocess.run
) -> list[dict[str, Any]]:
    """Run Hayabusa on arbitrary .evtx files and return alerts at or above ``min_level``."""
    require_hayabusa(cfg)
    source = workdir / "evtx"
    source.mkdir(parents=True, exist_ok=True)
    for path in evtx_files:
        shutil.copyfile(path, source / path.name)
    output = workdir / "alerts.jsonl"
    _invoke(cfg, source, output, "the given files", runner)
    minimum = LEVELS[cfg.min_level]
    alerts: list[dict[str, Any]] = []
    for record in read_alert_file(output):
        alert = normalize_alert(record, "detect")
        if alert is None or alert["level_num"] < minimum:
            continue
        alerts.append(
            {
                "type": "rule",
                "host": _get(record, "Computer"),
                "time": alert["ts_utc"].isoformat(),
                "window_start": alert["ts_utc"].isoformat(),
                "severity": alert["level"],
                "rule_title": alert["rule_title"],
                "rule_file": alert["rule_file"],
                "mitre_tags": alert["mitre_tags"],
                "channel": alert["channel"],
                "event_id": alert["event_id"],
                "record_id": alert["record_id"],
            }
        )
    return alerts


def _excluded_records(run: RunDir, execution_id: str, drop: set[str]) -> set[tuple[str, int]]:
    """(channel, record_id) of events the feature stage ignores, so rules ignore them too."""
    path = run.labeled_path(execution_id)
    if not path.is_file():
        return set()
    events = read_events(path).select(["channel", "record_id", "label_reason"]).to_pandas()
    hit = events[events["label_reason"].isin(drop)]
    return set(zip(hit["channel"], hit["record_id"].astype(int), strict=True))


def technique_matches(tags: Iterable[str], technique_id: str | None) -> bool:
    """True if a rule's ATT&CK tags name the technique, its parent or a sub-technique."""
    if not technique_id:
        return False
    wanted = technique_id.upper()
    parent = wanted.split(".")[0]
    return any(tag == wanted or tag == parent or tag.split(".")[0] == wanted for tag in tags)


def rule_window_scores(
    run: RunDir, windows: pd.DataFrame, alerts: pd.DataFrame, *, exclude_root: bool = True
) -> pd.DataFrame:
    """Per-window rule score (max alert level) and whether a technique-matching rule fired."""
    drop = {"control"} | ({"lineage_root"} if exclude_root else set())
    out = windows[
        ["window_id", "execution_id", "window_start", "window_end", "technique_id"]
    ].copy()
    out["score"] = 0.0
    out["technique_match"] = False
    if alerts.empty:
        return out[["window_id", "score", "technique_match"]]
    by_exec = {eid: frame for eid, frame in alerts.groupby("execution_id")}
    scores: list[float] = []
    matches: list[bool] = []
    excluded_cache: dict[str, set[tuple[str, int]]] = {}
    for row in out.itertuples(index=False):
        frame = by_exec.get(row.execution_id)
        if frame is None:
            scores.append(0.0)
            matches.append(False)
            continue
        if row.execution_id not in excluded_cache:
            excluded_cache[row.execution_id] = _excluded_records(run, row.execution_id, drop)
        excluded = excluded_cache[row.execution_id]
        inside = frame[(frame["ts_utc"] >= row.window_start) & (frame["ts_utc"] < row.window_end)]
        if excluded and not inside.empty:
            keys = list(zip(inside["channel"], inside["record_id"], strict=True))
            keep = [not (pd.notna(r) and (c, int(r)) in excluded) for c, r in keys]
            inside = inside[keep]
        if inside.empty:
            scores.append(0.0)
            matches.append(False)
            continue
        scores.append(float(inside["level_num"].max()))
        technique = row.technique_id if isinstance(row.technique_id, str) else None
        matches.append(
            any(technique_matches(list(tags), technique) for tags in inside["mitre_tags"])
        )
    out["score"] = scores
    out["technique_match"] = matches
    return out[["window_id", "score", "technique_match"]]
