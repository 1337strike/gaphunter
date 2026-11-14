"""Run directory: reproducibility manifest plus resumable session state.

Layout of one run directory::

    results/runs/<run_id>/
        manifest.json        config snapshot, seed, tool versions, VM snapshot name
        config.yaml          the effective config as YAML
        state.json           one entry per collection session (source of truth for resume)
        executions.parquet   state.json mirrored as a table for analysis
        evtx/<execution_id>/<channel>.evtx
        events/<execution_id>.parquet

``state.json`` is rewritten atomically after every step, so a crash leaves the run in a
state that the next command can pick up from.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any, Literal

import pyarrow as pa
import pyarrow.parquet as pq
from pydantic import BaseModel, ConfigDict, Field

from gaphunter import __version__
from gaphunter.config import Config, dump_config
from gaphunter.errors import RunStateError
from gaphunter.schema import EXECUTIONS_SCHEMA

SessionKind = Literal["attack", "baseline"]
SessionStatus = Literal["open", "ended", "collected"]

_TRACKED_PACKAGES = (
    "pyarrow",
    "evtx",
    "pydantic",
    "typer",
    "structlog",
    "libvirt-python",
    "numpy",
    "pandas",
    "scikit-learn",
    "torch",
    "matplotlib",
)
_SAFE_ID = re.compile(r"[^A-Za-z0-9._-]+")


class Session(BaseModel):
    """One collection window on the VM."""

    model_config = ConfigDict(extra="forbid")

    execution_id: str
    kind: SessionKind
    technique_id: str | None = None
    test_number: int | None = None
    test_guid: str | None = None
    repetition: int | None = None
    start_utc: datetime
    end_utc: datetime | None = None
    exit_code: int | None = None
    executor_root_pid: int | None = None
    control_pids: list[int] = Field(default_factory=list)
    snapshot: str | None = None
    reverted: bool = False
    status: SessionStatus = "open"
    n_events: int | None = None
    notes: str | None = None


def make_execution_id(
    kind: SessionKind,
    *,
    technique_id: str | None = None,
    test_number: int | None = None,
    repetition: int | None = None,
    name: str | None = None,
) -> str:
    """Deterministic, filesystem-safe id, e.g. ``T1059.001-1-r2`` or ``baseline-morning``."""
    if kind == "attack":
        if not technique_id or test_number is None or repetition is None:
            raise RunStateError("attack sessions need --technique, --test and --rep")
        raw = f"{technique_id}-{test_number}-r{repetition}"
    else:
        if not name:
            raise RunStateError("baseline sessions need --name")
        raw = f"baseline-{name}"
    return _SAFE_ID.sub("_", raw)


def _tool_versions() -> dict[str, str]:
    versions: dict[str, str] = {
        "gaphunter": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
    }
    for pkg in _TRACKED_PACKAGES:
        try:
            versions[pkg] = metadata.version(pkg)
        except metadata.PackageNotFoundError:
            versions[pkg] = "not installed"
    if shutil.which("ssh"):
        try:
            out = subprocess.run(
                ["ssh", "-V"], capture_output=True, text=True, timeout=5, check=False
            )
            versions["ssh"] = (out.stderr or out.stdout).strip()
        except (OSError, subprocess.SubprocessError):
            versions["ssh"] = "unknown"
    return versions


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


class RunDir:
    """Handle on one run directory."""

    def __init__(self, path: Path) -> None:
        self.path = path

    # -- paths ---------------------------------------------------------------------
    @property
    def manifest_path(self) -> Path:
        return self.path / "manifest.json"

    @property
    def state_path(self) -> Path:
        return self.path / "state.json"

    @property
    def executions_path(self) -> Path:
        return self.path / "executions.parquet"

    def evtx_dir(self, execution_id: str) -> Path:
        return self.path / "evtx" / execution_id

    def events_path(self, execution_id: str) -> Path:
        return self.path / "events" / f"{execution_id}.parquet"

    def labeled_path(self, execution_id: str) -> Path:
        return self.path / "labeled" / f"{execution_id}.parquet"

    def alerts_raw_path(self, execution_id: str) -> Path:
        return self.path / "alerts" / f"{execution_id}.jsonl"

    @property
    def windows_path(self) -> Path:
        return self.path / "windows.parquet"

    @property
    def alerts_path(self) -> Path:
        return self.path / "alerts.parquet"

    @property
    def splits_path(self) -> Path:
        return self.path / "splits.parquet"

    @property
    def scores_path(self) -> Path:
        return self.path / "scores.parquet"

    @property
    def eval_dir(self) -> Path:
        return self.path / "eval"

    def collected(self) -> list[Session]:
        return [s for s in self.sessions() if s.status == "collected"]

    def is_synthetic(self) -> bool:
        return bool(self.manifest().get("synthetic", False))

    # -- lifecycle -----------------------------------------------------------------
    @classmethod
    def create(
        cls,
        config: Config,
        *,
        name: str | None = None,
        now: datetime | None = None,
        synthetic: bool = False,
    ) -> RunDir:
        stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
        run_id = f"{stamp}-{_SAFE_ID.sub('_', name)}" if name else stamp
        path = config.results_dir / "runs" / run_id
        if path.exists():
            raise RunStateError(f"run directory already exists: {path}")
        (path / "evtx").mkdir(parents=True)
        (path / "events").mkdir()
        run = cls(path)
        manifest: dict[str, Any] = {
            "run_id": run_id,
            "created_utc": (now or datetime.now(UTC)).isoformat(),
            "seed": config.seed,
            "vm": {
                "libvirt_uri": config.lab.libvirt_uri,
                "domain": config.lab.domain,
                "snapshot": config.lab.snapshot,
            },
            "tool_versions": _tool_versions(),
            "guest": {},
            "synthetic": synthetic,
            "config": config.model_dump(mode="json"),
        }
        _atomic_write(run.manifest_path, json.dumps(manifest, indent=2))
        _atomic_write(path / "config.yaml", dump_config(config))
        run._save([])
        return run

    @classmethod
    def open(cls, path: Path) -> RunDir:
        run = cls(path)
        if not run.manifest_path.is_file() or not run.state_path.is_file():
            raise RunStateError(f"not a GapHunter run directory: {path}")
        return run

    # -- manifest ------------------------------------------------------------------
    def manifest(self) -> dict[str, Any]:
        data: dict[str, Any] = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        return data

    def update_guest_info(self, info: dict[str, str]) -> None:
        """Record guest-side versions (Sysmon, OS build...) the first time we see them."""
        manifest = self.manifest()
        manifest.setdefault("guest", {}).update(info)
        _atomic_write(self.manifest_path, json.dumps(manifest, indent=2))

    def record_tool_version(self, name: str, version: str) -> None:
        """Add a host-side tool version (e.g. Hayabusa) to the manifest."""
        manifest = self.manifest()
        manifest.setdefault("tool_versions", {})[name] = version
        _atomic_write(self.manifest_path, json.dumps(manifest, indent=2))

    # -- sessions ------------------------------------------------------------------
    def sessions(self) -> list[Session]:
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RunStateError(f"corrupt state file {self.state_path}: {exc}") from exc
        return [Session.model_validate(item) for item in data.get("sessions", [])]

    def get(self, execution_id: str) -> Session | None:
        return next((s for s in self.sessions() if s.execution_id == execution_id), None)

    def pending(self) -> list[Session]:
        """Sessions that still need work (not yet collected), oldest first."""
        return [s for s in self.sessions() if s.status != "collected"]

    def upsert(self, session: Session) -> None:
        sessions = [s for s in self.sessions() if s.execution_id != session.execution_id]
        sessions.append(session)
        sessions.sort(key=lambda s: s.start_utc)
        self._save(sessions)

    def remove(self, execution_id: str) -> None:
        self._save([s for s in self.sessions() if s.execution_id != execution_id])
        shutil.rmtree(self.evtx_dir(execution_id), ignore_errors=True)
        self.events_path(execution_id).unlink(missing_ok=True)
        self.labeled_path(execution_id).unlink(missing_ok=True)
        self.alerts_raw_path(execution_id).unlink(missing_ok=True)

    def _save(self, sessions: list[Session]) -> None:
        payload = {"sessions": [s.model_dump(mode="json") for s in sessions]}
        _atomic_write(self.state_path, json.dumps(payload, indent=2))
        rows = [s.model_dump() for s in sessions]
        table = pa.Table.from_pylist(rows, schema=EXECUTIONS_SCHEMA)
        tmp = self.executions_path.with_suffix(".parquet.tmp")
        pq.write_table(table, tmp)
        os.replace(tmp, self.executions_path)
