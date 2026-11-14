"""Scripted benign activity: the training data for the anomaly detectors.

The baseline is ordinary administration and desktop-style work (listing processes,
editing and archiving files, reading settings, starting and closing a desktop program, creating and
removing a harmless scheduled task). It runs over the same SSH + PowerShell channel as
every other GapHunter command, so that the remote-control channel itself is part of
"normal" and cannot be what the detectors learn to flag.

The activity sequence is drawn from a seeded generator, one stream per slice, so a
baseline is reproducible and a crashed baseline can be resumed slice by slice.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

from gaphunter.collector import collect_session
from gaphunter.config import BaselineConfig, Config
from gaphunter.errors import ConfigError, RemoteError
from gaphunter.lab import guest_utc_now
from gaphunter.log import get_logger
from gaphunter.remote import Remote
from gaphunter.rundir import RunDir, Session, make_execution_id

log = get_logger(__name__)

WORKDIR = r"C:\gaphunter\baseline"


@dataclass(frozen=True)
class Activity:
    name: str
    script: str


_PREP = f"$w = '{WORKDIR}'; New-Item -ItemType Directory -Force -Path $w | Out-Null\n"

BUILTIN_ACTIVITIES: tuple[Activity, ...] = (
    Activity("list-processes", "Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 | Out-String"),
    Activity("tasklist", "tasklist.exe | Select-Object -First 25"),
    Activity("list-services", "Get-Service | Where-Object Status -eq 'Running' | Measure-Object | Out-String"),
    Activity("system-info", "systeminfo.exe | Select-Object -First 12"),
    Activity("os-version", "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, LastBootUpTime | Out-String"),
    Activity("hostname-user", "hostname.exe; whoami.exe"),
    Activity("ip-config", "ipconfig.exe /all | Select-Object -First 20"),
    Activity("ping-gateway", "ping.exe -n 2 10.66.66.1 | Out-String"),
    Activity("netstat", "netstat.exe -an | Select-Object -First 20"),
    Activity("volumes", "Get-Volume | Out-String; Get-PSDrive -PSProvider FileSystem | Out-String"),
    Activity("hotfixes", "Get-HotFix | Select-Object -First 10 | Out-String"),
    Activity("local-users", "Get-LocalUser | Select-Object Name, Enabled | Out-String"),
    Activity("event-log-read", "Get-WinEvent -LogName System -MaxEvents 20 | Select-Object TimeCreated, Id | Out-String"),
    Activity("browse-profile", "Get-ChildItem $env:USERPROFILE -Recurse -Depth 2 -ErrorAction SilentlyContinue | Measure-Object | Out-String"),
    Activity("browse-programs", "Get-ChildItem 'C:\\Program Files' | Select-Object Name | Out-String"),
    Activity(
        "write-notes",
        _PREP
        + "1..20 | ForEach-Object { \"note line $_ $(Get-Date -Format o)\" } | Set-Content \"$w\\notes.txt\"\n"
        + "Add-Content \"$w\\notes.txt\" 'reviewed'\n"
        + "Get-Content \"$w\\notes.txt\" | Measure-Object -Line | Out-String",
    ),
    Activity(
        "copy-rename-delete",
        _PREP
        + "'quarterly figures draft' | Set-Content \"$w\\draft.txt\"\n"
        + "Copy-Item \"$w\\draft.txt\" \"$w\\draft-copy.txt\" -Force\n"
        + "Move-Item \"$w\\draft-copy.txt\" \"$w\\draft-final.txt\" -Force\n"
        + "Remove-Item \"$w\\draft-final.txt\" -Force",
    ),
    Activity(
        "csv-report",
        _PREP
        + "Get-Process | Select-Object Name, Id, WS | Export-Csv \"$w\\procs.csv\" -NoTypeInformation\n"
        + "Import-Csv \"$w\\procs.csv\" | Sort-Object Name | Select-Object -First 5 | Out-String",
    ),
    Activity(
        "archive-files",
        _PREP
        + "'a','b','c' | ForEach-Object { \"content $_\" | Set-Content \"$w\\file-$_.txt\" }\n"
        + "Compress-Archive -Path \"$w\\file-*.txt\" -DestinationPath \"$w\\files.zip\" -Force\n"
        + "Expand-Archive -Path \"$w\\files.zip\" -DestinationPath \"$w\\unzipped\" -Force\n"
        + "Remove-Item \"$w\\unzipped\" -Recurse -Force",
    ),
    Activity(
        "search-text",
        _PREP
        + "if (-not (Test-Path \"$w\\notes.txt\")) { 'note line 1' | Set-Content \"$w\\notes.txt\" }\n"
        + "Select-String -Path \"$w\\*.txt\" -Pattern 'line' | Measure-Object | Out-String\n"
        + "findstr.exe /c:\"note\" \"$w\\notes.txt\" | Select-Object -First 3",
    ),
    Activity(
        "file-hash",
        "Get-FileHash 'C:\\Windows\\System32\\cmd.exe' -Algorithm SHA256 | Out-String",
    ),
    # A classic Win32 program: Notepad and Paint are Store apps on Windows 11 and do not
    # start reliably from a non-interactive SSH session.
    Activity(
        "desktop-app-session",
        "$p = Start-Process charmap.exe -PassThru -ErrorAction SilentlyContinue\n"
        "Start-Sleep -Seconds 6\n"
        "if ($p) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }",
    ),
    Activity(
        "cmd-dir",
        "cmd.exe /c \"dir C:\\Windows\\System32\\drivers\\etc\" | Out-String",
    ),
    Activity(
        "registry-read",
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' | "
        "Select-Object ProductName, CurrentBuild | Out-String",
    ),
    Activity(
        "app-setting",
        "New-Item -Path 'HKCU:\\Software\\GapHunterBaseline' -Force | Out-Null\n"
        "Set-ItemProperty -Path 'HKCU:\\Software\\GapHunterBaseline' -Name 'LastOpened' "
        "-Value (Get-Date -Format o)\n"
        "Get-ItemProperty 'HKCU:\\Software\\GapHunterBaseline' | Out-String",
    ),
    Activity("scheduled-tasks-list", "schtasks.exe /query /fo LIST | Select-Object -First 30"),
    Activity(
        "scheduled-task-reminder",
        _PREP
        + "$a = New-ScheduledTaskAction -Execute 'cmd.exe' "
        + "-Argument ('/c echo reminder > ' + $w + '\\reminder.txt')\n"
        + "$t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(30)\n"
        + "Register-ScheduledTask -TaskName 'GapHunter Baseline Reminder' -Action $a -Trigger $t "
        + "-Force | Out-Null\n"
        + "Start-Sleep -Seconds 3\n"
        + "Unregister-ScheduledTask -TaskName 'GapHunter Baseline Reminder' -Confirm:$false",
    ),
    Activity("environment", "Get-ChildItem Env: | Select-Object -First 15 | Out-String"),
    Activity("modules", "Get-Module -ListAvailable | Select-Object -First 10 Name | Out-String"),
)  # fmt: skip


def load_activities(cfg: BaselineConfig) -> list[Activity]:
    """Built-in activities plus (or replaced by) the ones in ``activities_file``."""
    activities = [] if cfg.replace_builtin else list(BUILTIN_ACTIVITIES)
    if cfg.activities_file is not None:
        path: Path = cfg.activities_file
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigError(f"cannot read baseline activities {path}: {exc}") from exc
        if not isinstance(data, list):
            raise ConfigError(f"{path}: expected a list of {{name, script}} entries")
        for item in data:
            if not isinstance(item, dict) or not {"name", "script"} <= set(item):
                raise ConfigError(f"{path}: every entry needs 'name' and 'script'")
            activities.append(Activity(str(item["name"]), str(item["script"])))
    if not activities:
        raise ConfigError("no baseline activities configured")
    return activities


def slice_rng(seed: int, index: int) -> random.Random:
    """Independent, reproducible stream per slice."""
    return random.Random(f"gaphunter-baseline-{seed}-{index}")


def run_slice(
    remote: Remote,
    activities: list[Activity],
    cfg: BaselineConfig,
    rng: random.Random,
    *,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> list[str]:
    """Run activities with random gaps for one slice. Returns the activity names run."""
    deadline = clock() + cfg.slice_minutes * 60
    done: list[str] = []
    while clock() < deadline:
        activity = rng.choice(activities)
        try:
            remote.run_powershell(activity.script, check=False)
            done.append(activity.name)
        except RemoteError as exc:  # one flaky command must not end the baseline
            log.warning("baseline.activity_failed", activity=activity.name, error=str(exc))
        gap = rng.uniform(cfg.min_gap_s, max(cfg.min_gap_s, cfg.max_gap_s))
        remaining = deadline - clock()
        if remaining <= 0:
            break
        sleep(min(gap, remaining))
    return done


def run_baseline(
    remote: Remote,
    run: RunDir,
    config: Config,
    hours: float,
    *,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> list[str]:
    """Collect ``hours`` of baseline as consecutive slices. Returns new execution ids."""
    cfg = config.baseline
    activities = load_activities(cfg)
    n_slices = max(1, round(hours * 60 / cfg.slice_minutes))
    created: list[str] = []
    for index in range(1, n_slices + 1):
        execution_id = make_execution_id("baseline", name=f"{index:04d}")
        existing = run.get(execution_id)
        if existing is not None and existing.status == "collected":
            continue  # resume: this slice is already on disk
        if existing is not None:
            run.remove(execution_id)
        start, start_pid = guest_utc_now(remote)
        session = Session(
            execution_id=execution_id,
            kind="baseline",
            start_utc=start,
            snapshot=config.lab.snapshot,
            control_pids=[start_pid] if start_pid is not None else [],
        )
        run.upsert(session)
        log.info("baseline.slice", slice=index, of=n_slices, execution_id=execution_id)
        names = run_slice(
            remote, activities, cfg, slice_rng(config.seed, index), sleep=sleep, clock=clock
        )
        end, end_pid = guest_utc_now(remote)
        ended = session.model_copy(
            update={
                "end_utc": end,
                "status": "ended",
                "control_pids": [*session.control_pids, *([end_pid] if end_pid else [])],
                "notes": "activities=" + ",".join(names),
            }
        )
        run.upsert(ended)
        count = collect_session(remote, run, ended, config.collector, sleep=sleep)
        run.upsert(ended.model_copy(update={"status": "collected", "n_events": count}))
        created.append(execution_id)
    return created
