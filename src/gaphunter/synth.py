"""Synthetic demo data, for trying the analysis pipeline without a lab.

EVERYTHING PRODUCED HERE IS MADE UP. The "attack" sessions contain invented process names
and random strings, not real technique telemetry, and the rule alerts are fabricated to
exercise every branch of the evaluation (detected by both, rule only, ML only, neither,
no telemetry). The run manifest is marked ``synthetic: true`` and every report built from
it carries a SYNTHETIC notice. Never report these numbers as results.
"""

from __future__ import annotations

import json
import random
import string
from datetime import UTC, datetime, timedelta
from typing import Any

from gaphunter.collector.store import dedupe_and_sort, write_events
from gaphunter.config import Config
from gaphunter.rundir import RunDir, Session
from gaphunter.schema import EVENT_COLUMNS

_BENIGN: tuple[tuple[str, str, str], ...] = (
    ("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\tasklist.exe", "tasklist"),
    ("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\ipconfig.exe", "ipconfig /all"),
    ("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\hostname.exe", "hostname"),
    ("C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\notepad.exe", "notepad.exe C:\\work\\notes.txt"),
    ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\taskhostw.exe", "taskhostw.exe"),
    ("C:\\Windows\\System32\\services.exe", "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs -p"),
    ("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\findstr.exe", "findstr /c:note C:\\work\\notes.txt"),
    ("C:\\Windows\\System32\\OpenSSH\\sshd.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -NoLogo -NoProfile -NonInteractive -Command -"),
)  # fmt: skip
_BENIGN_SCRIPTS = (
    "Get-Process | Sort-Object CPU -Descending | Select-Object -First 15",
    "Get-ChildItem C:\\work | Measure-Object",
    "Get-Service | Where-Object Status -eq 'Running'",
)
_BENIGN_CONTROL: tuple[tuple[str, str], ...] = (
    ("C:\\Windows\\System32\\hostname.exe", "hostname"),
    ("C:\\Windows\\System32\\tasklist.exe", "tasklist"),
)
# technique id -> (activity profile, fabricated rule alert level or None)
PROFILES: dict[str, tuple[str, str | None]] = {
    "T1082": ("loud", "high"),  # anomalous and alerted      -> both
    "T1057": ("mimic", "high"),  # looks benign but alerted    -> rule only
    "T1033": ("loud", None),  # anomalous, no rule          -> ML only
    "T1016": ("mimic", None),  # looks benign, no rule       -> neither
    "T1083": ("silent", None),  # leaves nothing in the logs  -> no telemetry
}


class _Builder:
    def __init__(self, execution_id: str, rng: random.Random) -> None:
        self.execution_id = execution_id
        self.rng = rng
        self.rows: list[dict[str, Any]] = []
        self._record = {"sysmon": 0, "security": 0, "powershell": 0}
        self._pid = rng.randrange(2000, 3000)
        self._guid = 0

    def new_process(self) -> tuple[int, str]:
        self._pid += 4
        self._guid += 1
        return self._pid, f"{{{self.execution_id}-{self._guid:06d}}}"

    def event(self, ts: datetime, channel: str, event_id: int, **fields: Any) -> dict[str, Any]:
        self._record[channel] += 1
        row: dict[str, Any] = dict.fromkeys(EVENT_COLUMNS)
        row.update(
            execution_id=self.execution_id,
            host="SYNTH-HOST",
            channel=channel,
            provider="synthetic",
            event_id=event_id,
            record_id=self._record[channel],
            ts_utc=ts,
            raw=json.dumps({"synthetic": True}),
        )
        row.update(fields)
        self.rows.append(row)
        return row

    def process(
        self,
        ts: datetime,
        parent: tuple[int, str, str],
        image: str,
        command_line: str,
        integrity: str = "Medium",
    ) -> tuple[int, str, dict[str, Any]]:
        parent_pid, parent_guid, parent_image = parent
        pid, guid = self.new_process()
        create = self.event(
            ts, "sysmon", 1,
            process_guid=guid, pid=pid, image=image, command_line=command_line,
            parent_process_guid=parent_guid, parent_pid=parent_pid, parent_image=parent_image,
            user="SYNTH-HOST\\labadmin", integrity_level=integrity,
        )  # fmt: skip
        self.event(
            ts + timedelta(milliseconds=5), "security", 4688,
            pid=pid, image=image, command_line=command_line, parent_pid=parent_pid,
            parent_image=parent_image, user="SYNTH-HOST\\labadmin", integrity_level=integrity,
        )  # fmt: skip
        self.event(
            ts + timedelta(milliseconds=400), "sysmon", 5, process_guid=guid, pid=pid, image=image
        )
        return pid, guid, create


def _benign_activity(b: _Builder, start: datetime, seconds: float, rate: float) -> None:
    """Background noise: mundane process starts, a few file/registry/network events."""
    rng = b.rng
    t = 0.0
    host = (b.new_process()[0], f"{{{b.execution_id}-host}}", "C:\\Windows\\System32\\cmd.exe")
    while True:
        t += rng.expovariate(rate)
        if t >= seconds:
            return
        ts = start + timedelta(seconds=t)
        parent_image, image, command = rng.choice(_BENIGN)
        b.process(ts, (host[0], host[1], parent_image), image, command)
        roll = rng.random()
        if roll < 0.25:
            b.event(ts, "sysmon", 11, pid=host[0], process_guid=host[1],
                    image=parent_image, target_filename=f"C:\\work\\file-{rng.randrange(20)}.txt")  # fmt: skip
        elif roll < 0.40:
            b.event(ts, "sysmon", 13, pid=host[0], process_guid=host[1], image=parent_image,
                    target_object="HKU\\S-1-5-21-1\\Software\\SynthApp\\LastOpened")  # fmt: skip
        elif roll < 0.50:
            b.event(ts, "sysmon", 3, pid=host[0], process_guid=host[1], image=parent_image,
                    dest_ip="10.66.66.1", dest_port=53)  # fmt: skip
        elif roll < 0.65:
            b.event(ts, "powershell", 4104, pid=host[0],
                    script_block_text=rng.choice(_BENIGN_SCRIPTS))  # fmt: skip


def _random_token(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(n))


def _attack_activity(
    b: _Builder, start: datetime, profile: str, root_pid: int
) -> list[dict[str, Any]]:
    """Invented activity in the lineage of ``root_pid``. Returns its process-create rows."""
    rng = b.rng
    root = (root_pid, f"{{{b.execution_id}-root}}", "C:\\Windows\\System32\\cmd.exe")
    creates: list[dict[str, Any]] = []
    if profile == "silent":
        return creates
    for i in range(6):
        ts = start + timedelta(seconds=20 + 7 * i + rng.random())
        if profile == "loud":
            image = (
                f"C:\\Users\\labadmin\\AppData\\Local\\Temp\\synth-tool-{_random_token(rng, 5)}.exe"
            )
            command = f"{image} --payload-{_random_token(rng, 90)} --mode {_random_token(rng, 30)}"
            pid, guid, create = b.process(ts, root, image, command, integrity="High")
            child = (pid, guid, image)
            for j in range(4):
                b.process(ts + timedelta(milliseconds=50 * (j + 1)), child,
                          f"C:\\Users\\labadmin\\AppData\\Local\\Temp\\synth-child-{j}.exe",
                          f"synth-child-{j}.exe {_random_token(rng, 60)}", integrity="High")  # fmt: skip
            b.event(ts, "sysmon", 13, pid=pid, process_guid=guid, image=image,
                    target_object="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SynthEntry")  # fmt: skip
            b.event(ts, "sysmon", 11, pid=pid, process_guid=guid, image=image,
                    target_filename=f"C:\\Windows\\Temp\\synth-{_random_token(rng, 8)}.dll")  # fmt: skip
        else:  # "mimic": indistinguishable from the benign vocabulary
            parent_image, image, command = rng.choice(_BENIGN[:3])
            _, _, create = b.process(ts, (root[0], root[1], parent_image), image, command)
        creates.append(create)
    return creates


def _alert(row: dict[str, Any], level: str, technique: str | None, title: str) -> dict[str, Any]:
    return {
        "Timestamp": row["ts_utc"].isoformat().replace("+00:00", "Z"),
        "RuleTitle": title,
        "Level": level,
        "Computer": "SYNTH-HOST",
        "Channel": "Sysmon",
        "EventID": row["event_id"],
        "RecordID": row["record_id"],
        "MitreTactics": [],
        "MitreTags": [technique] if technique else [],
        "RuleFile": "synthetic.yml",
        "EvtxFile": f"synthetic/{row['channel']}.evtx",
    }


def make_demo_run(
    config: Config,
    *,
    name: str = "demo",
    n_baseline: int = 15,
    repetitions: int = 3,
    slice_seconds: float = 600.0,
    attack_seconds: float = 120.0,
    n_control: int = 3,
) -> RunDir:
    """Create a run directory filled with synthetic sessions, events and rule alerts."""
    run = RunDir.create(config, name=name, synthetic=True)
    t0 = datetime(2026, 1, 1, 8, 0, 0, tzinfo=UTC)
    (run.path / "alerts").mkdir(exist_ok=True)

    def finish(b: _Builder, session: Session, alerts: list[dict[str, Any]]) -> None:
        count = write_events(dedupe_and_sort(b.rows), run.events_path(session.execution_id))
        run.alerts_raw_path(session.execution_id).write_text(
            "".join(json.dumps(a) + "\n" for a in alerts), encoding="utf-8"
        )
        run.upsert(session.model_copy(update={"status": "collected", "n_events": count}))

    for index in range(1, n_baseline + 1):
        execution_id = f"baseline-{index:04d}"
        rng = random.Random(f"synth-{config.seed}-{execution_id}")
        start = t0 + timedelta(seconds=(index - 1) * slice_seconds)
        b = _Builder(execution_id, rng)
        _benign_activity(b, start, slice_seconds, rate=0.3)
        alerts = []
        if index % 4 == 0:  # the occasional low-severity rule hit on benign activity
            alerts.append(_alert(b.rows[0], "low", None, "Synthetic low-severity rule"))
        if index == n_baseline:  # and one real false positive in the benign test split
            alerts.append(_alert(b.rows[len(b.rows) // 2], "high", None, "Synthetic noisy rule"))
        session = Session(
            execution_id=execution_id,
            kind="baseline",
            start_utc=start,
            end_utc=start + timedelta(seconds=slice_seconds),
        )
        finish(b, session, alerts)

    attack_t0 = t0 + timedelta(days=1)
    slot = 0
    for technique, (profile, level) in PROFILES.items():
        for rep in range(1, repetitions + 1):
            execution_id = f"{technique}-1-r{rep}"
            rng = random.Random(f"synth-{config.seed}-{execution_id}")
            start = attack_t0 + timedelta(seconds=slot * (attack_seconds + 60))
            slot += 1
            b = _Builder(execution_id, rng)
            _benign_activity(b, start, attack_seconds, rate=0.3)
            root_pid = 9000 + slot
            creates = _attack_activity(b, start, profile, root_pid)
            alerts = (
                [_alert(creates[0], level, technique, "Synthetic technique rule")]
                if level and creates
                else []
            )
            session = Session(
                execution_id=execution_id,
                kind="attack",
                technique_id=technique,
                test_number=1,
                repetition=rep,
                start_utc=start,
                end_utc=start + timedelta(seconds=attack_seconds),
                executor_root_pid=root_pid,
                exit_code=0,
                notes="SYNTHETIC",
            )
            finish(b, session, alerts)
    # Null-control sessions: the same procedure, a benign command in the analyst's shell.
    for rep in range(1, n_control + 1):
        execution_id = f"control-r{rep}"
        rng = random.Random(f"synth-{config.seed}-{execution_id}")
        start = attack_t0 + timedelta(seconds=slot * (attack_seconds + 60))
        slot += 1
        b = _Builder(execution_id, rng)
        _benign_activity(b, start, attack_seconds, rate=0.3)
        root_pid = 9000 + slot
        root = (root_pid, f"{{{execution_id}-root}}", "C:\\Windows\\System32\\cmd.exe")
        for i, (image, command) in enumerate(_BENIGN_CONTROL):
            b.process(start + timedelta(seconds=20 + 5 * i), root, image, command)
        session = Session(
            execution_id=execution_id,
            kind="control",
            start_utc=start,
            end_utc=start + timedelta(seconds=attack_seconds),
            executor_root_pid=root_pid,
            repetition=rep,
            notes="SYNTHETIC",
        )
        finish(b, session, [])
    return run
