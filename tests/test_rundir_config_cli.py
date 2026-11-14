from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq
import pytest
from conftest import FakeRemote
from typer.testing import CliRunner

from gaphunter import cli
from gaphunter.config import Config, load_config, load_credentials
from gaphunter.errors import ConfigError, RunStateError
from gaphunter.remote import CommandResult
from gaphunter.rundir import RunDir, Session, make_execution_id
from gaphunter.schema import EXECUTIONS_SCHEMA

T0 = datetime(2026, 11, 14, 2, 0, 0, tzinfo=UTC)
runner = CliRunner()


# -- config --------------------------------------------------------------------------


def test_default_config_file_is_valid() -> None:
    cfg = load_config(Path(__file__).parents[1] / "configs" / "gaphunter.yaml")
    assert cfg.lab.domain == "gh-win11"
    assert set(cfg.collector.channels) == {"sysmon", "security", "powershell"}


def test_config_rejects_unknown_keys_and_bad_padding(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("lab:\n  domian: typo\n")
    with pytest.raises(ConfigError, match="domian"):
        load_config(bad)
    bad.write_text("collector:\n  pad_after_s: 30\n  flush_wait_s: 5\n")
    with pytest.raises(ConfigError, match="pad_after_s"):
        load_config(bad)
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.yaml")


def test_credentials_come_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = Config()
    monkeypatch.delenv(cfg.ssh.user_env, raising=False)
    monkeypatch.delenv(cfg.ssh.key_env, raising=False)
    with pytest.raises(ConfigError, match="GAPHUNTER_SSH_USER"):
        load_credentials(cfg.ssh, env_file=None)

    key = tmp_path / "id_ed25519"
    key.write_text("k")
    env = tmp_path / ".env"
    env.write_text(f"GAPHUNTER_SSH_USER=labadmin\nGAPHUNTER_SSH_KEY={key}\n")
    creds = load_credentials(cfg.ssh, env_file=env)
    assert creds.user == "labadmin" and creds.key_path == key
    monkeypatch.setenv(cfg.ssh.key_env, str(tmp_path / "nope"))
    with pytest.raises(ConfigError, match="not found"):
        load_credentials(cfg.ssh, env_file=None)


# -- run directory -------------------------------------------------------------------


def test_execution_ids() -> None:
    assert make_execution_id("attack", technique_id="T1059.001", test_number=2, repetition=3) == (
        "T1059.001-2-r3"
    )
    assert make_execution_id("baseline", name="mon am/1") == "baseline-mon_am_1"
    with pytest.raises(RunStateError):
        make_execution_id("attack", technique_id="T1059.001")
    with pytest.raises(RunStateError):
        make_execution_id("baseline")


def test_run_create_writes_reproducibility_manifest(config: Config) -> None:
    run = RunDir.create(config, name="pilot", now=T0)
    assert run.path.name == "20261114T020000Z-pilot"
    manifest = run.manifest()
    assert manifest["seed"] == 1337
    assert manifest["vm"] == {
        "libvirt_uri": "qemu:///system",
        "domain": "gh-win11",
        "snapshot": "clean",
    }
    assert {"gaphunter", "python", "pyarrow", "evtx"} <= set(manifest["tool_versions"])
    assert manifest["config"]["collector"]["channels"]["security"] == "Security"
    assert (run.path / "config.yaml").is_file()
    run.update_guest_info({"sysmon_version": "15.15"})
    assert run.manifest()["guest"] == {"sysmon_version": "15.15"}
    with pytest.raises(RunStateError, match="already exists"):
        RunDir.create(config, name="pilot", now=T0)


def test_open_rejects_other_directories(tmp_path: Path) -> None:
    with pytest.raises(RunStateError):
        RunDir.open(tmp_path)


def test_session_state_survives_reopen_and_mirrors_to_parquet(config: Config) -> None:
    run = RunDir.create(config, now=T0)
    first = Session(
        execution_id="T1082-1-r1",
        kind="attack",
        technique_id="T1082",
        test_number=1,
        repetition=1,
        start_utc=T0,
        control_pids=[111],
    )
    run.upsert(first)
    run.upsert(
        Session(execution_id="baseline-a", kind="baseline", start_utc=T0 - timedelta(hours=1))
    )

    reopened = RunDir.open(run.path)
    assert [s.execution_id for s in reopened.sessions()] == ["baseline-a", "T1082-1-r1"]
    assert [s.execution_id for s in reopened.pending()] == ["baseline-a", "T1082-1-r1"]

    done = first.model_copy(
        update={"status": "collected", "end_utc": T0 + timedelta(seconds=60), "n_events": 42}
    )
    reopened.upsert(done)
    assert [s.execution_id for s in reopened.pending()] == ["baseline-a"]

    table = pq.read_table(run.executions_path)
    assert table.schema.equals(EXECUTIONS_SCHEMA)
    row = next(r for r in table.to_pylist() if r["execution_id"] == "T1082-1-r1")
    assert row["status"] == "collected" and row["n_events"] == 42 and row["control_pids"] == [111]

    reopened.remove("baseline-a")
    assert reopened.get("baseline-a") is None


def test_corrupt_state_is_reported(config: Config) -> None:
    run = RunDir.create(config, now=T0)
    run.state_path.write_text("{not json")
    with pytest.raises(RunStateError, match="corrupt"):
        run.sessions()


# -- CLI -----------------------------------------------------------------------------


@pytest.fixture
def cfg_file(tmp_path: Path) -> Path:
    path = tmp_path / "cfg.yaml"
    path.write_text(
        f"results_dir: {tmp_path / 'results'}\n"
        "lab: {settle_s: 0}\n"
        "collector: {flush_wait_s: 0, pad_after_s: 0}\n"
    )
    return path


class Guest:
    """Scripted guest: answers the clock probe with advancing time."""

    def __init__(self) -> None:
        self.now = T0
        self.pid = 500

    def handler(self, script: str) -> CommandResult:
        if "UtcNow" in script:
            self.now += timedelta(seconds=30)
            self.pid += 1
            return CommandResult(
                0, f"{self.now.strftime('%Y-%m-%dT%H:%M:%S.0000000Z')}|{self.pid}\n", ""
            )
        if "Win32_OperatingSystem" in script:
            return CommandResult(0, "os_build=19045\nsysmon_state=Running\n", "")
        return CommandResult(0, "", "")


def _init(cfg_file: Path) -> Path:
    result = runner.invoke(cli.app, ["-c", str(cfg_file), "run", "init", "--name", "t"])
    assert result.exit_code == 0, result.output
    return Path(result.output.strip().splitlines()[-1])


def test_cli_full_session_flow_and_resume(
    cfg_file: Path, records: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    from gaphunter.collector import export as export_mod
    from gaphunter.collector.parse import normalize_records

    guest = Guest()
    remote = FakeRemote(guest.handler)
    monkeypatch.setattr(cli, "_remote", lambda state: remote)
    monkeypatch.setattr(
        export_mod,
        "parse_evtx",
        lambda path, *, execution_id: [
            r
            for r in normalize_records(records, execution_id=execution_id)
            if r["channel"] == path.stem
        ],
    )
    run_dir = _init(cfg_file)
    base = ["-c", str(cfg_file), "session"]
    begin = [*base, "begin", str(run_dir), "--technique", "T1082", "--test", "1", "--rep", "1"]

    result = runner.invoke(cli.app, begin)
    assert result.exit_code == 0, result.output
    assert result.output.strip().endswith("T1082-1-r1")

    # a second session cannot start while the first is uncollected
    other = [*base, "begin", str(run_dir), "--technique", "T1057", "--test", "1", "--rep", "1"]
    blocked = runner.invoke(cli.app, other)
    assert blocked.exit_code == 1

    result = runner.invoke(
        cli.app, [*base, "end", str(run_dir), "--exit-code", "0", "--root-pid", "999"]
    )
    assert result.exit_code == 0, result.output
    assert "7 events" in result.output

    run = RunDir.open(run_dir)
    session = run.get("T1082-1-r1")
    assert session is not None
    assert session.status == "collected" and session.n_events == 7
    assert session.end_utc is not None and session.end_utc - session.start_utc == timedelta(
        seconds=30
    )
    assert session.executor_root_pid == 999 and session.control_pids == [501, 502]
    assert run.manifest()["guest"]["os_build"] == "19045"
    assert run.events_path("T1082-1-r1").is_file()

    # resume: the same begin is skipped with exit code 3
    again = runner.invoke(cli.app, begin)
    assert again.exit_code == cli.EXIT_ALREADY_COLLECTED
    assert "already collected" in again.output

    status = runner.invoke(cli.app, ["-c", str(cfg_file), "run", "status", str(run_dir)])
    assert "T1082-1-r1" in status.output and "collected" in status.output


def test_cli_collect_retries_a_failed_export(
    cfg_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gaphunter.collector import export as export_mod

    guest = Guest()
    fail = {"on": True}

    def handler(script: str) -> CommandResult:
        if "wevtutil" in script and fail["on"]:
            return CommandResult(1, "", "GAPHUNTER_ERROR: wevtutil failed for sysmon: exit 5")
        return guest.handler(script)

    monkeypatch.setattr(cli, "_remote", lambda state: FakeRemote(handler))
    monkeypatch.setattr(export_mod, "parse_evtx", lambda path, *, execution_id: [])
    run_dir = _init(cfg_file)
    base = ["-c", str(cfg_file), "session"]
    assert (
        runner.invoke(
            cli.app, [*base, "begin", str(run_dir), "--kind", "baseline", "--name", "a"]
        ).exit_code
        == 0
    )

    failed = runner.invoke(cli.app, [*base, "end", str(run_dir)])
    assert failed.exit_code == 1
    assert RunDir.open(run_dir).get("baseline-a").status == "ended"  # type: ignore[union-attr]

    fail["on"] = False
    retried = runner.invoke(cli.app, [*base, "collect", str(run_dir)])
    assert retried.exit_code == 0, retried.output
    assert RunDir.open(run_dir).get("baseline-a").status == "collected"  # type: ignore[union-attr]
    assert "nothing to collect" in runner.invoke(cli.app, [*base, "collect", str(run_dir)]).output


def test_cli_errors_are_clean(cfg_file: Path, tmp_path: Path) -> None:
    assert runner.invoke(cli.app, ["-c", str(tmp_path / "nope.yaml"), "run", "init"]).exit_code == 1
    assert (
        runner.invoke(cli.app, ["-c", str(cfg_file), "run", "status", str(tmp_path)]).exit_code == 1
    )
    run_dir = _init(cfg_file)
    end = runner.invoke(cli.app, ["-c", str(cfg_file), "session", "end", str(run_dir)])
    assert end.exit_code == 1
    missing = runner.invoke(
        cli.app,
        ["-c", str(cfg_file), "parse", str(tmp_path / "x.evtx"), "-o", str(tmp_path / "o.parquet")],
    )
    assert missing.exit_code == 1
    state = json.loads((run_dir / "state.json").read_text())
    assert state == {"sessions": []}
