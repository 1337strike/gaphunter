from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeRemote

from gaphunter.collector import export as export_mod
from gaphunter.collector.export import (
    build_export_script,
    collect_session,
    time_filter_xpath,
)
from gaphunter.config import Config, SshConfig, SshCredentials
from gaphunter.errors import CollectError, RemoteError
from gaphunter.remote import CommandResult, SshRemote, ps_quote
from gaphunter.remote.ssh import wrap_powershell
from gaphunter.rundir import RunDir, Session

START = datetime(2026, 11, 14, 2, 0, 0, tzinfo=UTC)
END = START + timedelta(seconds=90)


def _ssh(tmp_path: Path, runner: Any) -> SshRemote:
    key = tmp_path / "id"
    key.write_text("k")
    cfg = SshConfig(known_hosts=tmp_path / "kh" / "known_hosts")
    return SshRemote(cfg, SshCredentials(user="labadmin", key_path=key), runner=runner)


def test_ps_quote_doubles_single_quotes() -> None:
    assert ps_quote("C:\\it's") == "'C:\\it''s'"


def test_wrap_powershell_traps_errors_and_ends_with_blank_line() -> None:
    wrapped = wrap_powershell("Write-Output 1")
    assert wrapped.startswith("$ErrorActionPreference = 'Stop'")
    assert "try {\nWrite-Output 1\n} catch {" in wrapped
    assert wrapped.endswith("exit 0\n\n\n")


def test_ssh_sends_script_on_stdin_and_never_prompts(tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    def runner(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["argv"], seen["kwargs"] = argv, kwargs
        return subprocess.CompletedProcess(argv, 0, "ok\n", "")

    remote = _ssh(tmp_path, runner)
    result = remote.run_powershell("Write-Output 'ok'")
    assert result.stdout == "ok\n"
    argv = seen["argv"]
    assert argv[0] == "ssh"
    assert "BatchMode=yes" in argv and "IdentitiesOnly=yes" in argv
    assert "labadmin@10.66.66.10" in argv
    assert argv[-2:] == ["-Command", "-"]
    # the script travels on stdin, not on the command line
    assert "Write-Output 'ok'" in seen["kwargs"]["input"]
    assert not any("Write-Output" in part for part in argv)


def test_ssh_failure_raises_with_stderr(tmp_path: Path) -> None:
    def runner(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 1, "", "GAPHUNTER_ERROR: boom")

    remote = _ssh(tmp_path, runner)
    with pytest.raises(RemoteError, match="boom") as info:
        remote.run_powershell("throw 'boom'")
    assert info.value.returncode == 1
    assert remote.run_powershell("throw 'boom'", check=False).returncode == 1


def test_ssh_timeout_and_missing_binary(tmp_path: Path) -> None:
    def slow(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(argv, 1)

    def missing(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(argv[0])

    with pytest.raises(RemoteError, match="timed out"):
        _ssh(tmp_path, slow).run_powershell("x")
    with pytest.raises(RemoteError, match="not found"):
        _ssh(tmp_path, missing).run_powershell("x")
    assert _ssh(tmp_path, slow).is_reachable() is False


def test_scp_argv_uses_forward_slashes(tmp_path: Path) -> None:
    remote = _ssh(tmp_path, lambda *a, **k: None)
    argv = remote.scp_argv("C:\\gaphunter\\export\\sysmon.evtx", tmp_path / "s.evtx")
    assert argv[0] == "scp"
    assert "labadmin@10.66.66.10:C:/gaphunter/export/sysmon.evtx" in argv
    assert argv[argv.index("-P") + 1] == "22"


def test_time_filter_xpath() -> None:
    assert time_filter_xpath(START, END) == (
        "*[System[TimeCreated[@SystemTime>='2026-11-14T02:00:00.000Z' "
        "and @SystemTime<='2026-11-14T02:01:30.000Z']]]"
    )
    with pytest.raises(CollectError):
        time_filter_xpath(END, START)


def test_export_script_covers_every_channel() -> None:
    channels = {"sysmon": "Microsoft-Windows-Sysmon/Operational", "security": "Security"}
    script = build_export_script(channels, "C:\\gaphunter\\export", START, END)
    assert "New-Item -ItemType Directory -Force" in script
    assert (
        "& wevtutil.exe epl 'Microsoft-Windows-Sysmon/Operational' "
        "'C:\\gaphunter\\export\\sysmon.evtx' \"/q:$query\" /ow:true"
    ) in script
    assert "'C:\\gaphunter\\export\\security.evtx'" in script
    assert script.count("$LASTEXITCODE -ne 0") == 2
    # nothing in the query may be expanded by PowerShell
    query_line = next(line for line in script.splitlines() if line.startswith("$query"))
    assert "$" not in query_line[len("$query") :]


def _ended_session() -> Session:
    return Session(
        execution_id="T1082-1-r1",
        kind="attack",
        technique_id="T1082",
        test_number=1,
        repetition=1,
        start_utc=START,
        end_utc=END,
        status="ended",
    )


def test_collect_session_exports_fetches_and_writes_parquet(
    config: Config, records: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    from gaphunter.collector.parse import normalize_records

    def fake_parse(path: Path, *, execution_id: str) -> list[dict[str, Any]]:
        rows = normalize_records(records, execution_id=execution_id)
        return [r for r in rows if r["channel"] == path.stem]

    monkeypatch.setattr(export_mod, "parse_evtx", fake_parse)
    run = RunDir.create(config, name="t")
    remote = FakeRemote()
    slept: list[float] = []

    count = collect_session(remote, run, _ended_session(), config.collector, sleep=slept.append)

    assert count == 7
    assert [p.name for _, p in remote.fetched] == [
        "sysmon.evtx",
        "security.evtx",
        "powershell.evtx",
    ]
    assert "wevtutil.exe epl" in remote.scripts[0]
    # window is padded by pad_before_s (2 s) on the left
    assert "2026-11-14T01:59:58.000Z" in remote.scripts[0]
    assert "Remove-Item" in remote.scripts[-1]
    assert run.events_path("T1082-1-r1").is_file()
    assert slept == []  # flush_wait_s is 0 in the test config


def test_collect_session_wraps_remote_failures(config: Config) -> None:
    run = RunDir.create(config, name="t")
    remote = FakeRemote(lambda script: CommandResult(1, "", "wevtutil failed for sysmon"))
    with pytest.raises(CollectError, match="wevtutil failed"):
        collect_session(remote, run, _ended_session(), config.collector, sleep=lambda s: None)


def test_collect_session_needs_an_end_time(config: Config) -> None:
    run = RunDir.create(config, name="t")
    session = _ended_session().model_copy(update={"end_utc": None, "status": "open"})
    with pytest.raises(CollectError, match="no end time"):
        collect_session(FakeRemote(), run, session, config.collector)
