"""Automatic root-PID detection, using the process tree of the first real pilot run."""

from __future__ import annotations

import pandas as pd

from gaphunter.roots import ProcessStart, detect_root


def ps(
    t: str, pid: int, ppid: int, parent: str, image: str, cmd: str, control: bool = False
) -> ProcessStart:
    return ProcessStart(pd.Timestamp(f"2026-11-14T{t}Z"), pid, ppid, image, parent, cmd, control)


# Process creations from the T1082 pilot (Windows 11, OpenSSH, Invoke-AtomicTest).
PILOT = [
    ps("12:50:25", 2760, 4036, "sshd.exe", "cmd.exe", '"c:\\windows\\system32\\cmd.exe" /c "powershell"'),
    ps("12:50:25", 3896, 2760, "cmd.exe", "powershell.exe", "powershell"),
    ps("12:51:05", 4704, 3896, "powershell.exe", "whoami.exe", "whoami.exe"),
    ps("12:51:07", 4656, 3896, "powershell.exe", "cmd.exe", '"cmd.exe" /c systeminfo & reg query X'),
    ps("12:51:07", 4680, 4656, "cmd.exe", "systeminfo.exe", "systeminfo"),
    ps("12:51:09", 4828, 964, "", "wmiprvse.exe", "wmiprvse.exe -secured -Embedding"),
    ps("12:51:11", 4920, 4656, "cmd.exe", "reg.exe", "reg query X"),
    ps("12:51:13", 4912, 3896, "powershell.exe", "cmd.exe", '"cmd.exe" /c'),
    ps("12:51:38", 4128, 792, "services.exe", "svchost.exe", "svchost.exe -k LocalService"),
    ps("12:51:49", 1820, 2184, "sshd.exe", "cmd.exe",
       '"c:\\windows\\system32\\cmd.exe" /c "powershell.exe -NoLogo -NoProfile -NonInteractive -Command -"'),
    ps("12:51:49", 1756, 1820, "cmd.exe", "powershell.exe",
       "powershell.exe  -NoLogo -NoProfile -NonInteractive -Command -", control=True),
]  # fmt: skip


def test_pilot_root_is_the_interactive_powershell() -> None:
    guess = detect_root(PILOT)
    assert guess.pid == 3896
    assert "powershell.exe" in guess.reason


def test_shell_started_directly_by_sshd() -> None:
    direct = [
        ps("10:00:00", 500, 400, "sshd-session.exe", "powershell.exe", "powershell"),
        ps("10:00:05", 501, 500, "powershell.exe", "whoami.exe", "whoami"),
    ]
    assert detect_root(direct).pid == 500


def test_harness_commands_alone_give_no_root() -> None:
    harness = [p for p in PILOT if p.pid in (1820, 1756, 4128)]
    harness.append(ps("12:51:50", 1757, 1756, "powershell.exe", "conhost.exe", "conhost.exe"))
    guess = detect_root(harness)
    assert guess.pid is None and "no interactive SSH shell" in guess.reason


def test_idle_shell_is_not_a_root() -> None:
    idle = [p for p in PILOT if p.pid in (2760, 3896)]  # opened but nothing was run
    assert detect_root(idle).pid is None


def test_two_active_shells_are_ambiguous() -> None:
    second = [
        ps("12:52:00", 2900, 4036, "sshd.exe", "cmd.exe", 'cmd.exe /c "powershell"'),
        ps("12:52:00", 2901, 2900, "cmd.exe", "powershell.exe", "powershell"),
        ps("12:52:05", 2902, 2901, "powershell.exe", "hostname.exe", "hostname"),
    ]
    guess = detect_root(PILOT + second)
    assert guess.pid is None and set(guess.candidates) == {3896, 2901}
