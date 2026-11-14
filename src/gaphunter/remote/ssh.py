"""Thin wrapper around the system OpenSSH client.

Why shell out instead of using a Python SSH library: the OpenSSH client is already on the
host, honours the user's key agent, and keeps the dependency list short.

PowerShell scripts are sent on stdin (``powershell -Command -``), which sidesteps every
quoting problem between the local shell, sshd's default shell and PowerShell itself, and
works whether the server's default shell is cmd.exe or PowerShell.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from gaphunter.config import SshConfig, SshCredentials
from gaphunter.errors import RemoteError
from gaphunter.log import get_logger

log = get_logger(__name__)

_PS_PREAMBLE = "$ErrorActionPreference = 'Stop'\n$ProgressPreference = 'SilentlyContinue'\ntry {\n"
# The trailing blank lines matter: PowerShell reading a script from stdin only runs a
# multi-line block once it sees an empty line after it.
_PS_POSTAMBLE = (
    "\n} catch {\n"
    "  [Console]::Error.WriteLine('GAPHUNTER_ERROR: ' + $_.Exception.Message)\n"
    "  exit 1\n"
    "}\n"
    "exit 0\n\n\n"
)

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


def ps_quote(value: str) -> str:
    """Quote a string as a PowerShell single-quoted literal."""
    return "'" + value.replace("'", "''") + "'"


def wrap_powershell(script: str) -> str:
    """Wrap a script so any terminating error becomes exit code 1 with a clear message."""
    return _PS_PREAMBLE + script.strip("\n") + _PS_POSTAMBLE


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class Remote(Protocol):
    """What the rest of GapHunter needs from the VM. Tests supply a fake."""

    def run_powershell(
        self, script: str, *, check: bool = True, timeout_s: int | None = None
    ) -> CommandResult: ...

    def fetch(self, remote_path: str, local_path: Path) -> None: ...

    def is_reachable(self) -> bool: ...


class SshRemote:
    """Key-based SSH/SCP to the Windows guest. Never prompts (BatchMode)."""

    def __init__(
        self,
        ssh: SshConfig,
        creds: SshCredentials,
        *,
        runner: Runner = subprocess.run,
    ) -> None:
        self._ssh = ssh
        self._creds = creds
        self._runner = runner

    def _common_options(self) -> list[str]:
        self._ssh.known_hosts.parent.mkdir(parents=True, exist_ok=True)
        return [
            "-i", str(self._creds.key_path),
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={self._ssh.known_hosts}",
            "-o", f"ConnectTimeout={self._ssh.connect_timeout_s}",
            "-o", "LogLevel=ERROR",
        ]  # fmt: skip

    @property
    def _target(self) -> str:
        return f"{self._creds.user}@{self._ssh.host}"

    def ssh_argv(self, remote_command: Sequence[str]) -> list[str]:
        return [
            "ssh",
            *self._common_options(),
            "-p",
            str(self._ssh.port),
            self._target,
            *remote_command,
        ]

    def scp_argv(self, remote_path: str, local_path: Path) -> list[str]:
        # Windows OpenSSH accepts forward slashes: user@host:C:/dir/file
        remote = remote_path.replace("\\", "/")
        return [
            "scp",
            *self._common_options(),
            "-P",
            str(self._ssh.port),
            f"{self._target}:{remote}",
            str(local_path),
        ]

    def _exec(self, argv: list[str], *, stdin: str | None, timeout_s: int) -> CommandResult:
        try:
            proc = self._runner(
                argv,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RemoteError(f"{argv[0]} timed out after {timeout_s}s") from exc
        except FileNotFoundError as exc:
            raise RemoteError(f"{argv[0]} not found on PATH (install openssh)") from exc
        return CommandResult(proc.returncode, proc.stdout or "", proc.stderr or "")

    def run_powershell(
        self, script: str, *, check: bool = True, timeout_s: int | None = None
    ) -> CommandResult:
        argv = self.ssh_argv(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"]
        )
        result = self._exec(
            argv,
            stdin=wrap_powershell(script),
            timeout_s=timeout_s or self._ssh.command_timeout_s,
        )
        if check and not result.ok:
            raise RemoteError(
                f"remote PowerShell failed (exit {result.returncode}): "
                f"{result.stderr.strip() or result.stdout.strip() or 'no output'}",
                returncode=result.returncode,
                stderr=result.stderr,
            )
        return result

    def fetch(self, remote_path: str, local_path: Path) -> None:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        result = self._exec(
            self.scp_argv(remote_path, local_path),
            stdin=None,
            timeout_s=self._ssh.command_timeout_s,
        )
        if not result.ok:
            raise RemoteError(
                f"scp of {remote_path} failed (exit {result.returncode}): {result.stderr.strip()}",
                returncode=result.returncode,
                stderr=result.stderr,
            )

    def is_reachable(self) -> bool:
        try:
            result = self.run_powershell(
                "Write-Output 'gaphunter-ready'",
                check=False,
                timeout_s=self._ssh.connect_timeout_s + 20,
            )
        except RemoteError as exc:
            log.debug("ssh.unreachable", error=str(exc))
            return False
        return result.ok and "gaphunter-ready" in result.stdout
