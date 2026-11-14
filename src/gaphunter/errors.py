"""Exception hierarchy. The CLI turns any GapHunterError into a clean exit code 1."""

from __future__ import annotations


class GapHunterError(Exception):
    """Base class for expected, user-facing failures."""


class ConfigError(GapHunterError):
    """Invalid or missing configuration / environment."""


class LabError(GapHunterError):
    """libvirt / VM lifecycle problem."""


class RemoteError(GapHunterError):
    """SSH/SCP call failed."""

    def __init__(self, message: str, *, returncode: int | None = None, stderr: str = "") -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


class CollectError(GapHunterError):
    """Log export, copy or parsing failed."""


class RunStateError(GapHunterError):
    """Run directory is missing, inconsistent, or in the wrong state for the request."""
