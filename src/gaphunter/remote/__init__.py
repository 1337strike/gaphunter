"""Remote control of the lab VM (administrative commands and file copy over SSH)."""

from gaphunter.remote.ssh import CommandResult, Remote, SshRemote, ps_quote

__all__ = ["CommandResult", "Remote", "SshRemote", "ps_quote"]
