"""Shared fixtures and fakes. No test touches a VM, libvirt or the network."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from gaphunter.config import Config
from gaphunter.errors import RemoteError
from gaphunter.remote import CommandResult

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def records() -> list[dict[str, Any]]:
    data: list[dict[str, Any]] = json.loads((FIXTURES / "records.json").read_text("utf-8"))
    return data


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config.model_validate(
        {
            "results_dir": str(tmp_path / "results"),
            "lab": {"ready_timeout_s": 10, "ready_poll_s": 1, "settle_s": 0},
            "collector": {"flush_wait_s": 0, "pad_after_s": 0},
        }
    )


class FakeRemote:
    """Records scripts; answers from a handler. Implements the Remote protocol."""

    def __init__(
        self,
        handler: Callable[[str], CommandResult] | None = None,
        *,
        reachable: bool | list[bool] = True,
    ) -> None:
        self.scripts: list[str] = []
        self.fetched: list[tuple[str, Path]] = []
        self._handler = handler or (lambda script: CommandResult(0, "", ""))
        self._reachable = reachable
        self.reachable_calls = 0

    def run_powershell(
        self, script: str, *, check: bool = True, timeout_s: int | None = None
    ) -> CommandResult:
        self.scripts.append(script)
        result = self._handler(script)
        if check and not result.ok:
            raise RemoteError(result.stderr or "failed", returncode=result.returncode)
        return result

    def fetch(self, remote_path: str, local_path: Path) -> None:
        self.fetched.append((remote_path, local_path))
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_bytes(b"")

    def is_reachable(self) -> bool:
        self.reachable_calls += 1
        if isinstance(self._reachable, list):
            index = min(self.reachable_calls - 1, len(self._reachable) - 1)
            return self._reachable[index]
        return self._reachable


ISOLATED_NET = "<network><name>gaphunter-isolated</name><ip address='10.66.66.1'/></network>"
NAT_NET = "<network><name>default</name><forward mode='nat'/></network>"


def domain_xml(*interfaces: str) -> str:
    return f"<domain><devices>{''.join(interfaces)}</devices></domain>"


def net_iface(network: str) -> str:
    return f"<interface type='network'><source network='{network}'/></interface>"


class FakeHypervisor:
    def __init__(
        self,
        *,
        snapshots: list[str] | None = None,
        running: bool = True,
        dom_xml: str | None = None,
        networks: dict[str, str] | None = None,
        running_after_revert: bool = True,
    ) -> None:
        self.snapshots = ["clean"] if snapshots is None else snapshots
        self.running = running
        self.running_after_revert = running_after_revert
        self.dom_xml = dom_xml or domain_xml(net_iface("gaphunter-isolated"))
        self.networks = networks or {"gaphunter-isolated": ISOLATED_NET, "default": NAT_NET}
        self.calls: list[str] = []

    def snapshot_names(self) -> list[str]:
        return list(self.snapshots)

    def is_running(self) -> bool:
        return self.running

    def revert(self, snapshot: str) -> None:
        self.calls.append(f"revert:{snapshot}")
        self.running = self.running_after_revert

    def start(self) -> None:
        self.calls.append("start")
        self.running = True

    def domain_xml(self) -> str:
        return self.dom_xml

    def network_xml(self, name: str) -> str:
        return self.networks[name]

    def close(self) -> None:
        self.calls.append("close")
