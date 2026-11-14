from __future__ import annotations

from datetime import UTC, datetime

import pytest
from conftest import NAT_NET, FakeHypervisor, FakeRemote, domain_xml, net_iface

from gaphunter.config import Config
from gaphunter.errors import LabError
from gaphunter.lab.vm import (
    check_lab,
    guest_info,
    guest_utc_now,
    isolation_problems,
    revert_and_wait,
    wait_until_ready,
)
from gaphunter.remote import CommandResult


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def test_isolated_network_passes() -> None:
    assert isolation_problems(FakeHypervisor()) == []


def test_nat_network_is_flagged() -> None:
    hv = FakeHypervisor(dom_xml=domain_xml(net_iface("default")))
    problems = isolation_problems(hv)
    assert len(problems) == 1 and "mode=nat" in problems[0]


def test_unverifiable_interfaces_are_flagged() -> None:
    hv = FakeHypervisor(
        dom_xml=domain_xml(
            "<interface type='user'/>",
            "<interface type='bridge'><source bridge='br0'/></interface>",
            net_iface("gaphunter-isolated"),
        )
    )
    problems = isolation_problems(hv)
    assert len(problems) == 2
    assert all("cannot be verified" in p for p in problems)


def test_vm_without_nic_is_isolated() -> None:
    assert isolation_problems(FakeHypervisor(dom_xml=domain_xml())) == []


def test_wait_until_ready_retries_then_succeeds(config: Config) -> None:
    clock = Clock()
    remote = FakeRemote(reachable=[False, False, True])
    waited = wait_until_ready(remote, config.lab, sleep=clock.sleep, clock=clock)
    assert remote.reachable_calls == 3
    assert waited == 2.0


def test_wait_until_ready_times_out(config: Config) -> None:
    clock = Clock()
    with pytest.raises(LabError, match="did not answer"):
        wait_until_ready(FakeRemote(reachable=False), config.lab, sleep=clock.sleep, clock=clock)
    assert clock.now >= config.lab.ready_timeout_s


def test_revert_and_wait_starts_a_shut_off_domain(config: Config) -> None:
    clock = Clock()
    hv = FakeHypervisor(running_after_revert=False)
    revert_and_wait(hv, FakeRemote(), config.lab, sleep=clock.sleep, clock=clock)
    assert hv.calls == ["revert:clean", "start"]


def test_revert_requires_the_snapshot(config: Config) -> None:
    hv = FakeHypervisor(snapshots=["other"])
    with pytest.raises(LabError, match="does not exist"):
        revert_and_wait(hv, FakeRemote(), config.lab)
    assert hv.calls == []


def test_guest_utc_now_returns_time_and_pid() -> None:
    remote = FakeRemote(lambda s: CommandResult(0, "2026-11-14T02:16:00.1234567Z|4242\r\n", ""))
    stamp, pid = guest_utc_now(remote)
    assert stamp == datetime(2026, 11, 14, 2, 16, 0, 123456, tzinfo=UTC)
    assert pid == 4242


def test_guest_info_parses_key_values() -> None:
    out = "os_build=19045\r\nsysmon_state=Running\r\nsysmon_config_hash=SHA256=AB=CD\r\nnoise\r\n"
    info = guest_info(FakeRemote(lambda s: CommandResult(0, out, "")))
    assert info == {
        "os_build": "19045",
        "sysmon_state": "Running",
        "sysmon_config_hash": "SHA256=AB=CD",
    }


def _info_handler(script: str) -> CommandResult:
    if "Win32_OperatingSystem" in script:
        out = (
            "sysmon_service=Sysmon64\nsysmon_state=Running\nsysmon_version=15.15\n"
            "defender_realtime=False\ndefender_tamper_protection=False\n"
        )
        return CommandResult(0, out, "")
    return CommandResult(0, "", "")


def test_check_lab_all_ok(config: Config) -> None:
    results = check_lab(FakeHypervisor(), FakeRemote(_info_handler), config)
    assert [r.name for r in results] == [
        "snapshot",
        "isolation",
        "snapshot-kind",
        "vm-running",
        "ssh",
        "sysmon",
        "defender",
        "channels",
    ]
    assert all(r.ok for r in results)
    defender = next(r for r in results if r.name == "defender")
    assert defender.detail == "real-time protection off, tamper protection False"


def test_check_lab_reports_missing_snapshot_and_nat(config: Config) -> None:
    hv = FakeHypervisor(
        snapshots=[],
        dom_xml=domain_xml(net_iface("default")),
        networks={"default": NAT_NET},
    )
    by_name = {r.name: r for r in check_lab(hv, FakeRemote(_info_handler), config)}
    assert not by_name["snapshot"].ok and "none" in by_name["snapshot"].detail
    assert not by_name["isolation"].ok


def test_check_lab_stops_when_vm_is_off_or_unreachable(config: Config) -> None:
    off = check_lab(FakeHypervisor(running=False), FakeRemote(), config)
    assert off[-1].name == "vm-running" and not off[-1].ok and not off[-1].fatal
    unreachable = check_lab(FakeHypervisor(), FakeRemote(reachable=False), config)
    assert unreachable[-1].name == "ssh" and not unreachable[-1].ok


def test_check_lab_flags_stopped_sysmon(config: Config) -> None:
    remote = FakeRemote(lambda s: CommandResult(0, "sysmon_state=Stopped\n", ""))
    by_name = {r.name: r for r in check_lab(FakeHypervisor(), remote, config)}
    assert not by_name["sysmon"].ok


# -- taking the clean snapshot -------------------------------------------------------


def test_take_snapshot_live_and_offline(config: Config) -> None:
    from gaphunter.lab.vm import take_snapshot

    live = FakeHypervisor(snapshots=[])
    assert take_snapshot(live, config.lab) == "live"
    assert live.calls == ["snapshot:clean"]

    offline = FakeHypervisor(snapshots=[], running=False)
    assert take_snapshot(offline, config.lab) == "offline"
    by_name = {r.name: r for r in check_lab(offline, FakeRemote(), config)}
    assert by_name["snapshot-kind"].ok and "offline" in by_name["snapshot-kind"].detail


def test_take_snapshot_refuses_a_vm_that_is_not_isolated(config: Config) -> None:
    from gaphunter.lab.vm import take_snapshot

    hv = FakeHypervisor(
        snapshots=[], dom_xml=domain_xml(net_iface("default")), networks={"default": NAT_NET}
    )
    with pytest.raises(LabError, match="not isolated"):
        take_snapshot(hv, config.lab)
    assert hv.calls == []


def test_take_snapshot_replace(config: Config) -> None:
    from gaphunter.lab.vm import take_snapshot

    hv = FakeHypervisor()
    with pytest.raises(LabError, match="already exists"):
        take_snapshot(hv, config.lab)
    take_snapshot(hv, config.lab, replace=True)
    assert hv.calls == ["delete:clean", "snapshot:clean"]


def test_uefi_snapshot_refusal_is_explained(config: Config) -> None:
    from gaphunter.lab.vm import explain_snapshot_error, take_snapshot

    hv = FakeHypervisor(snapshots=[])
    hv.snapshot_error = (
        "Operation not supported: internal snapshots of a VM with pflash based firmware "
        "require QCOW2 nvram format"
    )
    with pytest.raises(LabError) as info:
        take_snapshot(hv, config.lab)
    text = str(info.value)
    assert "offline snapshot" in text and "qcow2" in text and "gh-win11" in text
    assert explain_snapshot_error("disk full", "x") == "snapshot failed: disk full"


def test_check_lab_warns_when_defender_is_on(config: Config) -> None:
    remote = FakeRemote(
        lambda s: CommandResult(0, "sysmon_state=Running\ndefender_realtime=True\n", "")
    )
    by_name = {r.name: r for r in check_lab(FakeHypervisor(), remote, config)}
    assert not by_name["defender"].ok and not by_name["defender"].fatal
    assert "README" in by_name["defender"].detail
