"""libvirt control of the lab VM and pre-flight checks.

``libvirt`` is imported lazily so that parsing, tests and analysis work on machines
without libvirt installed.
"""

from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from gaphunter.config import Config, LabConfig
from gaphunter.errors import LabError, RemoteError
from gaphunter.log import get_logger
from gaphunter.remote import Remote, ps_quote
from gaphunter.timeutil import parse_utc

log = get_logger(__name__)


class Hypervisor(Protocol):
    def snapshot_names(self) -> list[str]: ...
    def is_running(self) -> bool: ...
    def revert(self, snapshot: str) -> None: ...
    def start(self) -> None: ...
    def domain_xml(self) -> str: ...
    def network_xml(self, name: str) -> str: ...
    def snapshot_xml(self, name: str) -> str: ...
    def create_snapshot(self, name: str, description: str) -> None: ...
    def delete_snapshot(self, name: str) -> None: ...
    def close(self) -> None: ...


class LibvirtHypervisor:
    """Real implementation on top of libvirt-python."""

    def __init__(self, lab: LabConfig) -> None:
        try:
            import libvirt
        except ImportError as exc:
            raise LabError(
                "libvirt-python is not installed. Install with: pip install 'gaphunter[lab]'"
            ) from exc
        self._libvirt: Any = libvirt
        self._lab = lab
        try:
            self._conn: Any = libvirt.open(lab.libvirt_uri)
            self._dom: Any = self._conn.lookupByName(lab.domain)
        except libvirt.libvirtError as exc:
            raise LabError(
                f"cannot open domain {lab.domain!r} at {lab.libvirt_uri}: {exc}"
            ) from exc

    def snapshot_names(self) -> list[str]:
        try:
            return list(self._dom.snapshotListNames())
        except self._libvirt.libvirtError as exc:
            raise LabError(f"cannot list snapshots: {exc}") from exc

    def is_running(self) -> bool:
        return bool(self._dom.isActive())

    def revert(self, snapshot: str) -> None:
        try:
            snap = self._dom.snapshotLookupByName(snapshot)
            flags = (
                self._libvirt.VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING
                | self._libvirt.VIR_DOMAIN_SNAPSHOT_REVERT_FORCE
            )
            self._dom.revertToSnapshot(snap, flags)
        except self._libvirt.libvirtError as exc:
            raise LabError(f"revert to snapshot {snapshot!r} failed: {exc}") from exc

    def start(self) -> None:
        try:
            self._dom.create()
        except self._libvirt.libvirtError as exc:
            raise LabError(f"cannot start domain: {exc}") from exc

    def domain_xml(self) -> str:
        return str(self._dom.XMLDesc())

    def network_xml(self, name: str) -> str:
        try:
            return str(self._conn.networkLookupByName(name).XMLDesc())
        except self._libvirt.libvirtError as exc:
            raise LabError(f"cannot read libvirt network {name!r}: {exc}") from exc

    def snapshot_xml(self, name: str) -> str:
        try:
            return str(self._dom.snapshotLookupByName(name).getXMLDesc())
        except self._libvirt.libvirtError as exc:
            raise LabError(f"cannot read snapshot {name!r}: {exc}") from exc

    def create_snapshot(self, name: str, description: str) -> None:
        root = ET.Element("domainsnapshot")
        ET.SubElement(root, "name").text = name
        ET.SubElement(root, "description").text = description
        try:
            self._dom.snapshotCreateXML(ET.tostring(root, encoding="unicode"), 0)
        except self._libvirt.libvirtError as exc:
            raise LabError(explain_snapshot_error(str(exc), self._lab.domain)) from exc

    def delete_snapshot(self, name: str) -> None:
        try:
            self._dom.snapshotLookupByName(name).delete(0)
        except self._libvirt.libvirtError as exc:
            raise LabError(f"cannot delete snapshot {name!r}: {exc}") from exc

    def close(self) -> None:
        try:
            self._conn.close()
        except self._libvirt.libvirtError:  # pragma: no cover - best effort
            pass


# -- snapshots -----------------------------------------------------------------------


def explain_snapshot_error(message: str, domain: str) -> str:
    """Turn libvirt's UEFI snapshot refusal into something actionable.

    Windows 11 needs UEFI firmware. libvirt can only include a UEFI guest's NVRAM in an
    internal snapshot when that NVRAM file is qcow2, and refuses a live snapshot otherwise.
    """
    lowered = message.lower()
    if "pflash" in lowered or "nvram" in lowered:
        return (
            f"libvirt refused the snapshot: {message}\n"
            "This VM uses UEFI firmware with a raw NVRAM file. Either:\n"
            f"  1. shut the VM down (virsh shutdown {domain}) and run 'gaphunter lab snapshot' "
            "again for an offline snapshot (GapHunter then boots the VM after every revert), or\n"
            "  2. convert the NVRAM to qcow2 as described under 'UEFI and snapshots' in the "
            "README, then snapshot the running VM (reverts take seconds)."
        )
    return f"snapshot failed: {message}"


def snapshot_kind(hv: Hypervisor, name: str) -> str:
    """``live`` if the snapshot holds the running guest's memory, else ``offline``."""
    root = ET.fromstring(hv.snapshot_xml(name))
    memory = root.find("memory")
    state = (root.findtext("state") or "").strip()
    has_memory = memory is not None and memory.get("snapshot", "no") not in ("no", "")
    return "live" if has_memory and state in ("running", "paused") else "offline"


def take_snapshot(hv: Hypervisor, lab: LabConfig, *, replace: bool = False) -> str:
    """Create the clean snapshot, refusing if the VM is not isolated. Returns its kind."""
    problems = isolation_problems(hv)
    if problems:
        raise LabError(
            "refusing to snapshot a VM that is not isolated: "
            + "; ".join(problems)
            + ". Attach it to the isolated network first."
        )
    if lab.snapshot in hv.snapshot_names():
        if not replace:
            raise LabError(
                f"snapshot {lab.snapshot!r} already exists; pass --replace to recreate it"
            )
        hv.delete_snapshot(lab.snapshot)
    hv.create_snapshot(lab.snapshot, "GapHunter clean state")
    kind = snapshot_kind(hv, lab.snapshot)
    log.info("lab.snapshot", domain=lab.domain, snapshot=lab.snapshot, kind=kind)
    return kind


# -- isolation -----------------------------------------------------------------------


def isolation_problems(hv: Hypervisor) -> list[str]:
    """Return reasons the VM might reach beyond the host; empty means isolated.

    A libvirt network without a ``<forward>`` element is isolated: guests can talk to the
    host and to each other, nothing else. Anything we cannot prove isolated is reported.
    """
    problems: list[str] = []
    root = ET.fromstring(hv.domain_xml())
    interfaces = root.findall("./devices/interface")
    for iface in interfaces:
        kind = iface.get("type", "?")
        if kind != "network":
            problems.append(
                f"interface of type {kind!r} cannot be verified as isolated "
                "(use a libvirt network without <forward>)"
            )
            continue
        source = iface.find("source")
        name = source.get("network") if source is not None else None
        if not name:
            problems.append("network interface without a source network")
            continue
        net = ET.fromstring(hv.network_xml(name))
        forward = net.find("forward")
        if forward is not None:
            mode = forward.get("mode", "nat")
            problems.append(f"network {name!r} forwards traffic (mode={mode}); it is not isolated")
    return problems


# -- readiness -----------------------------------------------------------------------


def wait_until_ready(
    remote: Remote,
    lab: LabConfig,
    *,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> float:
    """Poll SSH until the guest answers, then let it settle. Returns seconds waited."""
    started = clock()
    deadline = started + lab.ready_timeout_s
    attempt = 0
    while True:
        attempt += 1
        if remote.is_reachable():
            break
        if clock() >= deadline:
            raise LabError(
                f"VM did not answer over SSH within {lab.ready_timeout_s}s "
                f"({attempt} attempts). Is sshd running in the snapshot?"
            )
        sleep(lab.ready_poll_s)
    if lab.settle_s:
        sleep(lab.settle_s)
    waited = clock() - started
    log.info("lab.ready", waited_s=round(waited, 1), attempts=attempt)
    return waited


def revert_and_wait(
    hv: Hypervisor,
    remote: Remote,
    lab: LabConfig,
    *,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> float:
    """Revert the VM to the clean snapshot, make sure it runs, wait for SSH."""
    if lab.snapshot not in hv.snapshot_names():
        raise LabError(f"snapshot {lab.snapshot!r} does not exist on domain {lab.domain!r}")
    log.info("lab.revert", domain=lab.domain, snapshot=lab.snapshot)
    hv.revert(lab.snapshot)
    if not hv.is_running():
        # Offline (disk-only) snapshot: the revert leaves the domain shut off.
        hv.start()
    return wait_until_ready(remote, lab, sleep=sleep, clock=clock)


# -- guest facts ---------------------------------------------------------------------

_GUEST_INFO_SCRIPT = r"""
$os = Get-CimInstance Win32_OperatingSystem
Write-Output ("os_caption=" + $os.Caption)
Write-Output ("os_build=" + $os.BuildNumber)
Write-Output ("hostname=" + $env:COMPUTERNAME)
$svc = Get-CimInstance Win32_Service -Filter "Name like 'Sysmon%'" | Select-Object -First 1
if ($svc) {
  Write-Output ("sysmon_service=" + $svc.Name)
  Write-Output ("sysmon_state=" + $svc.State)
  $exe = $svc.PathName.Trim('"')
  if (Test-Path $exe) { Write-Output ("sysmon_version=" + (Get-Item $exe).VersionInfo.FileVersion) }
}
$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters'
$drv = Get-ItemProperty $key -ErrorAction SilentlyContinue
if ($drv -and $drv.ConfigHash) { Write-Output ("sysmon_config_hash=" + $drv.ConfigHash) }
"""

_UTC_NOW_SCRIPT = "Write-Output ([DateTime]::UtcNow.ToString('o') + '|' + $PID)"


def guest_info(remote: Remote) -> dict[str, str]:
    """OS build, Sysmon version and Sysmon config hash, for the run manifest."""
    out = remote.run_powershell(_GUEST_INFO_SCRIPT).stdout
    info: dict[str, str] = {}
    for line in out.splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key:
            info[key] = value.strip()
    return info


def guest_utc_now(remote: Remote) -> tuple[datetime, int | None]:
    """The guest's clock in UTC, plus the PID of the PowerShell process that read it.

    Session windows use the guest clock, because event timestamps come from it and the
    clock jumps back whenever the snapshot is reverted. The PID is kept so that later
    stages can tell GapHunter's own control-channel processes apart from everything else.
    """
    lines = remote.run_powershell(_UTC_NOW_SCRIPT).stdout.strip().splitlines()
    if not lines:
        raise RemoteError("guest returned no timestamp")
    stamp, _, pid = lines[-1].strip().partition("|")
    return parse_utc(stamp), int(pid) if pid.strip().isdigit() else None


# -- pre-flight ----------------------------------------------------------------------


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    detail: str
    fatal: bool = True


def check_lab(hv: Hypervisor, remote: Remote, config: Config) -> list[CheckResult]:
    """Pre-flight checks for ``gaphunter lab check``. Never raises for an expected failure."""
    results: list[CheckResult] = []
    lab = config.lab

    snapshots = hv.snapshot_names()
    results.append(
        CheckResult(
            "snapshot",
            lab.snapshot in snapshots,
            f"{lab.snapshot!r} found"
            if lab.snapshot in snapshots
            else f"{lab.snapshot!r} missing (have: {', '.join(snapshots) or 'none'})",
        )
    )

    try:
        problems = isolation_problems(hv)
    except (LabError, ET.ParseError) as exc:
        problems = [f"could not inspect networking: {exc}"]
    results.append(
        CheckResult("isolation", not problems, "; ".join(problems) or "no forwarding network")
    )

    if lab.snapshot in snapshots:
        try:
            kind = snapshot_kind(hv, lab.snapshot)
        except (LabError, ET.ParseError) as exc:
            results.append(CheckResult("snapshot-kind", False, str(exc), fatal=False))
        else:
            detail = (
                "live (reverts take seconds)"
                if kind == "live"
                else "offline (the VM boots after every revert; slower but fine)"
            )
            results.append(CheckResult("snapshot-kind", True, detail, fatal=False))

    running = hv.is_running()
    results.append(
        CheckResult("vm-running", running, "running" if running else "shut off", fatal=False)
    )
    if not running:
        return results

    reachable = remote.is_reachable()
    results.append(
        CheckResult("ssh", reachable, "PowerShell over SSH works" if reachable else "no answer")
    )
    if not reachable:
        return results

    try:
        info = guest_info(remote)
    except RemoteError as exc:
        results.append(CheckResult("guest-info", False, str(exc)))
        return results
    sysmon_ok = info.get("sysmon_state") == "Running"
    results.append(
        CheckResult(
            "sysmon",
            sysmon_ok,
            f"{info.get('sysmon_service', 'Sysmon')} {info.get('sysmon_version', '?')} running"
            if sysmon_ok
            else "Sysmon service not running",
        )
    )

    probe = "\n".join(
        f"$null = Get-WinEvent -ListLog {ps_quote(ch)}" for ch in config.collector.channels.values()
    )
    try:
        remote.run_powershell(probe)
        results.append(CheckResult("channels", True, "all configured log channels exist"))
    except RemoteError as exc:
        results.append(CheckResult("channels", False, str(exc)))
    return results
