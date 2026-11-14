"""VM lifecycle: snapshot revert, readiness and lab sanity checks."""

from gaphunter.lab.vm import (
    CheckResult,
    Hypervisor,
    LibvirtHypervisor,
    check_lab,
    guest_info,
    guest_utc_now,
    revert_and_wait,
    wait_until_ready,
)

__all__ = [
    "CheckResult",
    "Hypervisor",
    "LibvirtHypervisor",
    "check_lab",
    "guest_info",
    "guest_utc_now",
    "revert_and_wait",
    "wait_until_ready",
]
