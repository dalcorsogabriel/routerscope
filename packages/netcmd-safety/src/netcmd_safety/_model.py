"""Public data types: verdicts, CLI modes, classification results and vendor IDs."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

CISCO_IOS = "cisco_ios"
CISCO_XR = "cisco_xr"
HUAWEI_VRP = "huawei_vrp"
MIKROTIK_ROS7 = "mikrotik_ros7"
JUNIPER_JUNOS = "juniper_junos"
NOKIA_SROS = "nokia_sros"
IPINFUSION_OCNOS = "ipinfusion_ocnos"

VENDORS: tuple[str, ...] = (
    CISCO_IOS,
    CISCO_XR,
    HUAWEI_VRP,
    MIKROTIK_ROS7,
    JUNIPER_JUNOS,
    NOKIA_SROS,
    IPINFUSION_OCNOS,
)


class Verdict(StrEnum):
    """What a command does to the device, from harmless to dangerous.

    - ``READ``: only displays information.
    - ``SESSION``: changes the current CLI session only (paging, width, leaving a mode).
    - ``UNKNOWN``: not recognized. Treat it as unsafe (fail closed).
    - ``CONFIG``: changes configuration or enters configuration mode.
    - ``DESTRUCTIVE``: removes or disables configuration, resets sessions or counters,
      reboots, or writes/deletes files.
    """

    READ = "read"
    SESSION = "session"
    UNKNOWN = "unknown"
    CONFIG = "config"
    DESTRUCTIVE = "destructive"

    @property
    def severity(self) -> int:
        """Rank used to pick the worst verdict (READ=0 ... DESTRUCTIVE=4)."""
        return _SEVERITY[self]


_SEVERITY: dict[Verdict, int] = {
    Verdict.READ: 0,
    Verdict.SESSION: 1,
    Verdict.UNKNOWN: 2,
    Verdict.CONFIG: 3,
    Verdict.DESTRUCTIVE: 4,
}


class Mode(StrEnum):
    """CLI mode the command is typed in."""

    EXEC = "exec"
    CONFIG = "config"


@dataclass(frozen=True, slots=True)
class Classification:
    """Result of classifying one command."""

    command: str
    vendor: str
    verdict: Verdict
    reason: str
    mode: Mode | None = None
    next_mode: Mode | None = None
    """Mode the CLI is in after this command (used to classify multi-line input)."""

    @property
    def is_read(self) -> bool:
        """True only for commands that just display information."""
        return self.verdict is Verdict.READ

    @property
    def collector_safe(self) -> bool:
        """True if an automated read-only collector may send this command."""
        return self.verdict in (Verdict.READ, Verdict.SESSION)


class UnknownVendorError(ValueError):
    """Raised when the vendor ID is not one of :data:`VENDORS`."""


def worst(verdicts: list[Verdict] | tuple[Verdict, ...]) -> Verdict:
    """Return the most dangerous verdict; an empty sequence is ``UNKNOWN``."""
    if not verdicts:
        return Verdict.UNKNOWN
    return max(verdicts, key=lambda v: v.severity)
