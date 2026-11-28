"""Import RANCID configuration history kept in git.

A RANCID group directory holds ``router.db`` (``name;type;state``, or ``name:type:state`` in
older versions) and ``configs/<device>`` files. ``RancidImporter(path)`` accepts either one
group directory or a base directory containing several of them. History comes from git
(each group directory must be inside a git repository). RANCID's default CVS and Subversion
histories are **not supported**: the importer raises :class:`ImportError_` and tells you to
convert the history (for example with ``cvs2git``) or to use RANCID with git.

Content is kept exactly as committed, including RANCID's ``!RANCID-CONTENT-TYPE`` header
lines. The vendor is taken from that header of each version when present, else from the
device's ``type`` in ``router.db``, else ``None`` (ingestion detects it). The hostname is
the file name under ``configs/`` when it is a safe hostname. ``captured_at`` is the
commit's committer time.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from datetime import datetime
from pathlib import Path, PurePosixPath

from routerscope.capture.importers.base import ImportError_, ImportItem
from routerscope.capture.importers.git_history import (
    is_git_repository,
    safe_hostname,
    walk_history,
)
from routerscope.model import Source

__all__ = ["RANCID_TYPES", "RancidImporter", "parse_router_db"]

RANCID_TYPES: Mapping[str, str] = {
    "cisco": "cisco_ios",
    "cisco-xr": "cisco_xr",
    "cisco_xr": "cisco_xr",
    "ios-xr": "cisco_xr",
    "iosxr": "cisco_xr",
    "juniper": "juniper_junos",
    "junos": "juniper_junos",
    "huawei": "huawei_vrp",
    "vrp": "huawei_vrp",
    "mikrotik": "mikrotik_ros7",
    "routeros": "mikrotik_ros7",
    "nokia": "nokia_sros",
    "alu": "nokia_sros",
    "sros": "nokia_sros",
    "timos": "nokia_sros",
    "ocnos": "ipinfusion_ocnos",
    "ipinfusion": "ipinfusion_ocnos",
}
"""RANCID device type (or ``!RANCID-CONTENT-TYPE`` value) -> routerscope vendor id."""

_HEADER = re.compile(r"^!RANCID-CONTENT-TYPE:\s*(\S+)", re.MULTILINE)
_VCS_MARKERS = ("CVS", "CVSROOT", ".svn")


def _vendor_for_type(rancid_type: str | None) -> str | None:
    return RANCID_TYPES.get(rancid_type.strip().lower()) if rancid_type else None


def parse_router_db(text: str) -> dict[str, str]:
    """Parse ``router.db`` into ``{device name: rancid type}`` (``;`` or ``:`` separated)."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        fields = re.split(r"[;:]", line)
        if len(fields) >= 2 and fields[0].strip() and fields[1].strip():
            result[fields[0].strip()] = fields[1].strip()
    return result


class RancidImporter:
    """Yield one ``config`` item per (device file, commit) of a RANCID git history."""

    name = "rancid"

    def __init__(
        self,
        path: Path | str,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> None:
        self.path = Path(path)
        self.since = since
        self.until = until

    def _groups(self) -> list[Path]:
        if not self.path.is_dir():
            raise ImportError_(f"not a directory: {self.path}")
        if (self.path / "router.db").is_file():
            return [self.path]
        groups = sorted(p for p in self.path.iterdir() if (p / "router.db").is_file())
        if not groups:
            raise ImportError_(f"no router.db found in {self.path} or its subdirectories")
        return groups

    @staticmethod
    def _check_vcs(group: Path) -> None:
        if is_git_repository(group):
            return
        for directory in (group, group.parent):
            if any((directory / marker).exists() for marker in _VCS_MARKERS):
                raise ImportError_(
                    f"{group} keeps its history in CVS or Subversion, which is not supported; "
                    "convert it to git (for example with cvs2git) or use RANCID with git"
                )
        raise ImportError_(f"{group} is not inside a git repository")

    def items(self) -> Iterator[ImportItem]:
        for group in self._groups():
            self._check_vcs(group)
            db = parse_router_db(
                (group / "router.db").read_text(encoding="utf-8", errors="replace")
            )
            lower = {k.lower(): v for k, v in db.items()}
            uri = str(group.resolve())
            for version in walk_history(
                group, since=self.since, until=self.until, paths=["configs/*"]
            ):
                file_name = PurePosixPath(version.path).name
                if file_name.startswith("."):
                    continue
                hostname = safe_hostname(file_name)
                text = (
                    version.content
                    if isinstance(version.content, str)
                    else version.content.decode("utf-8", errors="replace")
                )
                header = _HEADER.search(text)
                vendor = _vendor_for_type(header.group(1) if header else None)
                if vendor is None:
                    vendor = _vendor_for_type(db.get(file_name) or lower.get(file_name.lower()))
                yield ImportItem(
                    content=version.content,
                    kind="config",
                    captured_at=version.committed_at,
                    source=Source(
                        kind="rancid", uri=uri, importer=self.name, git_commit=version.commit
                    ),
                    hostname=hostname,
                    vendor=vendor,
                )
