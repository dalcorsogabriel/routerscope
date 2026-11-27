"""The contract shared by every importer.

An importer turns some outside material (a terminal log, a git history of configs, pasted
text, a file dropped in a folder) into :class:`ImportItem` values. It never touches the
database and never talks to devices: :func:`routerscope.services.ingest.ingest` stores the
items (redacting them first) and runs the vendor parsers.

Rules for importers:

* Yield items in the order the material was produced (oldest first) when that is known.
* ``captured_at`` must be timezone-aware. Use the best time available (log timestamps, commit
  time, file modification time) and say in the importer docs which one.
* Leave ``vendor`` as ``None`` when unsure; ingestion detects it.
* A session log yields one ``session`` item with the whole (normalized) log plus one
  ``command_output`` item per command found in it, so each command's output has its own
  history and diff.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from routerscope.model import Source
from routerscope.model.provenance import SnapshotKind

__all__ = ["ImportItem", "Importer"]


@dataclass(frozen=True, slots=True)
class ImportItem:
    """One piece of material to store as a snapshot."""

    content: str | bytes
    kind: SnapshotKind
    captured_at: datetime
    source: Source
    hostname: str | None = None
    vendor: str | None = None
    command: str | None = None

    def __post_init__(self) -> None:
        if self.captured_at.tzinfo is None or self.captured_at.utcoffset() is None:
            raise ValueError("captured_at must be timezone-aware")
        if self.kind == "command_output" and not self.command:
            raise ValueError("a command_output item needs the command")


@runtime_checkable
class Importer(Protocol):
    """Anything that yields :class:`ImportItem` values."""

    name: str
    """Short id recorded in ``Source.importer`` (``"securecrt"``, ``"oxidized"``...)."""

    def items(self) -> Iterator[ImportItem]:
        """Yield the items; may raise :class:`ImportError_` for unreadable material."""
        ...


class ImportError_(Exception):
    """The material cannot be imported (unknown format, unreadable file...)."""
