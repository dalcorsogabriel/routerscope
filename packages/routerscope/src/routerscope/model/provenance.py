"""Provenance: Source (how data arrived), Snapshot (what was captured), SourceRef (where)."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Literal, Self

from pydantic import AwareDatetime, Field, field_validator, model_validator

from routerscope.model._base import Frozen, Sha256Hex, VendorId

SourceKind = Literal[
    "file", "session_log", "oxidized", "rancid", "paste", "drop_folder", "collector"
]
SnapshotKind = Literal["config", "command_output", "session"]


class Source(Frozen):
    """How a snapshot arrived."""

    kind: SourceKind
    uri: str = Field(min_length=1, description="File path or URI the data was read from.")
    importer: str = Field(min_length=1, description="Name of the importer that produced it.")
    git_commit: str | None = Field(default=None, description="Commit id for git-backed sources.")


class Snapshot(Frozen):
    """Metadata of one immutable capture. The text itself lives in storage, not here."""

    id: Sha256Hex = Field(description="sha256 hex digest of the content bytes.")
    hostname: str | None = None
    vendor: VendorId | None = None
    kind: SnapshotKind
    command: str | None = None
    captured_at: AwareDatetime
    source: Source
    size: int = Field(ge=0, description="Content size in bytes.")
    line_count: int = Field(ge=0)

    @field_validator("captured_at")
    @classmethod
    def _to_utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)


class SourceRef(Frozen):
    """Exact lines of a snapshot an object was parsed from (1-based, inclusive)."""

    snapshot_id: Sha256Hex
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.line_end < self.line_start:
            raise ValueError("line_end must be >= line_start")
        return self


def content_digest(content: str | bytes) -> str:
    """Return the sha256 hex digest used as a snapshot id (text is hashed as UTF-8)."""
    data = content.encode("utf-8") if isinstance(content, str) else content
    return hashlib.sha256(data).hexdigest()


def make_snapshot(
    content: str | bytes,
    *,
    source: Source,
    kind: SnapshotKind,
    captured_at: datetime,
    hostname: str | None = None,
    vendor: str | None = None,
    command: str | None = None,
) -> Snapshot:
    """Build a :class:`Snapshot` from content plus metadata.

    ``captured_at`` must be timezone-aware. The line count follows ``str.splitlines`` on the
    UTF-8 decoded text (undecodable bytes are replaced).
    """
    data = content.encode("utf-8") if isinstance(content, str) else content
    text = content if isinstance(content, str) else data.decode("utf-8", errors="replace")
    return Snapshot(
        id=hashlib.sha256(data).hexdigest(),
        hostname=hostname,
        vendor=vendor,
        kind=kind,
        command=command,
        captured_at=captured_at,
        source=source,
        size=len(data),
        line_count=len(text.splitlines()),
    )
