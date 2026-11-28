"""Diffs over time: pick snapshots from the store's history and diff them.

* :func:`diff_snapshots` diffs two stored snapshots by content id.
* :func:`diff_device` picks the pair for you (previous vs latest by default, or around ``at``,
  or between ``since`` and ``until``).
* :func:`changes` walks the history and yields one :class:`SnapshotDiff` per change.

Every result holds a text diff (hierarchical for configs, plain lines for command output and
sessions) and, when both snapshots have stored parser output, a semantic diff.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from itertools import pairwise

from routerscope.model import Snapshot, SnapshotKind
from routerscope.services.diff.config import ConfigDiff, ConfigDiffOptions, diff_config
from routerscope.services.diff.semantic import SemanticDiff, diff_objects
from routerscope.services.diff.text import LineDiff, diff_lines
from routerscope.storage import Store
from routerscope.storage.errors import UnknownSnapshotError

__all__ = ["SnapshotDiff", "changes", "diff_device", "diff_snapshots"]


@dataclass(frozen=True, slots=True)
class SnapshotDiff:
    """The difference between two snapshots of the same device and kind."""

    old: Snapshot
    new: Snapshot
    text: ConfigDiff | LineDiff
    semantic: SemanticDiff | None = None
    """``None`` when one side has no stored parser output."""

    @property
    def is_empty(self) -> bool:
        """True if nothing but ignorable noise differs."""
        return self.text.is_empty and (self.semantic is None or self.semantic.is_empty)

    def render_text(self) -> str:
        """The text diff, headed by the two capture times."""
        return self.text.render_text(
            old_label=f"{self.old.captured_at:%Y-%m-%dT%H:%M:%SZ} {self.old.id[:12]}",
            new_label=f"{self.new.captured_at:%Y-%m-%dT%H:%M:%SZ} {self.new.id[:12]}",
        )

    def to_dict(self) -> dict[str, object]:
        def brief(s: Snapshot) -> dict[str, object]:
            return {
                "id": s.id,
                "hostname": s.hostname,
                "vendor": s.vendor,
                "kind": s.kind,
                "command": s.command,
                "captured_at": s.captured_at.isoformat(),
            }

        return {
            "old": brief(self.old),
            "new": brief(self.new),
            "text_kind": "config" if isinstance(self.text, ConfigDiff) else "lines",
            "text": self.text.to_dict(),
            "semantic": None if self.semantic is None else self.semantic.to_dict(),
        }


def _load(store: Store, snapshot_id: str) -> tuple[Snapshot, str]:
    snapshot = store.get_snapshot(snapshot_id)
    content = store.get_content(snapshot_id)
    if snapshot is None or content is None:
        raise UnknownSnapshotError(f"snapshot {snapshot_id[:12]} is not stored")
    return snapshot, content


def _semantic(
    store: Store, old: Snapshot, new: Snapshot, include_volatile: bool
) -> SemanticDiff | None:
    plugin = new.vendor or old.vendor
    if plugin is None:
        return None
    if new.kind == "config":
        a = store.get_parsed_config(old.id, plugin)
        b = store.get_parsed_config(new.id, plugin)
        if a is None or b is None:
            return None
        return diff_objects(a, b, include_volatile=include_volatile)
    if new.kind == "command_output" and new.command:
        c = store.get_parse_result(old.id, plugin, old.command or new.command)
        d = store.get_parse_result(new.id, plugin, new.command)
        if c is None or d is None:
            return None
        return diff_objects(c, d, include_volatile=include_volatile)
    return None


def diff_snapshots(
    store: Store,
    old_id: str,
    new_id: str,
    *,
    include_volatile: bool = False,
    options: ConfigDiffOptions | None = None,
    ignore_lines: Sequence[str] = (),
) -> SnapshotDiff:
    """Diff two stored snapshots (content ids) of the same kind.

    ``include_volatile`` is passed to the semantic diff, ``options`` to the config diff and
    ``ignore_lines`` (regexes) to the plain line diff of non-config snapshots.
    Raises :class:`~routerscope.storage.errors.UnknownSnapshotError` for an unknown id and
    :class:`ValueError` when the two snapshots are of different kinds.
    """
    old, old_text = _load(store, old_id)
    new, new_text = _load(store, new_id)
    if old.kind != new.kind:
        raise ValueError(f"cannot diff a {old.kind} snapshot against a {new.kind} snapshot")
    text: ConfigDiff | LineDiff
    if new.kind == "config":
        text = diff_config(old_text, new_text, new.vendor or old.vendor, options=options)
    else:
        text = diff_lines(old_text, new_text, ignore=ignore_lines)
    return SnapshotDiff(old, new, text, _semantic(store, old, new, include_volatile))


def _history(
    store: Store, hostname: str, kind: SnapshotKind, command: str | None
) -> list[Snapshot]:
    if command is not None:
        kind = "command_output"
    return store.history(hostname, kind, command)


def _collapse(history: list[Snapshot]) -> list[Snapshot]:
    """Drop observations that repeat the content of the previous one."""
    out: list[Snapshot] = []
    for snapshot in history:
        if not out or out[-1].id != snapshot.id:
            out.append(snapshot)
    return out


def _pick_pair(
    history: list[Snapshot],
    since: datetime | None,
    until: datetime | None,
    at: datetime | None,
) -> tuple[Snapshot, Snapshot] | None:
    if at is not None:
        until = at
        since = None
    candidates = [s for s in history if until is None or s.captured_at <= until]
    if not candidates:
        return None
    new = candidates[-1]
    older = [s for s in candidates if s.id != new.id]
    if not older:
        return None
    if since is None:
        return older[-1], new
    baseline = [s for s in older if s.captured_at <= since]
    # Nothing known at ``since``: use the earliest known version as the baseline.
    return (baseline[-1] if baseline else older[0]), new


def diff_device(
    store: Store,
    hostname: str,
    *,
    kind: SnapshotKind = "config",
    command: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    at: datetime | None = None,
    include_volatile: bool = False,
    options: ConfigDiffOptions | None = None,
    ignore_lines: Sequence[str] = (),
) -> SnapshotDiff | None:
    """Diff two versions of a device's config (or of one command's output).

    * default: the version before the latest one (a different content) vs the latest;
    * ``at``: the version in effect at ``at`` vs the one before it ("what changed then");
    * ``until``: like the default but ignoring everything captured after ``until``;
    * ``since``: the version in effect at ``since`` (or the earliest known one) vs the latest
      (as limited by ``until``).

    ``command`` selects a command's output history (``kind`` is then ``command_output``).
    Returns ``None`` when there are not two different versions to compare.
    """
    history = _history(store, hostname, kind, command)
    pair = _pick_pair(history, since, until, at)
    if pair is None:
        return None
    return diff_snapshots(
        store,
        pair[0].id,
        pair[1].id,
        include_volatile=include_volatile,
        options=options,
        ignore_lines=ignore_lines,
    )


def changes(
    store: Store,
    hostname: str,
    *,
    kind: SnapshotKind = "config",
    command: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    include_empty: bool = False,
    include_volatile: bool = False,
    options: ConfigDiffOptions | None = None,
    ignore_lines: Sequence[str] = (),
) -> Iterator[SnapshotDiff]:
    """Timeline: one diff per pair of consecutive versions, oldest first.

    With ``since`` the first pair starts at the version in effect at ``since``; ``until`` stops
    the walk. Pairs whose diff is empty (only noise changed) are skipped unless
    ``include_empty``.
    """
    versions = _collapse(_history(store, hostname, kind, command))
    if until is not None:
        versions = [s for s in versions if s.captured_at <= until]
    if since is not None:
        start = max((i for i, s in enumerate(versions) if s.captured_at <= since), default=0)
        versions = versions[start:]
    for old, new in pairwise(versions):
        result = diff_snapshots(
            store,
            old.id,
            new.id,
            include_volatile=include_volatile,
            options=options,
            ignore_lines=ignore_lines,
        )
        if include_empty or not result.is_empty:
            yield result
