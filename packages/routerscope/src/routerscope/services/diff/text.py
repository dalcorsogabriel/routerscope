"""Plain line diff for command outputs and sessions (no structure to exploit)."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Literal

from routerscope.model import split_lines

__all__ = ["LineChange", "LineDiff", "diff_lines"]


@dataclass(frozen=True, slots=True)
class LineChange:
    """One added or removed line with its 1-based line number on the side where it exists."""

    op: Literal["added", "removed"]
    text: str
    old_line: int | None
    new_line: int | None

    def to_dict(self) -> dict[str, object]:
        return {
            "op": self.op,
            "text": self.text,
            "old_line": self.old_line,
            "new_line": self.new_line,
        }


@dataclass(slots=True)
class LineDiff:
    """Result of :func:`diff_lines`."""

    changes: list[LineChange] = field(default_factory=list)
    rows: list[tuple[str, str]] = field(default_factory=list, repr=False)
    """Every compared line as ``(marker, text)``; marker is ``" "``, ``"-"`` or ``"+"``."""

    @property
    def is_empty(self) -> bool:
        return not self.changes

    def render_text(
        self, *, context: int = 3, old_label: str = "old", new_label: str = "new"
    ) -> str:
        """Unified-style text with ``context`` unchanged lines around each change."""
        if not self.changes:
            return ""
        keep = [False] * len(self.rows)
        for index, (mark, _text) in enumerate(self.rows):
            if mark != " ":
                for near in range(max(0, index - context), min(len(keep), index + context + 1)):
                    keep[near] = True
        out = [f"--- {old_label}", f"+++ {new_label}"]
        skipping = False
        for index, (mark, text) in enumerate(self.rows):
            if keep[index]:
                out.append(f"{mark}{text}")
                skipping = False
            elif not skipping:
                out.append("...")
                skipping = True
        return "\n".join(out)

    def to_dict(self) -> dict[str, object]:
        return {
            "added": sum(c.op == "added" for c in self.changes),
            "removed": sum(c.op == "removed" for c in self.changes),
            "changes": [c.to_dict() for c in self.changes],
        }


def diff_lines(
    old: str,
    new: str,
    *,
    ignore: Sequence[str] = (),
    ignore_whitespace: bool = True,
) -> LineDiff:
    """Line diff of two texts.

    Lines matching any ``ignore`` regex (``re.search``) are dropped from both sides before the
    comparison (line numbers still refer to the original texts). With ``ignore_whitespace``
    runs of whitespace and trailing spaces are not differences.
    """
    patterns = [re.compile(p) for p in ignore]

    def prepare(text: str) -> list[tuple[int, str]]:
        return [
            (number, line)
            for number, line in enumerate(split_lines(text), start=1)
            if not any(p.search(line) for p in patterns)
        ]

    def norm(line: str) -> str:
        return " ".join(line.split()) if ignore_whitespace else line

    a, b = prepare(old), prepare(new)
    matcher = SequenceMatcher(
        None, [norm(t) for _, t in a], [norm(t) for _, t in b], autojunk=False
    )
    result = LineDiff()
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            result.rows.extend((" ", text) for _, text in a[i1:i2])
            continue
        for number, text in a[i1:i2]:
            result.changes.append(LineChange("removed", text, number, None))
            result.rows.append(("-", text))
        for number, text in b[j1:j2]:
            result.changes.append(LineChange("added", text, None, number))
            result.rows.append(("+", text))
    return result
