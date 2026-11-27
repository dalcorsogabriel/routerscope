"""Line splitting that keeps line endings and tracks block context."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

_EOL = re.compile(r"\r\n|\n|\r")
_ROS_PATH = re.compile(r"/[A-Za-z]")
# RouterOS prompt: "[admin@router] > /system identity print" or "[admin@router] /ip firewall> print"
_ROS_PROMPT = re.compile(r"\[[^\]\n]+@[^\]\n]+\]\s*(?P<path>/[^>\n]*)?>\s*(?P<cmd>/\S.*)?$")


@dataclass(frozen=True, slots=True)
class Line:
    """One physical line.

    ``context`` holds the stripped ancestor lines (by indentation, outermost first) and
    ``ros_path`` the last RouterOS ``/path`` line seen (lowercase), or ``""``.
    """

    number: int
    start: int
    body: str
    eol: str
    context: tuple[str, ...]
    ros_path: str


@dataclass(frozen=True, slots=True)
class Rule:
    """A regex whose named group ``v`` is the value of interest, optionally context-gated."""

    name: str
    pattern: re.Pattern[str]
    ctx: re.Pattern[str] | None = None
    ros: bool = False  # ctx is tested against the RouterOS path instead of ancestors
    parent_only: bool = False  # ctx is tested only against the direct parent line
    vendors: frozenset[str] | None = None  # rule only applies when the vendor hint matches

    def applies(self, line: Line, vendor: str | None) -> bool:
        if self.vendors is not None and vendor not in self.vendors:
            return False
        if self.ctx is None:
            return True
        if self.ros:
            return self.ctx.search(line.ros_path) is not None
        targets = line.context[-1:] if self.parent_only else line.context
        return any(self.ctx.search(t) for t in targets)


def rule(name: str, pattern: str, **kw: object) -> Rule:
    """Build a case-insensitive :class:`Rule`."""
    ctx = kw.pop("ctx", None)
    compiled_ctx = re.compile(str(ctx), re.IGNORECASE) if ctx is not None else None
    return Rule(name, re.compile(pattern, re.IGNORECASE), compiled_ctx, **kw)  # type: ignore[arg-type]


def raw_lines(text: str) -> Iterator[tuple[int, str, str]]:
    """Yield ``(start, body, eol)``; joining ``body + eol`` reproduces ``text`` exactly."""
    pos = 0
    for m in _EOL.finditer(text):
        yield pos, text[pos : m.start()], m.group()
        pos = m.end()
    if pos < len(text):
        yield pos, text[pos:], ""


def split_lines(text: str) -> Iterator[Line]:
    stack: list[tuple[int, str]] = []
    ros_path = ""
    for number, (start, body, eol) in enumerate(raw_lines(text), 1):
        stripped = body.strip()
        if body.startswith("/") and _ROS_PATH.match(body):
            ros_path = stripped.lower()
        elif (pm := _ROS_PROMPT.match(body)) is not None and (pm["cmd"] or pm["path"]):
            ros_path = (pm["cmd"] or pm["path"]).strip().lower()
        if stripped:
            expanded = body.expandtabs(8)
            indent = len(expanded) - len(expanded.lstrip())
            while stack and stack[-1][0] >= indent:
                stack.pop()
            ctx = tuple(s for _, s in stack)
            stack.append((indent, stripped))
        else:
            ctx = tuple(s for _, s in stack)
        yield Line(number, start, body, eol, ctx, ros_path)


def apply_edits(text: str, edits: list[tuple[int, int, str]]) -> str:
    """Apply non-overlapping ``(start, end, replacement)`` edits."""
    if not edits:
        return text
    out: list[str] = []
    pos = 0
    for start, end, repl in sorted(edits):
        if start < pos:
            continue
        out.append(text[pos:start])
        out.append(repl)
        pos = end
    out.append(text[pos:])
    return "".join(out)
