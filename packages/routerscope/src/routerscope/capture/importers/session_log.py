"""Terminal-log importer: SecureCRT, PuTTY, MobaXterm, ``script`` and plain exports.

One log file yields one ``session`` item (the whole normalized log) plus one
``command_output`` item per command found in it (:func:`netprompt.segment`). Commands whose
output is empty (``ip route ...`` in config mode, a bare Enter) are not emitted; they remain in
the session item.

Formats (``Source.importer`` carries the id):

* ``securecrt``: lines prefixed ``[2026-01-05 10:22:01] `` (custom log timestamp format).
* ``iso``: lines prefixed ``2026-01-05T10:22:01.123Z `` (any ISO 8601 stamp with ``T``).
* ``mobaxterm``: lines prefixed ``[10:22:01] `` (time only; the date comes from the header
  or the file's modification time).
* ``putty``: ``=~=~=~= PuTTY log 2026.01.05 10:22:01 =~=~=~=`` header, no line stamps.
* ``script``: util-linux ``Script started on 2026-01-05 10:22:01+00:00 [...]`` header.
* ``plain``: no timestamps. Plain exports of Windows Terminal, Tabby, iTerm, Termius,
  MobaXterm or SecureCRT (ANSI is stripped).

Detection looks at the first lines (header first, then the majority line prefix); force a
format with ``format=``. The aliases ``windows_terminal``, ``tabby``, ``iterm`` and ``termius``
mean ``plain``. Forcing a format whose prefix is absent from the file is harmless.

``captured_at`` of a command, first match wins:

1. the timestamp on the command's prompt line, or on the closest timestamped line above it;
2. the header timestamp (PuTTY, ``script``);
3. the file modification time (pasted text: the given or current time).

Time-only stamps (MobaXterm) take their date from the header, else from the modification
time, and move to the next day when the clock wraps past midnight. Stamps without a zone are
read in ``tz`` (default: the machine's local timezone), so datetimes are never naive. The
session item's ``captured_at`` follows the same order using the first stamp of the log.

The session item's content is the normalized log (ANSI, backspaces and pagination removed)
**without** the line timestamps and without header/footer lines (PuTTY header, ``Script
started``/``done``).
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, tzinfo
from pathlib import Path

import netprompt

from routerscope.capture.importers._common import decode_bytes
from routerscope.capture.importers.base import ImportError_, ImportItem
from routerscope.model import Source

__all__ = [
    "FORMATS",
    "ParsedLog",
    "SessionLogImporter",
    "detect_format",
    "parse_session_log",
    "session_items",
]

FORMATS = ("securecrt", "iso", "mobaxterm", "putty", "script", "plain")
_ALIASES = {"windows_terminal": "plain", "tabby": "plain", "iterm": "plain", "termius": "plain"}

_BRACKET_DT = re.compile(r"^\[(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\] ?")
_BRACKET_T = re.compile(r"^\[(\d{2}:\d{2}:\d{2})\] ?")
_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) ")
_PREFIX: dict[str, re.Pattern[str] | None] = {
    "securecrt": _BRACKET_DT,
    "iso": _ISO,
    "mobaxterm": _BRACKET_T,
    "putty": None,
    "script": None,
    "plain": None,
}
_PUTTY_HEADER = re.compile(
    r"^=~(?:=~)*=* PuTTY log (\d{4})\.(\d{2})\.(\d{2}) (\d{2}:\d{2}:\d{2}) =~"
)
_SCRIPT_LINE = re.compile(r"^Script (?:started|done)\b")
_SCRIPT_TIME = re.compile(
    r"^Script started on (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(Z|[+-]\d{2}:?\d{2})?"
)
_DETECT_LINES = 30


@dataclass(frozen=True, slots=True)
class ParsedLog:
    """A terminal log split into segments, with times resolved."""

    format: str
    content: str
    """Normalized log without line timestamps and header/footer lines."""
    segments: list[netprompt.Segment]
    started_at: datetime
    command_times: list[datetime]
    """``captured_at`` of each entry of ``segments`` (same order)."""


def _localize(value: datetime, tz: tzinfo | None) -> datetime:
    if value.tzinfo is not None and value.utcoffset() is not None:
        return value
    return value.astimezone() if tz is None else value.replace(tzinfo=tz)


def _parse_stamp(text: str, tz: tzinfo | None) -> datetime | None:
    try:
        value = datetime.fromisoformat(text.replace(",", ".").replace(" ", "T"))
    except ValueError:
        return None
    return _localize(value, tz)


def detect_format(text: str) -> str:
    """Guess the log format from the first lines (see the module docstring)."""
    head = [ln.rstrip("\r") for ln in text.split("\n", 400)[:400] if ln.strip()][:_DETECT_LINES]
    if not head:
        return "plain"
    if _PUTTY_HEADER.match(head[0]):
        return "putty"
    if _SCRIPT_LINE.match(head[0]):
        return "script"
    for fmt in ("securecrt", "iso", "mobaxterm"):
        pattern = _PREFIX[fmt]
        assert pattern is not None
        hits = sum(1 for ln in head if pattern.match(ln))
        if hits and hits * 2 >= len(head):
            return fmt
    return "plain"


def _resolve_format(fmt: str | None) -> str | None:
    if fmt is None:
        return None
    fmt = _ALIASES.get(fmt, fmt)
    if fmt not in FORMATS:
        raise ValueError(f"unknown log format {fmt!r}; expected one of {', '.join(FORMATS)}")
    return fmt


def _header_time(line: str, fmt: str, tz: tzinfo | None) -> tuple[bool, datetime | None]:
    """``(is_header_line, time)`` for PuTTY/script header and footer lines."""
    if fmt == "putty":
        match = _PUTTY_HEADER.match(line)
        if match:
            y, m, d, hms = match.groups()
            return True, _parse_stamp(f"{y}-{m}-{d}T{hms}", tz)
    elif fmt == "script" and _SCRIPT_LINE.match(line):
        match = _SCRIPT_TIME.match(line)
        if match:
            day, hms, zone = match.groups()
            return True, _parse_stamp(f"{day}T{hms}{zone or ''}", tz)
        return True, None
    return False, None


def _strip_lines(
    text: str, fmt: str, tz: tzinfo | None, fallback: datetime
) -> tuple[list[str], list[datetime | None], datetime | None]:
    """Remove header lines and timestamp prefixes; return lines, forward-filled stamps, header."""
    prefix = _PREFIX[fmt]
    header: datetime | None = None
    lines: list[str] = []
    stamps: list[datetime | None] = []
    day_offset = 0
    previous: datetime | None = None
    for line in text.split("\n"):
        is_header, when = _header_time(line.rstrip("\r"), fmt, tz)
        if is_header:
            header = header or when
            continue
        stamp: datetime | None = None
        match = prefix.match(line) if prefix is not None else None
        if match:
            line = line[match.end() :]
            if fmt == "mobaxterm":
                base = header or fallback
                clock = datetime.strptime(match.group(1), "%H:%M:%S").time()
                stamp = datetime.combine(
                    base.date() + timedelta(days=day_offset), clock, tzinfo=base.tzinfo
                )
                if previous is not None and stamp < previous:
                    day_offset += 1
                    stamp += timedelta(days=1)
                previous = stamp
            else:
                stamp = _parse_stamp(match.group(1), tz)
        lines.append(line)
        stamps.append(stamp)
    filled: list[datetime | None] = []
    current: datetime | None = None
    for stamp in stamps:
        current = stamp or current
        filled.append(current)
    return lines, filled, header


def _align(
    lines: list[str], stamps: list[datetime | None], norm_lines: list[str]
) -> list[datetime | None]:
    """Stamps of the lines that survive ``normalize`` (it drops pagination-only lines)."""
    if len(norm_lines) == len(lines):
        return stamps
    kept: list[datetime | None] = []
    index = 0
    for line, stamp in zip(lines, stamps, strict=True):
        blank_next = index < len(norm_lines) and norm_lines[index] == ""
        if netprompt.normalize(line) == "" and line.strip() and not blank_next:
            continue
        kept.append(stamp)
        index += 1
    return kept


def parse_session_log(
    text: str,
    *,
    fallback: datetime,
    fmt: str | None = None,
    tz: tzinfo | None = None,
) -> ParsedLog:
    """Parse ``text``; ``fallback`` is the last-resort time (file mtime, paste time)."""
    chosen = _resolve_format(fmt) or detect_format(text)
    fallback = _localize(fallback, tz)
    lines, stamps, header = _strip_lines(text, chosen, tz, fallback)
    content = netprompt.normalize("\n".join(lines))
    stamps = _align(lines, stamps, content.split("\n"))
    segments = netprompt.segment(content)
    default = header or fallback
    first = next((s for s in stamps if s is not None), None)
    times = [stamps[min(seg.line - 1, len(stamps) - 1)] or default for seg in segments]
    return ParsedLog(chosen, content, segments, first or default, times)


def session_items(parsed: ParsedLog, source: Source) -> Iterator[ImportItem]:
    """The ``session`` item followed by one ``command_output`` item per command with output."""
    devices = Counter(seg.device for seg in parsed.segments if seg.device)
    vendors = Counter(seg.prompt.vendor for seg in parsed.segments if seg.prompt.vendor)
    yield ImportItem(
        content=parsed.content,
        kind="session",
        captured_at=parsed.started_at,
        source=source,
        hostname=devices.most_common(1)[0][0] if devices else None,
        vendor=vendors.most_common(1)[0][0] if vendors else None,
    )
    for seg, when in zip(parsed.segments, parsed.command_times, strict=True):
        command = seg.command.strip()
        if not command or not seg.output.strip():
            continue
        yield ImportItem(
            content=seg.output,
            kind="command_output",
            captured_at=when,
            source=source,
            hostname=seg.device,
            vendor=seg.prompt.vendor,
            command=command,
        )


def read_log_file(path: Path, tz: tzinfo | None) -> tuple[str, datetime]:
    """Read and decode a file; return the text and its modification time (aware)."""
    try:
        data = path.read_bytes()
        mtime = path.stat().st_mtime
    except OSError as exc:
        raise ImportError_(f"cannot read {path}: {exc.strerror or exc}") from exc
    text = decode_bytes(data)
    if not text.strip():
        raise ImportError_(f"{path} is empty")
    when = datetime.fromtimestamp(mtime, tz) if tz else datetime.fromtimestamp(mtime).astimezone()
    return text, when


class SessionLogImporter:
    """Import one terminal log file (see the module docstring for formats and timestamps)."""

    name = "session_log"

    def __init__(
        self, path: str | Path, *, format: str | None = None, tz: tzinfo | None = None
    ) -> None:
        self.path = Path(path)
        self.format = _resolve_format(format)
        self.tz = tz

    def items(self) -> Iterator[ImportItem]:
        text, mtime = read_log_file(self.path, self.tz)
        parsed = parse_session_log(text, fmt=self.format, tz=self.tz, fallback=mtime)
        source = Source(kind="session_log", uri=str(self.path), importer=parsed.format)
        yield from session_items(parsed, source)
