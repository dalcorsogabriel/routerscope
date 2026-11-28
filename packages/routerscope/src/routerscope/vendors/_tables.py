"""Helpers for parsing the text tables of ``show`` commands.

Most outputs are whitespace separated, some are fixed width with empty cells (found through the
header), and some wrap one logical row over several lines. These helpers keep each vendor
parser short and always report the exact line range a row came from.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

from netaddr_search import normalize_mac

from routerscope.vendors._extract import parse_ip

IPAddr = IPv4Address | IPv6Address

_ERROR_LINE = re.compile(
    r"^\s*(%|error\b|syntax error|unknown command|invalid (input|command)|bad command"
    r"|unrecognized|incorrect command|ambiguous command|\^|invalid)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Row:
    """A logical row: its source lines (1-based ``start``) and their whitespace tokens."""

    start: int
    lines: tuple[str, ...]

    @property
    def end(self) -> int:
        return self.start + len(self.lines) - 1

    @property
    def tokens(self) -> list[str]:
        return " ".join(self.lines).split()


def looks_like_error(lines: Sequence[str]) -> bool:
    """True if the first non-blank line is a CLI error message (``% Invalid input``...)."""
    for line in lines:
        if line.strip():
            return bool(_ERROR_LINE.match(line))
    return True


def find_line(lines: Sequence[str], pattern: re.Pattern[str], start: int = 0) -> int | None:
    """Index of the first line at or after ``start`` that ``pattern`` matches (``search``)."""
    for i in range(start, len(lines)):
        if pattern.search(lines[i]):
            return i
    return None


def column_starts(header: str, names: Sequence[str]) -> list[int] | None:
    """Start offsets of ``names`` in ``header``, found left to right (case-insensitive)."""
    low = header.lower()
    out: list[int] = []
    pos = 0
    for name in names:
        i = low.find(name.lower(), pos)
        if i < 0:
            return None
        out.append(i)
        pos = i + len(name)
    return out


def slice_columns(line: str, starts: Sequence[int]) -> list[str]:
    """Cut a fixed-width ``line`` at the column ``starts`` and strip every cell."""
    cells = []
    for k, begin in enumerate(starts):
        end = starts[k + 1] if k + 1 < len(starts) else len(line)
        cells.append(line[begin:end].strip())
    return cells


def collect_rows(
    lines: Sequence[str],
    start: int,
    *,
    is_start: Callable[[str], bool],
    need_tokens: int = 0,
    is_continuation: Callable[[str], bool] | None = None,
    stop: Callable[[str], bool] | None = None,
) -> Iterator[Row]:
    """Group ``lines[start:]`` into logical rows.

    A row begins at a line where ``is_start`` is true. It is extended with following lines
    while it has fewer than ``need_tokens`` whitespace tokens (the wrapped-row case) or while
    ``is_continuation`` accepts the next line. Blank lines end a row; a line matching ``stop``
    ends the whole scan.
    """
    i = start
    n = len(lines)
    while i < n:
        line = lines[i]
        if stop is not None and stop(line):
            return
        if not line.strip() or not is_start(line):
            i += 1
            continue
        block = [line]
        j = i + 1
        while j < n and lines[j].strip() and not (stop is not None and stop(lines[j])):
            nxt = lines[j]
            if is_start(nxt):
                break
            wants = len(" ".join(block).split()) < need_tokens and not is_start(nxt)
            if not (wants or (is_continuation is not None and is_continuation(nxt))):
                break
            block.append(nxt)
            j += 1
        yield Row(i + 1, tuple(block))
        i = j


def first_ip(token: str) -> IPAddr | None:
    """Parse ``token`` as an address after removing ``*``, ``%scope`` and ``+port`` decoration."""
    text = token.lstrip("*")
    for sep in ("%", "+"):
        text = text.partition(sep)[0]
    return parse_ip(text)


def mac_of(token: str) -> str | None:
    """Canonical MAC for ``token`` or ``None`` (also for the all-zero placeholder)."""
    mac = normalize_mac(token)
    return None if mac is None or mac == "00:00:00:00:00:00" else mac


_STATES = {
    "established": "Established",
    "idle": "Idle",
    "active": "Active",
    "connect": "Connect",
    "opensent": "OpenSent",
    "openconfirm": "OpenConfirm",
    "idle (admin)": "Idle (Admin)",
    "idle(admin)": "Idle (Admin)",
    "idle (pfxct)": "Idle (PfxCt)",
    "idle(pfxct)": "Idle (PfxCt)",
    "idle (ovflw)": "Idle (Overflow)",
    "idle (overflow)": "Idle (Overflow)",
    "clearing": "Clearing",
}


def norm_bgp_state(text: str) -> str | None:
    """Normalize a BGP state column.

    A prefix count (``5`` or ``1/2/3/0``) means the session is established. Known state names
    get their canonical spelling; anything else is returned as printed, ``None`` if empty.
    """
    value = " ".join(text.split())
    if not value:
        return None
    if re.fullmatch(r"\d+(/\d+)*", value):
        return "Established"
    return _STATES.get(value.lower(), value)
