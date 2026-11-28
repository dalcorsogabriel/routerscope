"""Parser for RouterOS ``print`` output in its three shapes: table, ``detail`` and ``terse``.

All shapes become :class:`Record` objects with the exact source line range, the flag letters,
a ``;;; comment`` and the fields as a ``dict`` (keys lower-case; ``.as`` style continuation keys
inherit the prefix of the previous key, so ``remote.address`` ``.as`` becomes ``remote.as``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_FLAGS_LINE = re.compile(r"^\s*Flags:\s*(.*)$")
_LEGEND = re.compile(r"(\w)\s*-\s*([^,;]+)")
_ROW_START = re.compile(r"^\s*(\d+)(?=\s|$)")
_KV = re.compile(r'([\w./-]+)=("(?:[^"\\]|\\.)*"|\S*)')
_TOKEN = re.compile(r"\S+")
_FLAG_LEAD = re.compile(r"(?:\s+[A-Z]{1,2}(?=\s|$))+")

DEFAULT_FLAGS = {
    "X": "disabled",
    "D": "dynamic",
    "R": "running",
    "E": "established",
    "I": "invalid",
    "S": "slave",
    "L": "local",
}


@dataclass
class Record:
    """One printed row."""

    start: int  # 1-based, includes a preceding ``;;;`` comment line
    end: int
    flags: str = ""
    comment: str | None = None
    fields: dict[str, str] = field(default_factory=dict)


@dataclass
class Printed:
    records: list[Record]
    legend: dict[str, str]

    def has(self, record: Record, meaning: str) -> bool:
        """True if one of the record's flag letters means ``meaning`` (e.g. ``disabled``)."""
        legend = self.legend or DEFAULT_FLAGS
        return any(
            meaning in legend.get(ch, DEFAULT_FLAGS.get(ch, "")).lower() for ch in record.flags
        )


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return re.sub(r"\\(.)", r"\1", value[1:-1])
    return value


def _fields(text: str, fields: dict[str, str], prefix: list[str]) -> None:
    """Add every ``key=value`` of ``text``; ``prefix`` carries the dotted-prefix between calls."""
    for m in _KV.finditer(text):
        key = m[1].lower()
        if key.startswith(".") and prefix[0]:
            key = prefix[0] + key
        elif "." in key:
            prefix[0] = key.split(".", 1)[0]
        else:
            prefix[0] = ""
        fields[key] = _unquote(m[2])


def _legend(lines: list[str]) -> dict[str, str]:
    for line in lines:
        if m := _FLAGS_LINE.match(line):
            return {k: v.strip().lower() for k, v in _LEGEND.findall(m[1])}
    return {}


def parse_print(lines: list[str]) -> Printed | None:
    """Parse ``print`` output; ``None`` if it is neither a table nor key=value rows."""
    legend = _legend(lines)
    header = next((i for i, line in enumerate(lines) if re.match(r"^\s*#(\s|$)", line)), None)
    if header is not None:
        return Printed(_table(lines, header), legend)
    body = [i for i, line in enumerate(lines) if _ROW_START.match(line) and "=" in line]
    comment_rows = [i for i, line in enumerate(lines) if _ROW_START.match(line) and ";;;" in line]
    if body or comment_rows:
        return Printed(_kv_rows(lines), legend)
    return None


def _table(lines: list[str], header: int) -> list[Record]:
    cols = [(m.start(), m.group().lower()) for m in _TOKEN.finditer(lines[header])][1:]
    names: list[str] = []
    last_prefix = ""
    for _, name in cols:
        if name.startswith(".") and last_prefix:
            name = last_prefix + name
        elif "." in name:
            last_prefix = name.split(".", 1)[0]
        else:
            last_prefix = ""
        names.append(name)
    starts = [s for s, _ in cols]
    records: list[Record] = []
    pending: tuple[int, str] | None = None
    for i in range(header + 1, len(lines)):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith(";;;"):
            pending = (i + 1, stripped[3:].strip())
            continue
        if not _ROW_START.match(line) or not starts:
            continue
        rec = Record(
            start=pending[0] if pending else i + 1,
            end=i + 1,
            comment=pending[1] if pending else None,
        )
        pending = None
        cells: dict[int, list[str]] = {}
        for tm in list(_TOKEN.finditer(line))[1:]:
            if tm.start() < starts[0]:
                rec.flags += tm.group()
                continue
            mid = (tm.start() + tm.end()) / 2
            col = max((k for k, s in enumerate(starts) if s <= mid), default=0)
            cells.setdefault(col, []).append(tm.group())
        for col, words in cells.items():
            rec.fields[names[col]] = " ".join(words)
        records.append(rec)
    return records


def _kv_rows(lines: list[str]) -> list[Record]:
    records: list[Record] = []
    current: Record | None = None
    prefix = [""]
    for i, line in enumerate(lines):
        if _FLAGS_LINE.match(line) or line.lstrip().startswith("Columns:"):
            current = None
            continue
        m = _ROW_START.match(line)
        if m:
            current = Record(start=i + 1, end=i + 1)
            records.append(current)
            prefix[0] = ""
            rest = line[m.end() :]
            lead = _FLAG_LEAD.match(rest)
            if lead:
                current.flags = "".join(lead.group().split())
                rest = rest[lead.end() :]
            _consume(current, rest, prefix)
        elif current is not None and line.strip():
            current.end = i + 1
            _consume(current, line, prefix)
    return records


def _consume(record: Record, text: str, prefix: list[str]) -> None:
    if ";;;" in text:
        before, _, comment = text.partition(";;;")
        record.comment = comment.strip() or None
        text = before
    _fields(text, record.fields, prefix)


_COLON = re.compile(r"^\s*([A-Za-z][\w .-]*?)\s*:\s*(.*?)\s*$")


def parse_colon_lines(lines: list[str]) -> dict[str, tuple[int, str]]:
    """``key: value`` blocks (``/system resource print``): key -> (1-based line, value)."""
    out: dict[str, tuple[int, str]] = {}
    for i, line in enumerate(lines):
        if m := _COLON.match(line):
            out.setdefault(m[1].lower(), (i + 1, m[2]))
    return out
