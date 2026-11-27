"""MAC address normalization, formatting and extraction."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum

__all__ = ["MacMatch", "MacStyle", "find_macs", "format_mac", "normalize_mac"]

_FULL = [
    re.compile(r"[0-9a-f]{2}(?P<s>[:-])(?:[0-9a-f]{2}(?P=s)){4}[0-9a-f]{2}"),
    re.compile(r"(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}"),
    re.compile(r"(?:[0-9a-f]{4}-){2}[0-9a-f]{4}"),
    re.compile(r"[0-9a-f]{12}"),
]


def normalize_mac(text: str) -> str | None:
    """Return the canonical lowercase ``aa:bb:cc:dd:ee:ff`` form, or ``None`` if invalid.

    Accepts colon, hyphen, Cisco dotted (``aabb.ccdd.eeff``), Huawei (``aabb-ccdd-eeff``)
    and bare (``aabbccddeeff``) notations.
    """
    s = text.strip().lower()
    if not any(p.fullmatch(s) for p in _FULL):
        return None
    d = re.sub(r"[:.-]", "", s)
    return ":".join(d[i : i + 2] for i in range(0, 12, 2))


class MacStyle(StrEnum):
    """Output notation for :func:`format_mac`."""

    COLON = "colon"  # aa:bb:cc:dd:ee:ff
    HYPHEN = "hyphen"  # aa-bb-cc-dd-ee-ff
    CISCO = "cisco"  # aabb.ccdd.eeff
    HUAWEI = "huawei"  # aabb-ccdd-eeff
    BARE = "bare"  # aabbccddeeff


def format_mac(mac: str, style: MacStyle = MacStyle.COLON, *, upper: bool = False) -> str:
    """Render ``mac`` (any accepted notation) in ``style``. Raises ``ValueError`` if invalid."""
    norm = normalize_mac(mac)
    if norm is None:
        raise ValueError(f"invalid MAC address: {mac!r}")
    d = norm.replace(":", "")
    match MacStyle(style):
        case MacStyle.COLON:
            out = norm
        case MacStyle.HYPHEN:
            out = norm.replace(":", "-")
        case MacStyle.CISCO:
            out = f"{d[0:4]}.{d[4:8]}.{d[8:12]}"
        case MacStyle.HUAWEI:
            out = f"{d[0:4]}-{d[4:8]}-{d[8:12]}"
        case MacStyle.BARE:
            out = d
    return out.upper() if upper else out


@dataclass(frozen=True, slots=True)
class MacMatch:
    """A MAC address found in free text; ``mac`` is the canonical form."""

    start: int
    end: int
    text: str
    mac: str


_H2 = "[0-9A-Fa-f]{2}"
_H4 = "[0-9A-Fa-f]{4}"
_MAC_RE = re.compile(
    r"(?<![\w:.-])(?:"
    rf"(?:{_H2}:){{5}}{_H2}"
    rf"|(?:{_H2}-){{5}}{_H2}"
    rf"|(?:{_H4}\.){{2}}{_H4}"
    rf"|(?:{_H4}-){{2}}{_H4}"
    r")(?![\w:-]|\.\w)"
)


def find_macs(text: str) -> Iterator[MacMatch]:
    """Yield MAC addresses found in free text (colon, hyphen, Cisco and Huawei notations).

    Bare 12-digit hex is not searched (too many false positives). IPv6 addresses are skipped.
    """
    for m in _MAC_RE.finditer(text):
        norm = normalize_mac(m.group(0))
        if norm is not None:
            yield MacMatch(m.start(), m.end(), m.group(0), norm)
