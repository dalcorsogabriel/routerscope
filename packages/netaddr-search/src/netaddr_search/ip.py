"""IP address and prefix parsing, containment relations, SQL helpers and text extraction.

Different IP versions are always :attr:`Relation.DISJOINT` and the ``SQL_*`` fragments filter on
``version``: IPv4-mapped IPv6 (``::ffff:192.0.2.1``) never matches IPv4 rows. The SQL fragments
assume columns named ``version``, ``start`` and ``end``; use :func:`sql_fragments` for
prefixed column names.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)

type Network = IPv4Network | IPv6Network
type Address = IPv4Address | IPv6Address

__all__ = [
    "SQL_COVERING",
    "SQL_INSIDE",
    "SQL_OVERLAPS",
    "Address",
    "IPMatch",
    "MatchKind",
    "Network",
    "Relation",
    "bounds",
    "bounds_int",
    "find_ips",
    "parse_network",
    "query_params",
    "relation",
    "sql_fragments",
]


def _contiguous_mask(value: int) -> bool:
    """True when ``value`` is a 32-bit netmask (ones followed by zeros)."""
    inv = value ^ 0xFFFFFFFF
    return (inv & (inv + 1)) == 0


def _v4(text: str) -> IPv4Address | None:
    try:
        return IPv4Address(text)
    except ValueError:
        return None


def _pair_network(addr: IPv4Address, second: IPv4Address) -> tuple[IPv4Network, str] | None:
    """Combine ``addr`` with a netmask or a wildcard; returns (network, kind) or None.

    A contiguous netmask wins, except that ``0.0.0.0`` after a non-zero address is read as
    the wildcard of a single host (``192.0.2.1 0.0.0.0`` -> /32). ``0.0.0.0 0.0.0.0`` is the
    default route (mask, /0) and ``0.0.0.0 255.255.255.255`` is the ACL "any" (wildcard, /0).
    """
    value = int(second)
    if value == 0:
        if int(addr) == 0:
            return IPv4Network("0.0.0.0/0"), "mask"
        return IPv4Network(addr), "wildcard"
    if value == 0xFFFFFFFF and int(addr) == 0:
        return IPv4Network("0.0.0.0/0"), "wildcard"
    if _contiguous_mask(value):
        prefix = bin(value).count("1")
        return IPv4Network((addr, prefix), strict=False), "mask"
    if _contiguous_mask(value ^ 0xFFFFFFFF):
        prefix = 32 - bin(value).count("1")
        return IPv4Network((addr, prefix), strict=False), "wildcard"
    return None


def parse_network(text: str) -> Network | None:
    """Parse a host, CIDR prefix, ``ip mask`` or ``ip wildcard`` into a network.

    Host addresses become /32 or /128. CIDR is non-strict (``192.0.2.5/24`` becomes
    ``192.0.2.0/24``). Wildcards must be contiguous. Returns ``None`` for invalid input and
    raises ``TypeError`` if ``text`` is not a ``str``.

    Ambiguity of ``a b``: ``255.255.255.255`` is both the /32 mask and the all-ones wildcard.
    When ``a`` is ``0.0.0.0`` it is read as the wildcard "any" (``0.0.0.0/0``); after a
    non-zero address it is a /32 mask. Likewise ``0.0.0.0`` after a non-zero address is the
    wildcard of a single host (/32) and ``0.0.0.0 0.0.0.0`` is the mask form of /0.
    """
    if not isinstance(text, str):
        raise TypeError(f"expected str, not {type(text).__name__}")
    if "%" in text:
        return None
    parts = text.split()
    try:
        if len(parts) == 1:
            token = parts[0]
            if "/" in token:
                return ip_network(token, strict=False)
            return ip_network(ip_address(token))
        if len(parts) == 2:
            a, b = _v4(parts[0]), _v4(parts[1])
            if a is None or b is None:
                return None
            pair = _pair_network(a, b)
            return pair[0] if pair else None
    except ValueError:
        return None
    return None


class Relation(StrEnum):
    """How network ``a`` relates to network ``b``."""

    EQUAL = "equal"
    INSIDE = "inside"  # a is inside b
    CONTAINS = "contains"  # a contains b
    DISJOINT = "disjoint"


def relation(a: Network, b: Network) -> Relation:
    """Return how ``a`` relates to ``b``. Different IP versions are always DISJOINT."""
    if a.version != b.version:
        return Relation.DISJOINT
    if a == b:
        return Relation.EQUAL
    # Same-version networks are either nested or disjoint.
    if a.subnet_of(b):  # type: ignore[arg-type]
        return Relation.INSIDE
    if b.subnet_of(a):  # type: ignore[arg-type]
        return Relation.CONTAINS
    return Relation.DISJOINT


def bounds_int(net: Network) -> tuple[int, int, int]:
    """Return ``(version, first, last)`` with addresses as integers."""
    return net.version, int(net.network_address), int(net.broadcast_address)


def bounds(net: Network) -> tuple[int, bytes, bytes]:
    """Return ``(version, first, last)`` as fixed-width big-endian bytes (4 or 16).

    Fixed width makes SQLite BLOB comparison (memcmp) agree with numeric ordering.
    """
    return net.version, net.network_address.packed, net.broadcast_address.packed


SQL_INSIDE = '"version" = :version AND "start" >= :start AND "end" <= :end'
"""Rows whose range lies inside the query network (equal rows included)."""

SQL_COVERING = '"version" = :version AND "start" <= :start AND "end" >= :end'
"""Rows whose range covers the query network (equal rows included)."""

SQL_OVERLAPS = '"version" = :version AND "start" <= :end AND "end" >= :start'
"""Rows sharing at least one address with the query network."""


def sql_fragments(prefix: str = "") -> dict[str, str]:
    """Return the ``inside``, ``covering`` and ``overlaps`` fragments for prefixed columns.

    Columns are named ``{prefix}version``, ``{prefix}start`` and ``{prefix}end``; bind with
    :func:`query_params`. ``sql_fragments()`` equals the unprefixed ``SQL_INSIDE``,
    ``SQL_COVERING`` and ``SQL_OVERLAPS``. ``prefix`` must consist of word characters only.
    """
    if not re.fullmatch(r"\w*", prefix):
        raise ValueError(f"invalid column prefix: {prefix!r}")
    v, s, e = (f'"{prefix}{c}"' for c in ("version", "start", "end"))
    return {
        "inside": f"{v} = :version AND {s} >= :start AND {e} <= :end",
        "covering": f"{v} = :version AND {s} <= :start AND {e} >= :end",
        "overlaps": f"{v} = :version AND {s} <= :end AND {e} >= :start",
    }


def query_params(net: Network) -> dict[str, object]:
    """Named parameters ``:version``, ``:start``, ``:end`` for the ``SQL_*`` fragments."""
    version, start, end = bounds(net)
    return {"version": version, "start": start, "end": end}


class MatchKind(StrEnum):
    """What form an :class:`IPMatch` was written in."""

    ADDRESS = "address"
    PREFIX = "prefix"  # addr/len
    MASK = "mask"  # addr netmask
    WILDCARD = "wildcard"  # addr wildcard


@dataclass(frozen=True, slots=True)
class IPMatch:
    """An address or prefix found in free text.

    ``address`` is the address as written (``192.0.2.5`` in ``192.0.2.5/24``) and ``network``
    the enclosing network (/32 or /128 for bare hosts).
    """

    start: int
    end: int
    text: str
    address: Address
    network: Network
    kind: MatchKind


_V4 = r"(?:\d{1,3}\.){3}\d{1,3}"
_V4_RE = re.compile(rf"(?<![\w.])({_V4})(?![\w]|\.\d)(?:/(\d{{1,2}})(?!\d))?")
_PAIR_RE = re.compile(rf"[ \t]+({_V4})(?![\w]|\.\d)")
_V6_RE = re.compile(r"(?<![\w:.])[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*")
_V6_PREFIX_RE = re.compile(r"/(\d{1,3})(?!\d)")


def _find_v4(text: str) -> Iterator[IPMatch]:
    pos = 0
    while m := _V4_RE.search(text, pos):
        addr = _v4(m.group(1))
        if addr is None:
            pos = m.start() + 1
            continue
        start, end = m.start(), m.end()
        if m.group(2) is not None:
            plen = int(m.group(2))
            if plen <= 32:
                yield IPMatch(
                    start,
                    end,
                    m.group(0),
                    addr,
                    IPv4Network((addr, plen), strict=False),
                    MatchKind.PREFIX,
                )
                pos = end
                continue
            end = m.end(1)
        pair = _PAIR_RE.match(text, end)
        if pair is not None:
            second = _v4(pair.group(1))
            combined = _pair_network(addr, second) if second is not None else None
            if combined is not None and second is not None:
                net, kind = combined
                yield IPMatch(
                    start,
                    pair.end(),
                    text[start : pair.end()],
                    addr,
                    net,
                    MatchKind(kind),
                )
                pos = pair.end()
                continue
        yield IPMatch(start, end, text[start:end], addr, IPv4Network(addr), MatchKind.ADDRESS)
        pos = end


def _find_v6(text: str) -> Iterator[IPMatch]:
    for m in _V6_RE.finditer(text):
        cand = m.group(0)
        start = m.start()
        addr: IPv6Address | None = None
        while cand:
            if cand.count(":") >= 2:
                try:
                    addr = IPv6Address(cand)
                    break
                except ValueError:
                    pass
            if cand[-1] in ".:":
                cand = cand[:-1]
            else:
                break
        if addr is None:
            continue
        end = start + len(cand)
        # Reject if directly followed by more address-like characters.
        if end < len(text) and (text[end].isalnum() or text[end] == "_"):
            continue
        pm = _V6_PREFIX_RE.match(text, end)
        if pm is not None and int(pm.group(1)) <= 128:
            plen = int(pm.group(1))
            yield IPMatch(
                start,
                pm.end(),
                text[start : pm.end()],
                addr,
                IPv6Network((addr, plen), strict=False),
                MatchKind.PREFIX,
            )
        elif cand != "::":  # a standalone "::" is too common in prose; "::/0" matches above
            yield IPMatch(start, end, cand, addr, IPv6Network(addr), MatchKind.ADDRESS)


def _skipped(text: str, start: int, words: tuple[str, ...]) -> bool:
    """True when the same-line text before ``start`` ends with one of ``words``."""
    line_start = text.rfind("\n", 0, start) + 1
    before = text[line_start:start].rstrip(" \t:=").lower()
    for w in words:
        w = w.lower()
        if before.endswith(w) and (len(before) == len(w) or not before[-len(w) - 1].isalnum()):
            return True
    return False


def find_ips(text: str, *, skip_after: tuple[str, ...] = ()) -> Iterator[IPMatch]:
    """Yield IPv4/IPv6 addresses and prefixes found in free text, in order of position.

    Recognized: bare addresses, ``addr/len``, ``addr netmask`` and ``addr wildcard`` pairs
    (IPv4), compressed IPv6 and IPv4-mapped IPv6. ``0.0.0.0 0.0.0.0`` yields one ``0.0.0.0/0``
    MASK match and ``0.0.0.0 255.255.255.255`` one ``0.0.0.0/0`` WILDCARD match; see
    :func:`parse_network` for the pairing rules. A standalone ``::`` is not matched (``::/0``
    and ``::1`` are). Not matched: three-part version strings (``7.16.1``), timestamps, MAC
    addresses, interface names (``1/1/1``).

    Caveat: a four-part version number (``7.16.1.0``) is indistinguishable from an IPv4 address
    and is returned. Pass ``skip_after=("version", "build", "release")`` to drop matches whose
    preceding same-line text (ignoring spaces, ``:`` and ``=``) ends with one of those words,
    compared case-insensitively.
    """
    found = [*_find_v4(text), *_find_v6(text)]
    found.sort(key=lambda x: x.start)
    last_end = -1
    for item in found:
        if item.start >= last_end:
            last_end = item.end
            if skip_after and _skipped(text, item.start, skip_after):
                continue
            yield item
