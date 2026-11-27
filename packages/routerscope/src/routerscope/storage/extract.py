"""Pure extraction of typed index rows (IPs, MACs, ASNs, communities, interfaces) from text.

Everything here is deliberately conservative: an ASN is only recognised after a BGP keyword,
a community only on lines that mention ``community``, and so on. Free-text search (FTS) covers
whatever these extractors miss. Input must already be redacted.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from netaddr_search import find_ips, find_macs, normalize_interface
from netaddr_search.ip import bounds

__all__ = [
    "IndexRows",
    "extract_asns",
    "extract_communities",
    "extract_interfaces",
    "extract_rows",
]

_I = re.IGNORECASE

# ---------------------------------------------------------------------------------------- ASNs

_AS = r"(\d{1,10}(?:\.\d{1,5})?)"
_END = r"(?![\w.:/-])"
_ASN_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Cisco/XR/OcNOS/Junos-like "router bgp N", "remote-as N", Huawei "as-number N", ...
    re.compile(rf"\b(?P<ctx>router\s+bgp)\s+{_AS}(?![\w.:/-])", _I),
    re.compile(rf"^\s*(?P<ctx>bgp)\s+{_AS}\s*$", _I),  # Huawei VRP, OcNOS
    re.compile(
        rf"(?<![\w.-])(?P<ctx>remote-as|peer-as|local-as|as-number|autonomous-system)\s+{_AS}{_END}",
        _I,
    ),
    # RouterOS: as=N, remote.as=N, local.as=N, remote-as=N
    re.compile(rf"(?<![\w.-])(?P<ctx>remote\.as|local\.as|remote-as|local-as|as)={_AS}{_END}", _I),
    # show output: "remote AS 64497", "local AS number 64496"
    re.compile(rf"(?<![\w-])(?P<ctx>(?:remote|local)\s+as(?:\s+number)?)\s+{_AS}{_END}", _I),
    # "AS64496" written as one token (case sensitive)
    re.compile(rf"(?<![\w-])(?P<ctx>AS){_AS}{_END}"),
)


def _asn_value(text: str) -> int | None:
    """Parse asplain or asdot (``65536.1``); None when out of the 1..4294967295 range."""
    if "." in text:
        high_s, low_s = text.split(".", 1)
        high, low = int(high_s), int(low_s)
        if high > 65535 or low > 65535:
            return None
        value = high * 65536 + low
    else:
        value = int(text)
    return value if 1 <= value <= 4294967295 else None


def extract_asns(line: str) -> list[tuple[int, str]]:
    """Return ``(asn, context)`` pairs found on one line, without duplicates."""
    found: list[tuple[int, str]] = []
    for pattern in _ASN_PATTERNS:
        for m in pattern.finditer(line):
            value = _asn_value(m[2])
            ctx = re.sub(r"\s+", " ", m["ctx"].lower())
            if value is not None and (value, ctx) not in found:
                found.append((value, ctx))
    return found


# -------------------------------------------------------------------------------- communities

_COMM_TOKEN = re.compile(r"(?<![\w:.\-/])(\d{1,10}):(\d{1,10})(?::(\d{1,10}))?(?![\w:.]|-\w)")
_WELL_KNOWN = re.compile(
    r"(?<![\w-])(no-export-subconfed|no-export|no-advertise|local-as|internet"
    r"|graceful-shutdown|blackhole|no-peer|accept-own)(?![\w-])",
    _I,
)


def extract_communities(line: str) -> list[tuple[str, str]]:
    """Return ``(community, kind)`` pairs; only lines mentioning ``communit*`` are considered.

    Kinds: ``standard`` (``N:M``, both 16-bit), ``large`` (``N:M:K``, 32-bit parts) and
    ``well_known`` (lowercase name such as ``no-export``).
    """
    if "communit" not in line.lower():
        return []
    found: list[tuple[str, str]] = []
    for m in _COMM_TOKEN.finditer(line):
        a, b, c = int(m[1]), int(m[2]), m[3]
        if c is None:
            item = (f"{a}:{b}", "standard") if a <= 65535 and b <= 65535 else None
        else:
            item = (f"{a}:{b}:{int(c)}", "large") if max(a, b, int(c)) <= 4294967295 else None
        if item is not None and item not in found:
            found.append(item)
    for m in _WELL_KNOWN.finditer(line):
        item = (m[1].lower(), "well_known")
        if item not in found:
            found.append(item)
    return found


# ------------------------------------------------------------------------------- interfaces

_CISCO_HUAWEI_TYPES = (
    "TwentyFiveGigE|TenGigabitEthernet|TenGigE|FortyGigabitEthernet|FortyGigE|HundredGigE"
    "|XGigabitEthernet|GigabitEthernet|FastEthernet|Bundle-Ether|Port-channel|Eth-Trunk"
    "|MgmtEth|LoopBack|Loopback|Vlanif|Ethernet|Serial|Tunnel|Vlan|MEth|Twe|Gi|Te|Fo|Hu|Fa|Eth"
    "|Po|BE|Lo|Vl|Tu|Mg|Se|BDI|XGE|GE|10GE|25GE|40GE|100GE"
)
_IFACE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(rf"(?<![\w/.:-])(?:{_CISCO_HUAWEI_TYPES})\d+(?:[/.:]\d+)*(?![\w-])", _I),
    # Junos
    re.compile(
        r"(?<![\w/.:-])(?:(?:ge|xe|et|fe|xle|so|em|fxp|vme|me)-\d+(?:/\d+)*(?::\d+)?(?:\.\d+)?"
        r"|(?:ae|reth|lo|irb)\d+(?:\.\d+)?)(?![\w-])",
        _I,
    ),
    # RouterOS
    re.compile(
        r"(?<![\w/.:-])(?:ether|sfp-sfpplus|sfpplus|sfp|qsfpplus|wlan|bonding|bridge|vrrp"
        r"|pppoe-out|lte)\d+(?:\.\d+)?(?![\w-])",
        _I,
    ),
    # Nokia SR OS: ports after "port", breakout ports (c<N>), lag-N
    re.compile(r"(?<![\w/.:-])port\s+(\d+/\d+/(?:c\d+/)?\d+)(?![\w/-])", _I),
    re.compile(r"(?<![\w/.:-])\d+/\d+/c\d+/\d+(?![\w/-])", _I),
    re.compile(r"(?<![\w/.:-])lag-\d+(?![\w-])", _I),
    # IP Infusion OcNOS
    re.compile(r"(?<![\w/.:-])(?:xe|ce)\d+(?:/\d+)*(?:\.\d+)?(?![\w-])", _I),
)
_INTERFACE_STMT = re.compile(r"^\s*interface\s+\"?([^\s\"]+)\"?", _I)


def extract_interfaces(line: str, vendor: str | None) -> list[tuple[str, str]]:
    """Return ``(raw, normalized)`` interface names on one line (deduplicated, case-insensitive)."""
    raws: list[str] = []
    stmt = _INTERFACE_STMT.match(line)
    if stmt:
        raws.append(stmt[1])
    for pattern in _IFACE_PATTERNS:
        for m in pattern.finditer(line):
            raws.append(m[1] if m.re.groups else m[0])
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw in raws:
        try:
            normalized = normalize_interface(raw, vendor)
        except ValueError:  # vendor id unknown to netaddr-search
            normalized = normalize_interface(raw)
        key = normalized.lower()
        if key not in seen:
            seen.add(key)
            out.append((raw, normalized))
    return out


# ------------------------------------------------------------------------------------ rows


@dataclass(slots=True)
class IndexRows:
    """Rows for the typed side tables, each tagged with its 1-based line number."""

    ips: list[tuple[int, int, bytes, bytes, str, str, str]] = field(default_factory=list)
    macs: list[tuple[int, str]] = field(default_factory=list)
    asns: list[tuple[int, int, str]] = field(default_factory=list)
    communities: list[tuple[int, str, str]] = field(default_factory=list)
    interfaces: list[tuple[int, str, str]] = field(default_factory=list)


def extract_rows(lines: Iterable[str], vendor: str | None) -> IndexRows:
    """Extract side-table rows from ``lines`` (line numbers start at 1)."""
    rows = IndexRows()
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        for ip in find_ips(line, skip_after=("version", "build", "release")):
            version, start, end = bounds(ip.network)
            rows.ips.append(
                (line_no, version, start, end, str(ip.address), str(ip.network), ip.kind.value)
            )
        rows.macs.extend((line_no, m.mac) for m in find_macs(line))
        rows.asns.extend((line_no, asn, ctx) for asn, ctx in extract_asns(line))
        rows.communities.extend((line_no, c, k) for c, k in extract_communities(line))
        rows.interfaces.extend(
            (line_no, raw, norm) for raw, norm in extract_interfaces(line, vendor)
        )
    return rows
