"""State-command parsers for Nokia SR OS (classic and MD-CLI ``show`` commands).

The ``show`` output is the same in both CLI flavours; they differ only in how names are typed
(MD-CLI quotes them: ``show router "VPRN1" bgp summary``), which the matcher accepts.
"""

from __future__ import annotations

import re

from routerscope.model import (
    ARPEntry,
    BGPPeer,
    Device,
    Interface,
    IPAddress,
    MACEntry,
    ParsedObjectUnion,
    Version,
)
from routerscope.vendors._cmd import Ctx, Spec, spec
from routerscope.vendors._extract import parse_iface_addr, to_asn, to_int
from routerscope.vendors._tables import (
    collect_rows,
    find_line,
    first_ip,
    looks_like_error,
    mac_of,
    norm_bgp_state,
)

Objects = list[ParsedObjectUnion | None]

_DASHES = re.compile(r"^\s*-{10,}\s*$")
_END = re.compile(r"^\s*={10,}\s*$")
_ROUTER = re.compile(r"\(Router:\s*(.+?)\)")
_LOCAL_AS = re.compile(r"Local AS:\s*(\S+)")


def _vrf(ctx: Ctx, text: str | None = None) -> str | None:
    """VRF name from the command capture or the table title; ``Base`` is the global table."""
    name = ctx.vrf or text
    return None if name is None or name.lower() == "base" else name


def _rows_start(lines: list[str], header: int) -> int:
    """Index of the first line after the dashed line that follows ``header``."""
    dash = find_line(lines, _DASHES, header + 1)
    return (dash + 1) if dash is not None else header + 1


def bgp_summary(ctx: Ctx) -> Objects | None:
    """``show router [vrf] bgp summary``: peer on one line, AS/state on the next."""
    lines = ctx.lines
    if looks_like_error(lines):
        return None
    h = find_line(lines, re.compile(r"State\|Rcv/Act/Sent"))
    if h is None:
        return None
    local_as = None
    for line in lines[:h]:
        if m := _LOCAL_AS.search(line):
            local_as = to_asn(m[1])
    out: Objects = []
    for row in collect_rows(
        lines,
        _rows_start(lines, h),
        is_start=lambda s: (
            not s[:1].isspace() and len(s.split()) == 1 and first_ip(s.split()[0]) is not None
        ),
        is_continuation=lambda s: not _DASHES.match(s) and not _END.match(s),
        stop=lambda s: bool(_DASHES.match(s) or _END.match(s)),
    ):
        peer = first_ip(row.lines[0].split()[0])
        asn = state = None
        description: list[str] = []
        for line in row.lines[1:]:
            tok = line.split()
            if asn is None and line[:1].isspace() and len(tok) >= 5 and tok[0].isdigit():
                asn = to_asn(tok[0])
                state = norm_bgp_state(
                    " ".join(tok[4:]) if not re.match(r"\d+/\d+/\d+", tok[4]) else tok[4]
                )
            elif asn is None and not line[:1].isspace():
                description.append(line.strip())
        if peer is None or asn is None:
            continue
        out.append(
            ctx.make(
                BGPPeer,
                row.start,
                row.end,
                peer=peer,
                remote_as=asn,
                local_as=local_as,
                vrf=_vrf(ctx),
                state=state,
                description=" ".join(description) or None,
            )
        )
    return out


def router_interface(ctx: Ctx) -> Objects | None:
    """``show router [vrf] interface``: interface rows with their indented address lines."""
    lines = ctx.lines
    h = find_line(lines, re.compile(r"^\s*Interface-Name\s+Adm", re.IGNORECASE))
    if h is None:
        return None
    title = next((m[1] for line in lines[:h] if (m := _ROUTER.search(line))), None)
    vrf = _vrf(ctx, title)
    out: Objects = []
    for row in collect_rows(
        lines,
        _rows_start(lines, h),
        is_start=lambda s: (
            not s[:1].isspace() and not _END.match(s) and not s.startswith("Interfaces")
        ),
        is_continuation=lambda s: s[:1].isspace(),
        stop=lambda s: bool(_DASHES.match(s) or _END.match(s)),
    ):
        tok = row.tokens
        if len(tok) < 2 or tok[1].lower() not in ("up", "down"):
            continue
        name = tok[0]
        out.append(
            ctx.make(
                Interface, row.start, row.end, name=name, enabled=tok[1].lower() == "up", vrf=vrf
            )
        )
        for k, line in enumerate(row.lines):
            for word in line.split():
                addr = parse_iface_addr(word) if "/" in word else None
                if addr is not None and not addr.is_link_local:
                    out.append(
                        ctx.make(
                            IPAddress,
                            row.start + k,
                            row.start + k,
                            interface=name,
                            address=addr,
                            vrf=vrf,
                        )
                    )
    return out


def port_table(ctx: Ctx) -> Objects | None:
    """``show port``: admin state, MTU and LAG membership per port."""
    lines = ctx.lines
    headers = [
        i for i, line in enumerate(lines) if re.match(r"^\s*Port\s+Admin\s+Link\s+Port", line)
    ]
    if not headers:
        return None
    out: Objects = []
    for h in headers:
        for row in collect_rows(
            lines,
            _rows_start(lines, h + 1),
            is_start=lambda s: len(s.split()) >= 7 and s.split()[1].lower() in ("up", "down"),
            stop=lambda s: bool(_END.match(s)),
        ):
            tok = row.tokens
            lag = f"lag-{tok[6]}" if tok[6].isdigit() else None
            out.append(
                ctx.make(
                    Interface,
                    row.start,
                    row.end,
                    name=tok[0],
                    enabled=tok[1].lower() == "up",
                    mtu=to_int(tok[4]) or None,
                    lag=lag,
                )
            )
    return out


def arp(ctx: Ctx) -> Objects | None:
    """``show router [vrf] arp``."""
    lines = ctx.lines
    h = find_line(lines, re.compile(r"^\s*IP Address\s+MAC Address\s+Expiry", re.IGNORECASE))
    if h is None:
        return None
    title = next((m[1] for line in lines[:h] if (m := _ROUTER.search(line))), None)
    vrf = _vrf(ctx, title)
    out: Objects = []
    for row in collect_rows(
        lines,
        _rows_start(lines, h),
        is_start=lambda s: bool(s.split()) and first_ip(s.split()[0]) is not None,
        stop=lambda s: bool(_DASHES.match(s) or _END.match(s)),
    ):
        tok = row.tokens
        ip = first_ip(tok[0])
        mac = mac_of(tok[1]) if len(tok) > 1 else None
        if ip is None or mac is None:
            continue
        out.append(
            ctx.make(
                ARPEntry,
                row.start,
                row.end,
                ip=ip,
                mac=mac,
                interface=tok[4] if len(tok) > 4 else None,
                vrf=vrf,
            )
        )
    return out


def _fdb_type(kind: str) -> str | None:
    low = kind.lower()
    if low.startswith("l"):
        return "dynamic"
    if low.startswith(("static", "os", "cpm")):
        return "static"
    return None


def fdb_mac(ctx: Ctx) -> Objects | None:
    """``show service fdb-mac``: one row per MAC per service."""
    lines = ctx.lines
    h = find_line(lines, re.compile(r"^\s*ServId\s+MACAddress", re.IGNORECASE))
    if h is None:
        return None
    out: Objects = []
    for row in collect_rows(
        lines,
        _rows_start(lines, h),
        is_start=lambda s: len(s.split()) >= 3 and mac_of(s.split()[1]) is not None,
        stop=lambda s: bool(_DASHES.match(s) or _END.match(s)),
    ):
        tok = row.tokens
        out.append(
            ctx.make(
                MACEntry,
                row.start,
                row.end,
                mac=mac_of(tok[1]),
                interface=tok[2],
                entry_type=_fdb_type(tok[3]) if len(tok) > 3 else None,
                domain=tok[0],
            )
        )
    return out


_TIMOS = re.compile(r"TiMOS-(\S+)\s+\S+\s+(.+?)\s+Copyright")
_TIMOS_SHORT = re.compile(r"TiMOS-(\S+)")


def show_version(ctx: Ctx) -> Objects | None:
    """``show version``: the ``TiMOS-...`` banner line."""
    lines = ctx.lines
    v = find_line(lines, _TIMOS_SHORT)
    if v is None:
        return None
    full = _TIMOS.search(lines[v])
    short = _TIMOS_SHORT.search(lines[v])
    version = full[1] if full else short[1] if short else None
    return [
        ctx.make(
            Version, v + 1, software="SR OS", version=version, platform=full[2] if full else None
        )
    ]


def system_information(ctx: Ctx) -> Objects | None:
    """``show system information``: name, type, version and uptime."""
    lines = ctx.lines
    fields: dict[str, tuple[int, str]] = {}
    for i, line in enumerate(lines):
        m = re.match(r"^\s*(System (?:Name|Type|Version|Up Time))\s*:\s*(.*?)\s*$", line)
        if m and m[1] not in fields:
            fields[m[1]] = (i, m[2])
    if "System Version" not in fields or not fields["System Version"][1]:
        return None
    ver_line, version = fields["System Version"]
    platform = fields.get("System Type", (0, ""))[1] or None
    uptime = fields.get("System Up Time", (0, ""))[1] or None
    out: Objects = [
        ctx.make(
            Version,
            ver_line + 1,
            software="SR OS",
            version=version,
            platform=platform,
            uptime=uptime,
        )
    ]
    name = fields.get("System Name")
    if name and name[1]:
        out.append(ctx.make(Device, name[0] + 1, hostname=name[1], model=platform))
    return out


SPECS: tuple[Spec, ...] = (
    spec(
        "show router bgp summary",
        bgp_summary,
        "show:2 router:3 bgp:2 summary:3",
        "show:2 router:3 <vrf> bgp:2 summary:3",
    ),
    spec(
        "show router interface",
        router_interface,
        "show:2 router:3 interface:3",
        "show:2 router:3 <vrf> interface:3",
    ),
    spec("show port", port_table, "show:2 port:2"),
    spec(
        "show router arp",
        arp,
        "show:2 router:3 arp:2",
        "show:2 router:3 <vrf> arp:2",
    ),
    spec("show service fdb-mac", fdb_mac, "show:2 service:3 fdb-mac:3"),
    spec("show version", show_version, "show:2 version:3"),
    spec("show system information", system_information, "show:2 system:3 information:3"),
)
