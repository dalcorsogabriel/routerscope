"""State-command parsers for Huawei VRP (``display ...``)."""

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
    column_starts,
    find_line,
    first_ip,
    looks_like_error,
    mac_of,
    norm_bgp_state,
    slice_columns,
)

Objects = list[ParsedObjectUnion | None]

_PEER_HEADER = re.compile(r"^\s*Peer\s+V\s+AS\s+MsgRcvd", re.IGNORECASE)
_VPN_INSTANCE = re.compile(r"VPN-Instance\s+([^\s,]+)\s*,", re.IGNORECASE)
_LOCAL_AS = re.compile(r"Local AS number\s*:\s*(\S+)", re.IGNORECASE)
_PEER_COLUMNS = 9  # peer V AS rcvd sent outq up/down state prefrcv


def _starts_with_ip(line: str) -> bool:
    tok = line.split()
    return bool(tok) and first_ip(tok[0]) is not None


def bgp_peer(ctx: Ctx) -> Objects | None:
    """``display bgp peer`` and the ipv6 / vpnv4 / vpnv6 variants."""
    lines = ctx.lines
    if looks_like_error(lines):
        return None
    vrf = ctx.vrf
    local_as: int | None = None
    found = False
    out: Objects = []
    for i, line in enumerate(lines):
        if m := _VPN_INSTANCE.search(line):
            vrf = None if m[1] == "_public_" else m[1]
        elif m := _LOCAL_AS.search(line):
            local_as = to_asn(m[1])
        elif _PEER_HEADER.match(line):
            found = True
            for row in collect_rows(
                lines,
                i + 1,
                is_start=_starts_with_ip,
                need_tokens=_PEER_COLUMNS,
                stop=lambda s: bool(_PEER_HEADER.match(s) or _VPN_INSTANCE.search(s)),
            ):
                tok = row.tokens
                peer = first_ip(tok[0])
                asn = to_asn(tok[2]) if len(tok) >= _PEER_COLUMNS - 1 else None
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
                        vrf=vrf,
                        state=norm_bgp_state(tok[7]),
                    )
                )
    return out if found else None


_SPEED = re.compile(r"\(\d+[GMK]\)$")


def _clean_name(name: str) -> str:
    return _SPEED.sub("", name)


def interface_brief(ctx: Ctx) -> Objects | None:
    """``display interface brief``: name, physical state (``*down`` = shut down), protocol."""
    lines = ctx.lines
    h = find_line(lines, re.compile(r"^\s*Interface\s+PHY\s+Protocol", re.IGNORECASE))
    if h is None:
        return None
    out: Objects = []
    for row in collect_rows(lines, h + 1, is_start=lambda s: len(s.split()) >= 3):
        tok = row.tokens
        out.append(
            ctx.make(
                Interface,
                row.start,
                row.end,
                name=_clean_name(tok[0]),
                enabled=not tok[1].startswith("*"),
                vrf=ctx.vrf,
            )
        )
    return out


def ip_interface_brief(ctx: Ctx) -> Objects | None:
    """``display ip interface brief``: adds the address with its prefix length."""
    lines = ctx.lines
    h = find_line(lines, re.compile(r"^\s*Interface\s+IP Address/Mask\s+Physical", re.IGNORECASE))
    if h is None:
        return None
    has_vpn = "vpn" in lines[h].lower()
    out: Objects = []
    for row in collect_rows(lines, h + 1, is_start=lambda s: len(s.split()) >= 4):
        tok = row.tokens
        vrf = ctx.vrf
        if has_vpn and len(tok) >= 5 and tok[4] != "--":
            vrf = tok[4]
        name = _clean_name(tok[0])
        out.append(
            ctx.make(
                Interface,
                row.start,
                row.end,
                name=name,
                enabled=not tok[2].startswith("*"),
                vrf=vrf,
            )
        )
        addr = parse_iface_addr(tok[1]) if "/" in tok[1] else None
        if addr is not None:
            out.append(
                ctx.make(IPAddress, row.start, row.end, interface=name, address=addr, vrf=vrf)
            )
    return out


def interface_description(ctx: Ctx) -> Objects | None:
    """``display interface description``."""
    lines = ctx.lines
    h = find_line(lines, re.compile(r"^\s*Interface\s+PHY\s+Protocol\s+Description", re.IGNORECASE))
    if h is None:
        return None
    starts = column_starts(lines[h], ["Interface", "PHY", "Protocol", "Description"])
    out: Objects = []
    for row in collect_rows(lines, h + 1, is_start=lambda s: len(s.split()) >= 3):
        tok = row.tokens
        desc = ""
        if starts is not None and len(row.lines[0]) > starts[3]:
            desc = slice_columns(row.lines[0], starts)[3]
        elif len(tok) > 3:
            desc = " ".join(tok[3:])
        out.append(
            ctx.make(
                Interface,
                row.start,
                row.end,
                name=_clean_name(tok[0]),
                enabled=not tok[1].startswith("*"),
                description=desc or None,
                vrf=ctx.vrf,
            )
        )
    return out


_ARP_TYPE = re.compile(r"^[A-Z]{1,3}(-\d+(/\d+)?)?$")
_VLAN_COL = re.compile(r"^\d+/[-\d]+$")


def arp(ctx: Ctx) -> Objects | None:
    """``display arp`` (optionally for one VPN instance)."""
    lines = ctx.lines
    h = find_line(lines, re.compile(r"^\s*IP ADDRESS\s+MAC ADDRESS", re.IGNORECASE))
    if h is None:
        return None
    dash = find_line(lines, re.compile(r"^\s*-{5,}"), h + 1)
    start = dash + 1 if dash is not None else h + 1
    out: Objects = []
    for row in collect_rows(
        lines,
        start,
        is_start=_starts_with_ip,
        is_continuation=lambda s: s[:1].isspace() and not s.lstrip().startswith("-"),
        stop=lambda s: s.lstrip().startswith("-----") or s.startswith("Total"),
    ):
        tok = row.tokens
        ip = first_ip(tok[0])
        mac = mac_of(tok[1]) if len(tok) > 1 else None
        if ip is None or mac is None:
            continue
        rest = tok[2:]
        if rest and rest[0].isdigit():
            rest = rest[1:]  # expire time
        if rest and _ARP_TYPE.match(rest[0]):
            rest = rest[1:]
        while rest and rest[0] == "-":
            rest = rest[1:]
        iface = rest[0] if rest else None
        vrf = ctx.vrf
        if len(rest) > 1 and rest[1] != "-" and not _VLAN_COL.match(rest[1]):
            vrf = rest[1]
        out.append(ctx.make(ARPEntry, row.start, row.end, ip=ip, mac=mac, interface=iface, vrf=vrf))
    return out


def mac_address(ctx: Ctx) -> Objects | None:
    """``display mac-address`` (full table)."""
    lines = ctx.lines
    h = find_line(lines, re.compile(r"^\s*MAC Address\s+VLAN/VSI", re.IGNORECASE))
    if h is None:
        return None
    out: Objects = []
    for row in collect_rows(
        lines,
        h + 1,
        is_start=lambda s: bool(s.split()) and mac_of(s.split()[0]) is not None,
        stop=lambda s: s.startswith("Total"),
    ):
        tok = row.tokens
        mac = mac_of(tok[0])
        if mac is None or len(tok) < 4:
            continue
        parts = tok[1].split("/")
        vlan = to_int(parts[0])
        domain = next((p for p in parts[1:] if p not in ("", "-")), None)
        kind = tok[3].lower()
        out.append(
            ctx.make(
                MACEntry,
                row.start,
                row.end,
                mac=mac,
                vlan=vlan if vlan else None,
                interface=tok[2],
                entry_type="dynamic"
                if kind == "dynamic"
                else "static"
                if kind == "static"
                else None,
                domain=domain,
            )
        )
    return out


_VERSION = re.compile(r"VRP\s*\(R\)\s*software,\s*Version\s+(.+?)\s*$", re.IGNORECASE)
_UPTIME = re.compile(r"^\s*(?:HUAWEI\s+)?(\S+)\s+uptime is\s+(.+?)\s*$", re.IGNORECASE)


def version(ctx: Ctx) -> Objects | None:
    """``display version``."""
    lines = ctx.lines
    v = find_line(lines, _VERSION)
    m = _VERSION.search(lines[v]) if v is not None else None
    if v is None or m is None:
        return None
    u = find_line(lines, _UPTIME)
    up = _UPTIME.match(lines[u]) if u is not None else None
    platform = up[1] if up else None
    out: Objects = [
        ctx.make(
            Version,
            v + 1,
            software="VRP",
            version=m[1],
            platform=platform,
            uptime=up[2] if up else None,
        )
    ]
    if u is not None and platform:
        out.append(ctx.make(Device, u + 1, model=platform))
    return out


SPECS: tuple[Spec, ...] = (
    spec(
        ("display bgp peer", "display bgp ipv6 peer", "display bgp vpnv4 all peer"),
        bgp_peer,
        "display:3 bgp:2 peer:2",
        "display:3 bgp:2 ipv6:3 peer:2",
        "display:3 bgp:2 vpnv4:3/vpnv6:3 all:2 peer:2",
        "display:3 bgp:2 vpnv4:3/vpnv6:3 vpn-instance:2 <vrf> peer:2",
    ),
    spec("display interface brief", interface_brief, "display:3 interface:3 brief:1"),
    spec("display ip interface brief", ip_interface_brief, "display:3 ip:2 interface:3 brief:1"),
    spec(
        "display interface description",
        interface_description,
        "display:3 interface:3 description:1",
    ),
    spec(
        "display arp",
        arp,
        "display:3 arp:2",
        "display:3 arp:2 vpn-instance:2 <vrf>",
    ),
    spec("display mac-address", mac_address, "display:3 mac-address:3"),
    spec("display version", version, "display:3 version:3"),
)
