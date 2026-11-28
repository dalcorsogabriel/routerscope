"""State-command parsers for Juniper Junos."""

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

_PEER_HEADER = re.compile(r"^\s*Peer\s+AS\s+InPkt\s+OutPkt", re.IGNORECASE)
_TABLE_LINE = re.compile(r"^\s*(?:(\S+)\.)?inet6?\.0:\s")
_PEER_COLUMNS = 8  # peer as inpkt outpkt outq flaps last-up/down state (at least)


def _starts_with_ip(line: str) -> bool:
    tok = line.split()
    return bool(tok) and not line[:1].isspace() and first_ip(tok[0]) is not None


def bgp_summary(ctx: Ctx) -> Objects | None:
    """``show bgp summary``: one row per peer, optional indented per-table lines below it."""
    lines = ctx.lines
    if looks_like_error(lines):
        return None
    h = find_line(lines, _PEER_HEADER)
    if h is None:
        return None
    out: Objects = []
    for row in collect_rows(
        lines,
        h + 1,
        is_start=_starts_with_ip,
        need_tokens=_PEER_COLUMNS,
        is_continuation=lambda s: s[:1].isspace() and bool(re.match(r"^\s*\S+:\s", s)),
    ):
        first = row.lines[0].split()
        peer = first_ip(first[0])
        head = " ".join(row.lines[:1] if len(first) >= _PEER_COLUMNS else row.lines[:2]).split()
        asn = to_asn(head[1]) if len(head) >= _PEER_COLUMNS else None
        if peer is None or asn is None:
            continue
        vrf = ctx.vrf
        for extra in row.lines[1:]:
            if m := _TABLE_LINE.match(extra):
                vrf = vrf or m[1]
                break
        state = head[-1]
        out.append(
            ctx.make(
                BGPPeer,
                row.start,
                row.end,
                peer=peer,
                remote_as=asn,
                vrf=vrf,
                state="Established" if state.lower() == "establ" else norm_bgp_state(state),
            )
        )
    return out


_PROTOS = frozenset(
    {"inet", "inet6", "iso", "mpls", "eth-switch", "multiservice", "ccc", "tnp", "vpls"}
)


def interfaces_terse(ctx: Ctx) -> Objects | None:
    """``show interfaces terse``: interfaces plus the inet/inet6 addresses under them."""
    lines = ctx.lines
    h = find_line(lines, re.compile(r"^\s*Interface\s+Admin\s+Link", re.IGNORECASE))
    if h is None:
        return None
    out: Objects = []
    for row in collect_rows(
        lines,
        h + 1,
        is_start=lambda s: not s[:1].isspace() and len(s.split()) >= 3,
        is_continuation=lambda s: s[:1].isspace(),
    ):
        first = row.lines[0].split()
        name = first[0]
        out.append(
            ctx.make(Interface, row.start, row.end, name=name, enabled=first[1].lower() == "up")
        )
        proto: str | None = None
        for k, line in enumerate(row.lines):
            tok = first[3:] if k == 0 else line.split()
            if tok and tok[0] in _PROTOS:
                proto = tok[0]
                tok = tok[1:]
            if proto in ("inet", "inet6") and tok:
                addr = parse_iface_addr(tok[0])
                if addr is not None and not addr.is_link_local:
                    out.append(
                        ctx.make(
                            IPAddress, row.start + k, row.start + k, interface=name, address=addr
                        )
                    )
    return out


def arp(ctx: Ctx) -> Objects | None:
    """``show arp`` / ``show arp no-resolve``."""
    lines = ctx.lines
    h = find_line(lines, re.compile(r"^\s*MAC Address\s+Address\s", re.IGNORECASE))
    if h is None:
        return None
    has_name = " name " in f" {lines[h].lower()} "
    out: Objects = []
    for row in collect_rows(
        lines, h + 1, is_start=lambda s: len(s.split()) >= 3 and mac_of(s.split()[0]) is not None
    ):
        tok = row.tokens
        mac, ip = mac_of(tok[0]), first_ip(tok[1])
        idx = 3 if has_name else 2
        if mac is None or ip is None or len(tok) <= idx:
            continue
        out.append(
            ctx.make(ARPEntry, row.start, row.end, ip=ip, mac=mac, interface=tok[idx], vrf=ctx.vrf)
        )
    return out


_BRIDGE_DOMAIN = re.compile(r"^\s*Bridging domain\s*:\s*(\S+?),\s*VLAN\s*:\s*(\S+)", re.IGNORECASE)
_MAC_HEADER = re.compile(r"^\s*(vlan|mac)\s+mac\b", re.IGNORECASE)
_MAC_MARKER = re.compile(r"ethernet.switching table|bridging domain|MAC flags", re.IGNORECASE)


def _flag_type(flag: str) -> str | None:
    low = flag.lower()
    if low in ("static", "persistent") or (len(flag) <= 3 and flag[:1] == "S" and flag.isupper()):
        return "static"
    if low in ("learn", "dynamic") or (len(flag) <= 3 and flag[:1] == "D" and flag.isupper()):
        return "dynamic"
    return None


def mac_table(ctx: Ctx) -> Objects | None:
    """``show ethernet-switching table`` and ``show bridge mac-table`` (all layouts)."""
    lines = ctx.lines
    if looks_like_error(lines) or find_line(lines, _MAC_MARKER) is None:
        return None
    out: Objects = []
    domain: str | None = None
    vlan: int | None = None
    for i, line in enumerate(lines):
        if m := _BRIDGE_DOMAIN.match(line):
            domain, vlan = m[1], to_int(m[2])
            continue
        tok = line.split()
        if not tok or _MAC_HEADER.match(line):
            continue
        j = 0 if mac_of(tok[0]) else 1
        if len(tok) <= j + 1 or mac_of(tok[j]) is None:
            continue
        rest = [t for t in tok[j + 2 :] if not (t.isdigit() or t == "-")]
        entry_vlan, entry_domain = vlan, domain
        if j == 1:
            entry_vlan = to_int(tok[0])
            entry_domain = None if entry_vlan is not None else tok[0]
        out.append(
            ctx.make(
                MACEntry,
                i + 1,
                i + 1,
                mac=mac_of(tok[j]),
                vlan=entry_vlan,
                interface=rest[0] if rest else None,
                entry_type=_flag_type(tok[j + 1]),
                domain=entry_domain,
            )
        )
    return out


_VERSION = re.compile(
    r"^\s*(?:Junos:\s*(\S+)|JUNOS Software Release\s*\[([^\]]+)\])", re.IGNORECASE
)


def show_version(ctx: Ctx) -> Objects | None:
    """``show version``: ``Hostname:``, ``Model:`` and ``Junos:`` lines."""
    lines = ctx.lines
    v = find_line(lines, _VERSION)
    m = _VERSION.match(lines[v]) if v is not None else None
    if v is None or m is None:
        return None
    hostname = model = None
    used: list[int] = []
    for k, line in enumerate(lines):
        if hostname is None and (h := re.match(r"^\s*Hostname:\s*(\S+)", line)):
            hostname = h[1]
            used.append(k)
        elif model is None and (md := re.match(r"^\s*Model:\s*(\S+)", line)):
            model = md[1]
            used.append(k)
    out: Objects = [
        ctx.make(Version, v + 1, software="Junos", version=m[1] or m[2], platform=model)
    ]
    if used:
        out.append(ctx.make(Device, min(used) + 1, max(used) + 1, hostname=hostname, model=model))
    return out


SPECS: tuple[Spec, ...] = (
    spec(
        "show bgp summary",
        bgp_summary,
        "show:2 bgp:2 summary:3",
        "show:2 bgp:2 summary:3 instance:2 <vrf>",
    ),
    spec("show interfaces terse", interfaces_terse, "show:2 interfaces:3 terse:1"),
    spec(
        ("show arp no-resolve", "show arp"),
        arp,
        "show:2 arp:2 [no-resolve:2] [vpn:3 <vrf>] [no-resolve:2]",
    ),
    spec("show ethernet-switching table", mac_table, "show:2 ethernet-switching:2 table:2"),
    spec("show bridge mac-table", mac_table, "show:2 bridge:2 mac-table:2"),
    spec("show version", show_version, "show:2 version:3"),
)
