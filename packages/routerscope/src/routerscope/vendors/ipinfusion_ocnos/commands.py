"""State-command table for IP Infusion OcNOS (Cisco-like CLI)."""

from __future__ import annotations

import re

from routerscope.model import Device, Version
from routerscope.vendors import _cisco_like as c
from routerscope.vendors._cmd import Ctx, Spec, spec
from routerscope.vendors._tables import find_line

_VERSION = re.compile(r"OcNOS\s+version\s+(\S+)", re.IGNORECASE)
_HOSTNAME = re.compile(r"^\s*Hostname\s*:\s*(\S+)", re.IGNORECASE)
_UPTIME = re.compile(r"uptime is\s+(.+?)\s*$", re.IGNORECASE)


def show_version(ctx: Ctx) -> c.Objects | None:
    """OcNOS ``show version``: ``OcNOS version X`` plus optional hostname and uptime lines."""
    lines = ctx.lines
    v = find_line(lines, _VERSION)
    m = _VERSION.search(lines[v]) if v is not None else None
    if v is None or m is None:
        return None
    h = find_line(lines, _HOSTNAME)
    u = find_line(lines, _UPTIME)
    uptime = _UPTIME.search(lines[u]) if u is not None else None
    out: c.Objects = [
        ctx.make(
            Version, v + 1, software="OcNOS", version=m[1], uptime=uptime[1] if uptime else None
        )
    ]
    hostname = _HOSTNAME.match(lines[h]) if h is not None else None
    if h is not None and hostname is not None:
        out.append(ctx.make(Device, h + 1, hostname=hostname[1]))
    return out


SPECS: tuple[Spec, ...] = (
    spec(
        ("show ip bgp summary", "show bgp ipv6 summary"),
        c.bgp_summary,
        "show:2 ip:2 bgp:2 summary:3",
        "show:2 ip:2 bgp:2 vrf:2 <vrf> summary:3",
        "show:2 ip:2 bgp:2 vpnv4:3 summary:3",
        "show:2 ip:2 bgp:2 vpnv4:3 vrf:2 <vrf> summary:3",
        "show:2 bgp:2 ipv6:3 summary:3",
        "show:2 bgp:2 ipv6:3 vrf:2 <vrf> summary:3",
    ),
    spec(
        "show ip interface brief",
        c.interface_brief,
        "show:2 ip:2 interface:3 brief:1",
        "show:2 ip:2 interface:3 brief:1 vrf:2 <vrf>",
    ),
    spec(
        "show arp",
        c.arp_table,
        "show:2 arp:2",
        "show:2 ip:2 arp:2",
        "show:2 arp:2 vrf:2 <vrf>",
        "show:2 ip:2 arp:2 vrf:2 <vrf>",
    ),
    spec(
        "show mac address-table",
        c.mac_table,
        "show:2 mac:3 address-table:3",
    ),
    spec("show version", show_version, "show:2 version:3"),
)
