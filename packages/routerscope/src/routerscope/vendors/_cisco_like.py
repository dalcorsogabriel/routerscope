"""State-command handlers for the Cisco-style CLIs (IOS / IOS-XE, IOS-XR, OcNOS).

The three vendors print very similar tables, so the handlers are shared and tolerant: they
locate the table by its header, read rows by whitespace tokens (robust against misaligned
columns) and rebuild rows that the device wrapped over two lines.
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
from routerscope.vendors._cmd import Ctx
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

_BGP_HEADER = re.compile(r"^\s*Neighbor\s+(V|Spk)\s+AS\b", re.IGNORECASE)
_BGP_VRF = re.compile(r"^\s*BGP VRF\s+(\S+?),", re.IGNORECASE)
_BGP_AFI = re.compile(r"^\s*(?:For address family|Address Family)\s*:\s*(.+?)\s*$", re.IGNORECASE)
_LOCAL_AS = re.compile(r"local AS number\s+(\S+?)[,\s]*$", re.IGNORECASE)
_BGP_COLUMNS = 10  # neighbor V/Spk AS rcvd sent tblver inq outq up/down state


def _starts_with_ip(line: str) -> bool:
    tok = line.split()
    return bool(tok) and first_ip(tok[0]) is not None


def bgp_summary(ctx: Ctx) -> Objects | None:
    """``show ip bgp summary`` and relatives (IOS, XR, OcNOS: one neighbor table per section)."""
    lines = ctx.lines
    if looks_like_error(lines):
        return None
    vrf = ctx.vrf
    families: tuple[str, ...] = ()
    local_as: int | None = None
    found_header = False
    out: Objects = []
    for i, line in enumerate(lines):
        if m := _BGP_VRF.match(line):
            vrf = None if m[1].lower() == "default" else m[1]
        elif m := _BGP_AFI.match(line):
            families = (m[1].lower(),)
        elif m := _LOCAL_AS.search(line):
            local_as = to_asn(m[1].rstrip(","))
        elif _BGP_HEADER.match(line):
            found_header = True
            for row in collect_rows(
                lines,
                i + 1,
                is_start=_starts_with_ip,
                need_tokens=_BGP_COLUMNS,
                stop=lambda s: bool(_BGP_HEADER.match(s) or _BGP_AFI.match(s) or _BGP_VRF.match(s)),
            ):
                tok = row.tokens
                peer = first_ip(tok[0])
                asn = to_asn(tok[2]) if len(tok) >= _BGP_COLUMNS else None
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
                        address_families=families,
                        state=norm_bgp_state(" ".join(tok[9:])),
                    )
                )
    return out if found_header else None


def _admin_down(status: str) -> bool:
    return status.lower().startswith(("admin", "shutdown", "shut"))


def interface_brief(ctx: Ctx) -> Objects | None:
    """``show ip interface brief`` (IOS/OcNOS) and ``show ipv4 interface brief`` (XR)."""
    lines = ctx.lines
    h = find_line(lines, re.compile(r"^\s*Interface\s+IP-Address\b", re.IGNORECASE))
    if h is None or "status" not in lines[h].lower().split():
        return None
    words = lines[h].lower().split()
    skip = words.index("status") - 2  # the OK? and Method columns of IOS
    has_vrf = words[-1] == "vrf-name"
    has_proto = "protocol" in words
    out: Objects = []
    for row in collect_rows(lines, h + 1, is_start=lambda s: len(s.split()) >= 3):
        tok = row.tokens
        vrf = ctx.vrf
        if has_vrf and len(tok) > 3 + skip:
            tail = tok.pop()
            vrf = None if tail.lower() == "default" else tail
        if has_proto and len(tok) > 3 + skip:
            tok.pop()
        status = " ".join(tok[2 + skip :])
        if not status:
            continue
        name = tok[0]
        out.append(
            ctx.make(
                Interface, row.start, row.end, name=name, enabled=not _admin_down(status), vrf=vrf
            )
        )
        addr = parse_iface_addr(tok[1]) if "/" in tok[1] else None  # no mask shown: no address
        if addr is not None:
            out.append(
                ctx.make(IPAddress, row.start, row.end, interface=name, address=addr, vrf=vrf)
            )
    return out


def interface_description(ctx: Ctx) -> Objects | None:
    """``show interfaces description`` (IOS, XR)."""
    lines = ctx.lines
    h = find_line(lines, re.compile(r"^\s*Interface\s+Status\s+Protocol", re.IGNORECASE))
    if h is None:
        return None
    starts = column_starts(lines[h], ["Interface", "Status", "Protocol", "Description"])
    out: Objects = []
    for row in collect_rows(lines, h + 1, is_start=lambda s: len(s.split()) >= 2):
        tok = row.tokens
        first = row.lines[0]
        if starts is not None and len(first) > starts[1]:
            name, status, _, desc = slice_columns(first, starts)
        else:
            name, status, desc = tok[0], tok[1], ""
        if not name or " " in name:
            name, status, desc = tok[0], tok[1], ""
        out.append(
            ctx.make(
                Interface,
                row.start,
                row.end,
                name=name,
                enabled=not _admin_down(status),
                description=desc or None,
                vrf=ctx.vrf,
            )
        )
    return out


def xr_interfaces_brief(ctx: Ctx) -> Objects | None:
    """IOS-XR ``show interfaces brief`` (name, state, line protocol, encapsulation, MTU, BW)."""
    lines = ctx.lines
    h = find_line(lines, re.compile(r"^\s*Intf\s+Intf\s+LineP", re.IGNORECASE))
    if h is None:
        return None
    out: Objects = []
    for row in collect_rows(lines, h + 1, is_start=lambda s: len(s.split()) >= 3 and s[:1] == " "):
        tok = row.tokens
        if tok[0].startswith("-") or not tok[1].lower().startswith(("up", "down", "admin")):
            continue
        mtu = to_int(tok[-2]) if len(tok) >= 5 else None
        out.append(
            ctx.make(
                Interface,
                row.start,
                row.end,
                name=tok[0],
                enabled=not _admin_down(tok[1]),
                mtu=mtu or None,
                vrf=ctx.vrf,
            )
        )
    return out


_TYPE_WORDS = frozenset(
    {"arpa", "snap", "sap", "dynamic", "static", "interface", "alias", "evpn", "probe", "dhcp"}
)


def _arp_start(line: str) -> bool:
    tok = line.split()
    return bool(tok) and (
        first_ip(tok[0]) is not None or (len(tok) > 1 and first_ip(tok[1]) is not None)
    )


def arp_table(ctx: Ctx) -> Objects | None:
    """``show ip arp`` / ``show arp`` (IOS, XR, OcNOS)."""
    lines = ctx.lines
    header = re.compile(
        r"^\s*(Protocol\s+)?(Address|IP Address)\s+.*(Hardware|MAC)\s", re.IGNORECASE
    )
    h = find_line(lines, header)
    if h is None:
        return None
    out: Objects = []
    for row in collect_rows(lines, h + 1, is_start=_arp_start):
        tok = row.tokens
        k = 0 if first_ip(tok[0]) is not None else 1
        ip = first_ip(tok[k])
        j = next((x for x in range(k + 1, len(tok)) if mac_of(tok[x]) is not None), None)
        if ip is None or j is None:
            continue
        rest = [t for t in tok[j + 1 :] if t.lower() not in _TYPE_WORDS]
        out.append(
            ctx.make(
                ARPEntry,
                row.start,
                row.end,
                ip=ip,
                mac=mac_of(tok[j]),
                interface=rest[-1] if rest else None,
                vrf=ctx.vrf,
            )
        )
    return out


def _mac_start(line: str) -> bool:
    tok = line.split()
    return bool(tok) and (
        mac_of(tok[0]) is not None or (len(tok) > 1 and mac_of(tok[1]) is not None)
    )


def mac_type(kind: str) -> str | None:
    """Map a vendor's MAC entry type word to ``static`` / ``dynamic`` / ``None``."""
    kind = kind.lower()
    if kind in ("static", "self", "permanent", "secure", "sticky"):
        return "static"
    if kind in ("dynamic", "learned", "learn"):
        return "dynamic"
    return None


def mac_table(ctx: Ctx) -> Objects | None:
    """``show mac address-table`` (IOS, OcNOS) and the XR L2VPN forwarding table."""
    lines = ctx.lines
    h = find_line(lines, re.compile(r"^\s*(Vlan\s+)?Mac Address\b", re.IGNORECASE))
    if h is None:
        return None
    out: Objects = []
    for row in collect_rows(lines, h + 1, is_start=_mac_start):
        tok = row.tokens
        j = 0 if mac_of(tok[0]) else 1
        mac = mac_of(tok[j])
        if mac is None:
            continue
        out.append(
            ctx.make(
                MACEntry,
                row.start,
                row.end,
                mac=mac,
                vlan=to_int(tok[0]) if j == 1 else None,
                interface=tok[j + 2] if len(tok) > j + 2 else None,
                entry_type=mac_type(tok[j + 1]) if len(tok) > j + 1 else None,
            )
        )
    return out


_VERSION_LINE = re.compile(r"Cisco IOS.*?Software.*?\bVersion\s+([^\s,\[]+)", re.IGNORECASE)
_UPTIME = re.compile(r"^\s*(\S+)\s+uptime is\s+(.+?)\s*$")
_PLATFORM = re.compile(r"^\s*cisco\s+(.+?)\s+\(.*\bwith\s+\d", re.IGNORECASE)
_SERIAL = re.compile(r"Processor board ID\s+(\S+)", re.IGNORECASE)


def show_version(ctx: Ctx) -> Objects | None:
    """``show version`` for IOS, IOS-XE and IOS-XR."""
    lines = ctx.lines
    v = find_line(lines, _VERSION_LINE)
    if v is None:
        return None
    m = _VERSION_LINE.search(lines[v])
    if m is None:  # pragma: no cover - find_line just matched
        return None
    head = lines[v].lower()
    software = "IOS-XR" if "ios xr" in head else "IOS-XE" if "ios xe" in head else "IOS"
    hostname = uptime = platform = serial = None
    used: list[int] = []
    for k, line in enumerate(lines):
        if hostname is None and (u := _UPTIME.match(line)):
            hostname, uptime = u[1], u[2]
            used.append(k)
        elif platform is None and (p := _PLATFORM.match(line)):
            platform = p[1]
            used.append(k)
        elif serial is None and (s := _SERIAL.search(line)):
            serial = s[1]
            used.append(k)
    out: Objects = [
        ctx.make(Version, v + 1, software=software, version=m[1], platform=platform, uptime=uptime)
    ]
    if used:
        out.append(
            ctx.make(
                Device,
                min(used) + 1,
                max(used) + 1,
                hostname=hostname,
                model=platform,
                serial=serial,
            )
        )
    return out
