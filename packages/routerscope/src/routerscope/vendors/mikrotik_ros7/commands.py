"""State-command parsers for MikroTik RouterOS 7 (``print`` in table, detail and terse form)."""

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
from routerscope.vendors._routeros_print import Printed, parse_colon_lines, parse_print
from routerscope.vendors._tables import first_ip, looks_like_error, mac_of, norm_bgp_state

Objects = list[ParsedObjectUnion | None]


def normalize(command: str) -> list[str] | None:
    """Tokens of a RouterOS command with the menu path split into words.

    ``/ip/arp/print``, ``/ip arp print`` and ``ip arp pr`` give the same tokens. Anything with
    a pipe, a script expression or a ``where`` filter is left for the patterns to reject.
    """
    if "|" in command or "[" in command or command.lstrip().startswith(":"):
        return None
    return command.strip().lstrip("/").replace("/", " ").split()


def _printed(ctx: Ctx) -> Printed | None:
    if looks_like_error(ctx.lines):
        return None
    return parse_print(ctx.lines)


def _is_error(lines: list[str]) -> bool:
    return looks_like_error(lines) or any(
        re.match(
            r"^\s*(bad command name|syntax error|expected end of command|failure:)", line, re.I
        )
        for line in lines
    )


def bgp_session(ctx: Ctx) -> Objects | None:
    """``/routing bgp session print``: one record per session."""
    if _is_error(ctx.lines) or (printed := _printed(ctx)) is None:
        return None
    out: Objects = []
    for rec in printed.records:
        f = rec.fields
        peer = first_ip(f.get("remote.address") or f.get("remote-address") or "")
        remote_as = to_asn(f.get("remote.as") or f.get("remote-as"))
        if peer is None or remote_as is None:
            continue
        established = printed.has(rec, "established") or f.get("established") == "yes"
        state = "Established" if established else norm_bgp_state(f.get("state", ""))
        vrf = f.get("vrf")
        out.append(
            ctx.make(
                BGPPeer,
                rec.start,
                rec.end,
                peer=peer,
                remote_as=remote_as,
                local_as=to_asn(f.get("local.as") or f.get("local-as")),
                vrf=None if vrf in (None, "", "main") else vrf,
                state=state,
                description=rec.comment,
            )
        )
    return out


def interface_print(ctx: Ctx) -> Objects | None:
    """``/interface print``."""
    if _is_error(ctx.lines) or (printed := _printed(ctx)) is None:
        return None
    out: Objects = []
    for rec in printed.records:
        name = rec.fields.get("name")
        if not name:
            continue
        mtu = to_int(rec.fields.get("mtu") or rec.fields.get("actual-mtu"))
        out.append(
            ctx.make(
                Interface,
                rec.start,
                rec.end,
                name=name,
                enabled=not printed.has(rec, "disabled"),
                mtu=mtu or None,
                description=rec.comment or rec.fields.get("comment") or None,
            )
        )
    return out


def ip_address_print(ctx: Ctx) -> Objects | None:
    """``/ip address print`` (disabled and invalid entries are not assigned addresses)."""
    if _is_error(ctx.lines) or (printed := _printed(ctx)) is None:
        return None
    out: Objects = []
    for rec in printed.records:
        addr = parse_iface_addr(rec.fields.get("address", ""))
        iface = rec.fields.get("interface")
        if addr is None or not iface or printed.has(rec, "disabled") or printed.has(rec, "invalid"):
            continue
        out.append(ctx.make(IPAddress, rec.start, rec.end, interface=iface, address=addr))
    return out


def arp_print(ctx: Ctx) -> Objects | None:
    """``/ip arp print`` (incomplete entries, which have no MAC, are skipped)."""
    if _is_error(ctx.lines) or (printed := _printed(ctx)) is None:
        return None
    out: Objects = []
    for rec in printed.records:
        ip = first_ip(rec.fields.get("address", ""))
        mac = mac_of(rec.fields.get("mac-address", ""))
        if ip is None or mac is None or printed.has(rec, "disabled"):
            continue
        out.append(
            ctx.make(
                ARPEntry, rec.start, rec.end, ip=ip, mac=mac, interface=rec.fields.get("interface")
            )
        )
    return out


def bridge_host_print(ctx: Ctx) -> Objects | None:
    """``/interface bridge host print``: local and static entries count as static."""
    if _is_error(ctx.lines) or (printed := _printed(ctx)) is None:
        return None
    out: Objects = []
    for rec in printed.records:
        mac = mac_of(rec.fields.get("mac-address", ""))
        if mac is None:
            continue
        dynamic = printed.has(rec, "dynamic") and not printed.has(rec, "local")
        vid = to_int(rec.fields.get("vid"))
        out.append(
            ctx.make(
                MACEntry,
                rec.start,
                rec.end,
                mac=mac,
                vlan=vid or None,
                interface=rec.fields.get("on-interface"),
                entry_type="dynamic" if dynamic else "static",
                domain=rec.fields.get("bridge"),
            )
        )
    return out


def system_resource(ctx: Ctx) -> Objects | None:
    """``/system resource print``: ``version``, ``board-name`` and ``uptime``."""
    if _is_error(ctx.lines):
        return None
    f = parse_colon_lines(ctx.lines)
    if "version" not in f or not f["version"][1]:
        return None
    line, version = f["version"]
    platform = (f.get("board-name") or (0, ""))[1] or None
    uptime = (f.get("uptime") or (0, ""))[1] or None
    return [
        ctx.make(
            Version, line, software="RouterOS", version=version, platform=platform, uptime=uptime
        )
    ]


def system_routerboard(ctx: Ctx) -> Objects | None:
    """``/system routerboard print``: model and serial number of the board."""
    if _is_error(ctx.lines):
        return None
    f = parse_colon_lines(ctx.lines)
    model, serial = f.get("model"), f.get("serial-number")
    if model is None and serial is None:
        return None
    lines = [x[0] for x in (model, serial) if x]
    return [
        ctx.make(
            Device,
            min(lines),
            max(lines),
            model=(model or (0, ""))[1] or None,
            serial=(serial or (0, ""))[1] or None,
        )
    ]


def system_identity(ctx: Ctx) -> Objects | None:
    """``/system identity print``: the router name."""
    if _is_error(ctx.lines):
        return None
    f = parse_colon_lines(ctx.lines)
    if "name" not in f or not f["name"][1]:
        return None
    line, name = f["name"]
    return [ctx.make(Device, line, hostname=name)]


_PRINT = "print:1 [detail:1/terse:1/brief:2] [without-paging:3] [detail:1/terse:1]"

SPECS: tuple[Spec, ...] = (
    spec("/routing bgp session print", bgp_session, f"routing:2 bgp:2 session:2 {_PRINT}"),
    spec("/interface print", interface_print, f"interface:3 {_PRINT}"),
    spec("/ip address print", ip_address_print, f"ip:2 address:2 {_PRINT}"),
    spec("/ip arp print", arp_print, f"ip:2 arp:2 {_PRINT}"),
    spec(
        "/interface bridge host print",
        bridge_host_print,
        f"interface:3 bridge:2 host:2 {_PRINT}",
    ),
    spec("/system resource print", system_resource, f"system:3 resource:3 {_PRINT}"),
    spec("/system routerboard print", system_routerboard, f"system:3 routerboard:3 {_PRINT}"),
    spec("/system identity print", system_identity, f"system:3 identity:3 {_PRINT}"),
)
