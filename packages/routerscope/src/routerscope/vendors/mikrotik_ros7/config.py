"""Config extraction for MikroTik RouterOS ``/export`` output."""

from __future__ import annotations

from routerscope.model import VLAN, VRF, BGPPeer, Device, ParsedConfig, Snapshot
from routerscope.vendors._extract import (
    Builder,
    RouteTarget,
    apply_interface_vrfs,
    make,
    make_static_route,
    parse_iface_addr,
    parse_ip,
    parse_net,
    to_asn,
    to_int,
)
from routerscope.vendors._tree import ConfigNode, parse_command, parse_routeros

_IFACE_SECTIONS = (
    "/interface ethernet",
    "/interface vlan",
    "/interface bridge",
    "/interface bonding",
    "/interface vrrp",
    "/interface wireguard",
    "/interface gre",
    "/interface eoip",
    "/interface vxlan",
    "/interface loopback",
    "/interface wifi",
    "/interface lte",
    "/interface 6to4",
)


def _flag(value: str | None) -> bool:
    return value is not None and value.lower() in ("yes", "true")


def parse_routeros_config(text: str, snapshot: Snapshot, vendor: str) -> ParsedConfig:
    """Parse a RouterOS ``/export`` into the neutral model."""
    root = parse_routeros(text)
    b = Builder(snapshot, vendor)
    iface_vrf: dict[str, str] = {}
    instances: dict[str, int | None] = {}
    vrf_members: dict[str, list[str]] = {}
    ifaces: dict[str, int] = {}

    for section in root.children:
        head = section.text
        for node in section.children:
            cmd = parse_command(node.text)
            p = cmd.params
            if head == "/system identity" and cmd.verb == "set" and "name" in p:
                if b.device is None:
                    b.device = make(Device, ref=b.ref(node), hostname=p["name"])
            elif head in _IFACE_SECTIONS:
                _interface(b, node, cmd.verb, cmd.selector, p, ifaces)
                if head == "/interface vlan" and cmd.verb == "add":
                    _vlan(b, node, p)
            elif head == "/interface bridge vlan" and cmd.verb == "add":
                _bridge_vlans(b, node, p)
            elif head in ("/ip address", "/ipv6 address") and cmd.verb == "add":
                addr = parse_iface_addr(p["address"]) if "address" in p else None
                if "interface" in p:
                    b.address(node, p["interface"], addr)
            elif head == "/ip vrf" and cmd.verb == "add" and "name" in p:
                members = [i for i in p.get("interfaces", "").split(",") if i]
                vrf_members[p["name"]] = members
                for member in members:
                    iface_vrf[member] = p["name"]
                vrf = make(VRF, ref=b.ref(node), name=p["name"], interfaces=tuple(members))
                if vrf is not None:
                    b.vrfs.append(vrf)
            elif head == "/routing bgp instance" and cmd.verb == "add" and "name" in p:
                instances[p["name"]] = to_asn(p.get("as"))
            elif head == "/routing bgp connection" and cmd.verb == "add":
                _bgp(b, node, p, instances, local_key="remote")
            elif head == "/routing bgp peer" and cmd.verb == "add":
                _bgp(b, node, p, instances, local_key="legacy")
            elif head in ("/ip route", "/ipv6 route") and cmd.verb == "add":
                _route(b, node, p, cmd.positional)
    apply_interface_vrfs(b, iface_vrf)
    return b.build()


def _interface(
    b: Builder,
    node: ConfigNode,
    verb: str,
    selector: str,
    p: dict[str, str],
    seen: dict[str, int],
) -> None:
    name: str | None = None
    if verb == "add":
        name = p.get("name")
    elif verb == "set" and selector.startswith("find") and "default-name=" in selector:
        default = selector.split("default-name=", 1)[1].split()[0]
        name = p.get("name", default)
    if not name:
        return
    seen[name] = node.line_start
    b.interface(
        node,
        name,
        description=p.get("comment"),
        enabled=not _flag(p.get("disabled")),
        mtu=to_int(p.get("mtu")),
    )


def _vlan(b: Builder, node: ConfigNode, p: dict[str, str]) -> None:
    vid = to_int(p.get("vlan-id"))
    if vid is not None:
        vlan = make(
            VLAN,
            ref=b.ref(node),
            vlan_id=vid,
            name=p.get("name"),
            interfaces=(p["name"],) if "name" in p else (),
        )
        if vlan is not None:
            b.vlans.append(vlan)


def _bridge_vlans(b: Builder, node: ConfigNode, p: dict[str, str]) -> None:
    members = tuple(i for i in (p.get("tagged", "") + "," + p.get("untagged", "")).split(",") if i)
    for part in p.get("vlan-ids", "").split(","):
        low, _, high = part.partition("-")
        start = to_int(low)
        end = to_int(high) if high else start
        if start is None or end is None or end < start or end - start > 4094:
            continue
        for vid in range(start, end + 1):
            vlan = make(VLAN, ref=b.ref(node), vlan_id=vid, interfaces=members)
            if vlan is not None:
                b.vlans.append(vlan)


def _bgp(
    b: Builder,
    node: ConfigNode,
    p: dict[str, str],
    instances: dict[str, int | None],
    local_key: str,
) -> None:
    if local_key == "remote":
        address = parse_ip(p.get("remote.address", "").partition("/")[0])
        remote_as = to_asn(p.get("remote.as"))
        local_as = to_asn(p.get("as")) or instances.get(p.get("instance", ""))
        imports = p.get("input.filter")
        exports = p.get("output.filter-chain")
    else:
        address = parse_ip(p.get("remote-address", ""))
        remote_as = to_asn(p.get("remote-as"))
        local_as = instances.get(p.get("instance", ""))
        imports = p.get("in-filter")
        exports = p.get("out-filter")
    if address is None or remote_as is None:
        return
    peer = make(
        BGPPeer,
        ref=b.ref(node),
        peer=address,
        remote_as=remote_as,
        local_as=local_as,
        vrf=p.get("vrf") if p.get("vrf", "main") != "main" else None,
        description=p.get("comment") or p.get("name"),
        import_policies=(imports,) if imports else (),
        export_policies=(exports,) if exports else (),
    )
    if peer is not None:
        b.bgp_peers.append(peer)


def _route(b: Builder, node: ConfigNode, p: dict[str, str], positional: list[str]) -> None:
    prefix = parse_net(p["dst-address"]) if "dst-address" in p else None
    target = RouteTarget(
        distance=to_int(p.get("distance")),
        description=p.get("comment"),
        blackhole="blackhole" in positional or p.get("type") == "blackhole",
    )
    gateway = p.get("gateway")
    if gateway:
        address = parse_ip(gateway.partition("%")[0])
        if address is not None:
            target.next_hop = address
        else:
            target.interface = gateway
    table = p.get("routing-table")
    vrf = table if table and table != "main" else None
    make_static_route(b, node, prefix, target, vrf)
