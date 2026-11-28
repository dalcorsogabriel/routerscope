"""Config extraction for Junos (hierarchical brace form and ``display set`` form).

Both forms are matched on :attr:`ConfigNode.flat_words` (the words of the whole path), so the
same code reads ``interfaces { ge-0/0/0 { unit 0 { ... } } }`` and
``set interfaces ge-0/0/0 unit 0 ...``. Statements under ``inactive:`` / ``deactivate`` are
ignored: they are not part of the active configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from routerscope.model import VLAN, VRF, Device, ParsedConfig, PrefixListEntry, Snapshot
from routerscope.vendors._extract import (
    Builder,
    PeerBook,
    RouteTarget,
    add_prefix_lists,
    apply_interface_vrfs,
    make,
    make_static_route,
    parse_iface_addr,
    parse_ip,
    parse_net,
    prefix_entry,
    to_asn,
    to_int,
)
from routerscope.vendors._tree import ConfigNode, looks_like_set, parse_brace, parse_set

_AFI = {"inet": "ipv4", "inet6": "ipv6", "inet-vpn": "vpnv4", "inet6-vpn": "vpnv6"}


def _anchor(node: ConfigNode, k: int) -> ConfigNode:
    """The topmost ancestor-or-self whose path already holds at least ``k`` words."""
    current = node
    while (
        current.parent is not None
        and not current.parent.is_root
        and len(current.parent.flat_words) >= k
    ):
        current = current.parent
    return current


def _values(words: tuple[str, ...]) -> list[str]:
    """Values of ``x`` or ``[ x y z ]`` (the words right after a keyword)."""
    if not words:
        return []
    if words[0] == "[":
        out = []
        for word in words[1:]:
            if word == "]":
                break
            out.append(word)
        return out
    return [words[0]]


def _inactive(node: ConfigNode) -> bool:
    current: ConfigNode | None = node
    while current is not None:
        if current.inactive:
            return True
        current = current.parent
    return False


@dataclass
class _Unit:
    node: ConfigNode
    description: str | None = None
    disabled: bool = False
    addresses: dict[str, ConfigNode] = field(default_factory=dict)


@dataclass
class _Iface:
    node: ConfigNode
    description: str | None = None
    disabled: bool = False
    mtu: int | None = None
    units: dict[str, _Unit] = field(default_factory=dict)


@dataclass
class _Vrf:
    node: ConfigNode
    rd: str | None = None
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)
    description: str | None = None


@dataclass
class _Route:
    node: ConfigNode
    target: RouteTarget = field(default_factory=RouteTarget)
    metric: int | None = None


def parse_junos(text: str, snapshot: Snapshot, vendor: str) -> ParsedConfig:
    """Parse Junos configuration (brace or ``set`` form) into the neutral model."""
    root = parse_set(text, "junos") if looks_like_set(text, "junos") else parse_brace(text)
    b = Builder(snapshot, vendor)
    book = PeerBook()
    ifaces: dict[str, _Iface] = {}
    vrfs: dict[str, _Vrf] = {}
    routes: dict[tuple[str | None, str], _Route] = {}
    prefixes: dict[tuple[str, str], tuple[list[ConfigNode], list[PrefixListEntry]]] = {}
    vlans: dict[str, tuple[ConfigNode, int | None]] = {}
    peer_nodes: dict[tuple[str | None, str], ConfigNode] = {}
    local_as: int | None = None

    for node in root.walk():
        fw = node.flat_words
        if not fw or _inactive(node):
            continue
        vrf: str | None = None
        base = 0
        if fw[0] == "routing-instances" and len(fw) >= 3:
            vrf = fw[1]
            base = 2
            vrf_acc = vrfs.setdefault(vrf, _Vrf(_anchor(node, 2)))
            _vrf_stmt(vrf_acc, fw[2:])
        rel = fw[base:]
        if not rel:
            continue
        if vrf is None:
            if rel[:2] == ("system", "host-name") and len(rel) == 3 and b.device is None:
                b.device = make(Device, ref=b.ref(node), hostname=rel[2])
            elif rel[:2] == ("routing-options", "autonomous-system") and len(rel) >= 3:
                local_as = to_asn(rel[2]) or local_as
            elif rel[0] == "interfaces" and len(rel) >= 3:
                _iface_stmt(ifaces, node, rel)
            elif rel[0] == "vlans" and len(rel) >= 4 and rel[2] == "vlan-id":
                vlans.setdefault(rel[1], (_anchor(node, 2), to_int(rel[3])))
            elif rel[:2] == ("policy-options", "prefix-list") and len(rel) >= 4:
                _prefix_stmt(prefixes, node, fw, rel)
        if rel[:2] == ("protocols", "bgp"):
            _bgp_stmt(book, peer_nodes, node, fw, rel, vrf)
        elif rel[0] == "routing-options":
            _route_stmt(routes, node, fw, rel, vrf)

    for (peer_vrf, name), anchor in peer_nodes.items():
        peer_acc = book.peers[(peer_vrf, name)]
        peer_acc.ref = (anchor.line_start, anchor.line_end)
        grp = book.groups.get((peer_vrf, peer_acc.group or ""))
        if peer_acc.local_as is None and (grp is None or grp.local_as is None):
            peer_acc.local_as = local_as
    book.emit(b)

    iface_vrf: dict[str, str] = {}
    for name, v in vrfs.items():
        for member in v.interfaces:
            iface_vrf[member] = name
        obj = make(
            VRF,
            ref=b.ref(v.node),
            name=name,
            rd=v.rd,
            import_targets=tuple(v.imports),
            export_targets=tuple(v.exports),
            interfaces=tuple(v.interfaces),
            description=v.description,
        )
        if obj is not None:
            b.vrfs.append(obj)
    for name, i in ifaces.items():
        b.interface(i.node, name, description=i.description, enabled=not i.disabled, mtu=i.mtu)
        for unit, u in i.units.items():
            unit_name = f"{name}.{unit}"
            b.interface(
                u.node, unit_name, description=u.description, enabled=not (u.disabled or i.disabled)
            )
            for address, address_node in u.addresses.items():
                b.address(address_node, unit_name, parse_iface_addr(address))
    apply_interface_vrfs(b, iface_vrf)
    for (route_vrf, prefix), r in routes.items():
        make_static_route(b, r.node, parse_net(prefix), r.target, route_vrf, metric=r.metric)
    add_prefix_lists(b, prefixes)
    for vlan_name, (vlan_node, vid) in vlans.items():
        vlan = make(VLAN, ref=b.ref(vlan_node), vlan_id=vid, name=vlan_name)
        if vlan is not None:
            b.vlans.append(vlan)
    return b.build()


def _vrf_stmt(acc: _Vrf, rest: tuple[str, ...]) -> None:
    if rest[0] == "route-distinguisher" and len(rest) >= 2:
        acc.rd = rest[1]
    elif rest[0] == "description" and len(rest) >= 2:
        acc.description = rest[1]
    elif rest[0] == "interface" and len(rest) >= 2 and rest[1] not in acc.interfaces:
        acc.interfaces.append(rest[1])
    elif rest[0] == "vrf-target" and len(rest) >= 2:
        if rest[1] == "import" and len(rest) >= 3:
            acc.imports.append(rest[2])
        elif rest[1] == "export" and len(rest) >= 3:
            acc.exports.append(rest[2])
        elif rest[1].startswith("target:"):
            acc.imports.append(rest[1])
            acc.exports.append(rest[1])


def _iface_stmt(ifaces: dict[str, _Iface], node: ConfigNode, rel: tuple[str, ...]) -> None:
    name = rel[1]
    acc = ifaces.setdefault(name, _Iface(_anchor(node, 2)))
    tail = rel[2:]
    if tail[0] == "unit" and len(tail) >= 3:
        unit = ifaces[name].units.setdefault(tail[1], _Unit(_anchor(node, 4)))
        body = tail[2:]
        if body[0] == "description" and len(body) >= 2:
            unit.description = body[1]
        elif body[0] == "disable":
            unit.disabled = True
        elif body[0] == "family" and len(body) >= 4 and body[2] == "address":
            unit.addresses.setdefault(body[3], _anchor(node, 8))
    elif tail[0] == "description" and len(tail) >= 2:
        acc.description = tail[1]
    elif tail[0] == "disable":
        acc.disabled = True
    elif tail[0] == "mtu" and len(tail) >= 2:
        acc.mtu = to_int(tail[1])


def _bgp_stmt(
    book: PeerBook,
    peer_nodes: dict[tuple[str | None, str], ConfigNode],
    node: ConfigNode,
    fw: tuple[str, ...],
    rel: tuple[str, ...],
    vrf: str | None,
) -> None:
    body = rel[2:]
    group: str | None = None
    if body[:1] == ("group",) and len(body) >= 3:
        group = body[1]
        body = body[2:]
    peer: str | None = None
    if body[:1] == ("neighbor",) and len(body) >= 3 and parse_ip(body[1]) is not None:
        peer = body[1]
        body = body[2:]
        peer_nodes.setdefault((vrf, peer), _anchor(node, len(fw) - len(body)))
    if peer is None and group is None:
        return
    if peer is not None:
        acc = book.peer(vrf, peer)
        if group is not None:
            acc.group = group
    else:
        assert group is not None
        acc = book.group(vrf, group)
    if not body:
        return
    key = body[0]
    if key == "peer-as" and len(body) >= 2:
        acc.remote_as = to_asn(body[1])
    elif key == "local-as" and len(body) >= 2:
        acc.local_as = to_asn(body[1])
    elif key == "description" and len(body) >= 2:
        acc.description = body[1]
    elif key == "import":
        acc.imports.extend(v for v in _values(body[1:]) if v not in acc.imports)
    elif key == "export":
        acc.exports.extend(v for v in _values(body[1:]) if v not in acc.exports)
    elif key == "family" and len(body) >= 2:
        acc.add_family(" ".join([_AFI.get(body[1], body[1]), *body[2:3]]))


def _route_stmt(
    routes: dict[tuple[str | None, str], _Route],
    node: ConfigNode,
    fw: tuple[str, ...],
    rel: tuple[str, ...],
    vrf: str | None,
) -> None:
    if "static" not in rel:
        return
    at = rel.index("static")
    if rel[at + 1 : at + 2] != ("route",) or len(rel) < at + 3:
        return
    prefix = rel[at + 2]
    route = routes.setdefault((vrf, prefix), _Route(_anchor(node, len(fw) - len(rel) + at + 3)))
    body = rel[at + 3 :]
    if not body:
        return
    key = body[0]
    if key == "next-hop" and len(body) >= 2:
        first = _values(body[1:])[0] if _values(body[1:]) else None
        if first is not None:
            address = parse_ip(first)
            if address is not None:
                route.target.next_hop = route.target.next_hop or address
            elif route.target.interface is None:
                route.target.interface = first
    elif key in ("discard", "reject"):
        route.target.blackhole = True
    elif key == "preference" and len(body) >= 2:
        route.target.distance = to_int(body[1])
    elif key == "tag" and len(body) >= 2:
        route.target.tag = to_int(body[1])
    elif key == "metric" and len(body) >= 2:
        route.metric = to_int(body[1])
    elif key == "description" and len(body) >= 2:
        route.target.description = body[1]


def _prefix_stmt(
    acc: dict[tuple[str, str], tuple[list[ConfigNode], list[PrefixListEntry]]],
    node: ConfigNode,
    fw: tuple[str, ...],
    rel: tuple[str, ...],
) -> None:
    name = rel[2]
    prefix = parse_net(rel[3])
    if prefix is None or "/" not in rel[3]:
        return
    entry = prefix_entry("permit", prefix)
    if entry is None:
        return
    afi = "ipv6" if prefix.version == 6 else "ipv4"
    nodes, entries = acc.setdefault((afi, name), ([], []))
    list_node = _anchor(node, 3 + len(fw) - len(rel))
    if not any(n is list_node for n in nodes):
        nodes.append(list_node)
    if all(e.prefix != prefix for e in entries):
        entries.append(entry)
