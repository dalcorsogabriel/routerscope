"""Config extraction for Nokia SR OS: classic CLI and MD-CLI (``info`` and ``info flat``)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from routerscope.model import VRF, Device, ParsedConfig, Snapshot, split_lines
from routerscope.vendors._extract import (
    Builder,
    PeerAcc,
    PeerBook,
    PrefixTable,
    RouteTarget,
    add_prefix_lists,
    make,
    make_static_route,
    parse_iface_addr,
    parse_ip,
    parse_net,
    parse_route_target,
    prefix_entry,
    rest,
    to_asn,
    to_int,
)
from routerscope.vendors._flat import anchor_at, is_inactive, values
from routerscope.vendors._tree import (
    ConfigNode,
    looks_like_set,
    parse_brace,
    parse_indented,
    parse_set,
)

_MDCLI = re.compile(r"^\s*(configure\s*\{|/configure\s)", re.MULTILINE)


def parse_sros(text: str, snapshot: Snapshot, vendor: str) -> ParsedConfig:
    """Parse SR OS configuration (MD-CLI brace/flat form or classic CLI) into the model."""
    if looks_like_set(text, "mdcli"):
        return _mdcli(parse_set(text, "mdcli"), snapshot, vendor)
    if _MDCLI.search("\n".join(split_lines(text))):
        return _mdcli(parse_brace(text, "mdcli"), snapshot, vendor)
    return _classic(parse_indented(text, "sros"), snapshot, vendor)


# --------------------------------------------------------------------------- classic


def _classic(root: ConfigNode, snapshot: Snapshot, vendor: str) -> ParsedConfig:
    b = Builder(snapshot, vendor)
    book = PeerBook()
    prefixes = PrefixTable()
    for node in root.walk():
        w = node.words
        if not w:
            continue
        parent = node.parent.words if node.parent is not None else []
        if w[0] == "name" and len(w) == 2 and parent[:1] == ["system"] and b.device is None:
            b.device = make(Device, ref=b.ref(node), hostname=w[1])
        elif w[0] == "router" and (len(w) == 1 or w[1] == "Base") and "create" not in w:
            _classic_router(b, book, node, None)
        elif w[0] == "vprn" and len(w) >= 2:
            _classic_vprn(b, book, node)
        elif w[0] == "port" and len(w) == 2 and parent[:1] != ["router"] and node.children:
            _classic_port(b, node)
        elif w[0] == "prefix-list" and len(w) == 2 and parent[:1] == ["policy-options"]:
            _classic_prefix_list(prefixes, node, w[1])
    book.emit(b)
    add_prefix_lists(b, prefixes)
    b.vrfs = [
        v.model_copy(update={"interfaces": tuple(i.name for i in b.interfaces if i.vrf == v.name)})
        for v in b.vrfs
    ]
    return b.build()


def _classic_vprn(b: Builder, book: PeerBook, node: ConfigNode) -> None:
    words = node.words
    name = f"vprn{words[1]}"
    if "name" in words[2:-1]:
        name = words[words.index("name") + 1]
    rd: str | None = None
    imports: list[str] = []
    exports: list[str] = []
    for child in node.children:
        cw = child.words
        if cw[:1] == ["service-name"] and len(cw) == 2:
            name = cw[1]
        elif cw[:1] == ["route-distinguisher"] and len(cw) == 2:
            rd = cw[1]
        elif cw[:1] == ["vrf-target"] and len(cw) >= 2:
            if cw[1] == "export" and len(cw) >= 3:
                exports.append(cw[2])
            elif cw[1] == "import" and len(cw) >= 3:
                imports.append(cw[2])
            else:
                imports.append(cw[1])
                exports.append(cw[1])
    vrf = make(
        VRF,
        ref=b.ref(node),
        name=name,
        rd=rd,
        import_targets=tuple(imports),
        export_targets=tuple(exports),
    )
    if vrf is not None:
        b.vrfs.append(vrf)
    _classic_router(b, book, node, name)


def _classic_port(b: Builder, node: ConfigNode) -> None:
    description: str | None = None
    enabled: bool | None = None
    for child in node.children:
        if child.words[:1] == ["description"]:
            description = rest(child.text, 1)
        elif child.words == ["shutdown"]:
            enabled = False
        elif child.words == ["no", "shutdown"]:
            enabled = True
    b.interface(node, node.words[1], description=description, enabled=enabled)


def _classic_router(b: Builder, book: PeerBook, node: ConfigNode, vrf: str | None) -> None:
    local_as: int | None = None
    for child in node.children:
        cw = child.words
        if cw[:1] == ["autonomous-system"] and len(cw) == 2:
            local_as = to_asn(cw[1])
    for child in node.children:
        cw = child.words
        if cw[:1] == ["interface"] and len(cw) >= 2:
            _classic_interface(b, child, vrf)
        elif cw == ["bgp"]:
            _classic_bgp(book, child, vrf, local_as)
        elif cw[:1] == ["static-route-entry"] and len(cw) == 2:
            _classic_static(b, child, vrf)
        elif cw[:1] == ["static-route"] and len(cw) >= 4 and cw[2] == "next-hop":
            make_static_route(b, child, parse_net(cw[1]), parse_route_target(cw[2:]), vrf)


def _classic_interface(b: Builder, node: ConfigNode, vrf: str | None) -> None:
    name = node.words[1]
    description: str | None = None
    enabled = True
    mtu: int | None = None
    addresses = []
    for child in node.children:
        cw = child.words
        if cw[:1] == ["description"]:
            description = rest(child.text, 1)
        elif cw == ["shutdown"]:
            enabled = False
        elif cw == ["no", "shutdown"]:
            enabled = True
        elif cw[:1] == ["ip-mtu"] and len(cw) == 2:
            mtu = to_int(cw[1])
        elif cw[:1] == ["address"] and len(cw) >= 2:
            addresses.append((child, parse_iface_addr(cw[1]), "secondary" in cw[2:]))
        elif cw[:1] == ["secondary"] and len(cw) >= 2:
            addresses.append((child, parse_iface_addr(cw[1]), True))
        elif cw == ["ipv6"]:
            for sub in child.children:
                sw = sub.words
                if sw[:1] == ["address"] and len(sw) >= 2:
                    addresses.append((sub, parse_iface_addr(sw[1]), False))
    iface = b.interface(node, name, description=description, enabled=enabled, mtu=mtu, vrf=vrf)
    if iface is None:
        return
    for child, addr, secondary in addresses:
        b.address(child, name, addr, vrf=vrf, secondary=secondary)


def _classic_bgp(book: PeerBook, node: ConfigNode, vrf: str | None, local_as: int | None) -> None:
    def attrs(acc: PeerAcc, owner: ConfigNode) -> None:
        for child in owner.children:
            cw = child.words
            if cw[:1] == ["peer-as"] and len(cw) >= 2:
                acc.remote_as = to_asn(cw[1])
            elif cw[:1] == ["local-as"] and len(cw) >= 2:
                acc.local_as = to_asn(cw[1])
            elif cw[:1] == ["description"]:
                acc.description = rest(child.text, 1)
            elif cw[:1] == ["import"]:
                acc.imports.extend(cw[1:])
            elif cw[:1] == ["export"]:
                acc.exports.extend(cw[1:])
            elif cw[:1] == ["family"]:
                for fam in cw[1:]:
                    acc.add_family(fam)

    def neighbor(child: ConfigNode, group: str | None) -> None:
        cw = child.words
        if len(cw) == 2 and parse_ip(cw[1]) is not None:
            acc = book.peer(vrf, cw[1])
            acc.ref = (child.line_start, child.line_end)
            acc.group = group
            attrs(acc, child)
            if acc.local_as is None:
                grp = book.groups.get((vrf, group or ""))
                if grp is None or grp.local_as is None:
                    acc.local_as = local_as

    for child in node.children:
        cw = child.words
        if cw[:1] == ["group"] and len(cw) == 2:
            attrs(book.group(vrf, cw[1]), child)
    for child in node.children:
        cw = child.words
        if cw[:1] == ["group"] and len(cw) == 2:
            for sub in child.children:
                if sub.words[:1] == ["neighbor"]:
                    neighbor(sub, cw[1])
        elif cw[:1] == ["neighbor"]:
            neighbor(child, None)


def _classic_static(b: Builder, node: ConfigNode, vrf: str | None) -> None:
    prefix = parse_net(node.words[1])
    for child in node.children:
        cw = child.words
        target = RouteTarget()
        if cw[:1] == ["next-hop"] and len(cw) == 2:
            target.next_hop = parse_ip(cw[1])
            if target.next_hop is None:
                target.interface = cw[1]
        elif cw in (["black-hole"], ["blackhole"]):
            target.blackhole = True
        else:
            continue
        for sub in child.children:
            sw = sub.words
            if sw[:1] == ["preference"] and len(sw) == 2:
                target.distance = to_int(sw[1])
            elif sw[:1] == ["tag"] and len(sw) == 2:
                target.tag = to_int(sw[1])
            elif sw[:1] == ["description"]:
                target.description = rest(sub.text, 1)
        make_static_route(b, child, prefix, target, vrf, start=node)


def _classic_prefix_list(prefixes: PrefixTable, node: ConfigNode, name: str) -> None:
    for entry in node.children:
        ew = entry.words
        if ew[:1] != ["prefix"] or len(ew) < 2:
            continue
        prefix = parse_net(ew[1])
        if prefix is None:
            continue
        item = prefix_entry(
            "permit", prefix, **_length_bounds(prefix.prefixlen, prefix.max_prefixlen, ew[2:])
        )
        if item is None:
            continue
        afi = "ipv6" if prefix.version == 6 else "ipv4"
        prefixes.acc(afi, name).add(node, item)


def _length_bounds(length: int, top: int, words: list[str]) -> dict[str, int | None]:
    """Map SR OS match types (``exact``, ``longer``, ``through N``, ``prefix-length-range``)."""
    ge = le = None
    if words[:1] == ["longer"]:
        ge, le = length + 1, top
    elif words[:1] == ["orlonger"]:
        ge, le = length, top
    elif words[:1] == ["through"] and len(words) >= 2:
        ge, le = length, to_int(words[1])
    elif words[:1] == ["prefix-length-range"] and len(words) >= 2:
        low, _, high = words[1].partition("-")
        ge, le = to_int(low), to_int(high)
    return {"ge": ge, "le": le}


# --------------------------------------------------------------------------- MD-CLI

_Addr = tuple[ConfigNode, int | None, bool]
_Route = tuple[ConfigNode, RouteTarget, ConfigNode]


@dataclass
class _MdIface:
    node: ConfigNode
    vrf: str | None
    description: str | None = None
    disabled: bool = False
    mtu: int | None = None
    v4: dict[str, _Addr] = field(default_factory=dict)
    v6: dict[str, _Addr] = field(default_factory=dict)
    primary: str | None = None


@dataclass
class _MdPort:
    nodes: list[ConfigNode] = field(default_factory=list)
    description: str | None = None
    enabled: bool | None = None


@dataclass
class _MdVprn:
    node: ConfigNode
    rd: str | None = None
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)


_KINDS = {"exact": 0, "longer": 1, "orlonger": 2, "range": 3}


def _mdcli(root: ConfigNode, snapshot: Snapshot, vendor: str) -> ParsedConfig:
    b = Builder(snapshot, vendor)
    book = PeerBook()
    prefixes = PrefixTable()
    ifaces: dict[tuple[str | None, str], _MdIface] = {}
    ports: dict[str, _MdPort] = {}
    peer_nodes: dict[tuple[str | None, str], ConfigNode] = {}
    vprns: dict[str, _MdVprn] = {}
    routes: dict[tuple[str | None, str, str], _Route] = {}
    held: dict[tuple[str, str, str], dict[str, int | None]] = {}
    local_as: dict[str | None, int | None] = {}

    for node in root.walk():
        fw = node.flat_words
        if len(fw) < 2 or fw[0] != "configure" or is_inactive(node):
            continue
        rel = fw[1:]
        if rel[:2] == ("system", "name") and len(rel) == 3 and b.device is None:
            b.device = make(Device, ref=b.ref(node), hostname=rel[2])
            continue
        if rel[0] == "port" and len(rel) >= 2:
            _md_port(ports, node, rel)
            continue
        vrf: str | None = None
        base = 0
        if rel[:2] == ("router", "Base"):
            base = 2
        elif rel[:2] == ("service", "vprn") and len(rel) >= 3:
            vrf = rel[2]
            base = 3
            _md_vprn(vprns, node, rel)
        elif rel[0] == "policy-options" and len(rel) >= 5 and rel[1] == "prefix-list":
            _md_prefix(prefixes, held, node, fw, rel)
            continue
        else:
            continue
        body = rel[base:]
        if not body:
            continue
        if body[0] == "autonomous-system" and len(body) >= 2:
            local_as[vrf] = to_asn(body[1])
        elif body[0] == "interface" and len(body) >= 2:
            _md_iface(ifaces, node, fw, body, vrf)
        elif body[:2] == ("bgp", "neighbor") or body[:2] == ("bgp", "group"):
            _md_bgp(book, peer_nodes, node, fw, body, vrf)
        elif body[:1] == ("static-routes",) and len(body) >= 3 and body[1] == "route":
            _md_route(routes, node, fw, body, vrf)

    for (peer_vrf, name), peer_node in peer_nodes.items():
        acc = book.peers[(peer_vrf, name)]
        acc.ref = (peer_node.line_start, peer_node.line_end)
        grp = book.groups.get((peer_vrf, acc.group or ""))
        if acc.local_as is None and (grp is None or grp.local_as is None):
            acc.local_as = local_as.get(peer_vrf)
    book.emit(b)

    for port_name, port in ports.items():
        b.interface(port.nodes, port_name, description=port.description, enabled=port.enabled)
    for (scope, name), i in ifaces.items():
        b.interface(
            i.node,
            name,
            description=i.description,
            enabled=not i.disabled,
            mtu=i.mtu,
            vrf=scope,
        )
        for table in (i.v4, i.v6):
            for address, (addr_node, length, secondary) in table.items():
                if length is not None:
                    b.address(
                        addr_node,
                        name,
                        parse_iface_addr(address, str(length)),
                        vrf=scope,
                        secondary=secondary,
                    )
    for vrf_name, vp in vprns.items():
        vrf_obj = make(
            VRF,
            ref=b.ref(vp.node),
            name=vrf_name,
            rd=vp.rd,
            import_targets=tuple(vp.imports),
            export_targets=tuple(vp.exports),
            interfaces=tuple(i.name for i in b.interfaces if i.vrf == vrf_name),
        )
        if vrf_obj is not None:
            b.vrfs.append(vrf_obj)
    for (route_vrf, prefix, _), (route_node, target, start) in routes.items():
        make_static_route(b, route_node, parse_net(prefix), target, route_vrf, start=start)
    for (afi, name, prefix_text), slot in held.items():
        _apply_bounds(prefixes, afi, name, prefix_text, slot)
    add_prefix_lists(b, prefixes)
    return b.build()


def _md_port(ports: dict[str, _MdPort], node: ConfigNode, rel: tuple[str, ...]) -> None:
    port = ports.setdefault(rel[1], _MdPort())
    target = anchor_at(node, 3)
    if all(target is not n for n in port.nodes):
        port.nodes.append(target)
    tail = rel[2:]
    if tail[:1] == ("description",) and len(tail) >= 2:
        port.description = tail[1]
    elif tail[:1] == ("admin-state",) and len(tail) >= 2:
        port.enabled = tail[1] != "disable"


def _md_vprn(vprns: dict[str, _MdVprn], node: ConfigNode, rel: tuple[str, ...]) -> None:
    vp = vprns.setdefault(rel[2], _MdVprn(anchor_at(node, 4)))
    tail = rel[3:]
    if tail[:1] == ("route-distinguisher",) and len(tail) >= 2:
        vp.rd = tail[1]
    elif tail[:1] == ("vrf-target",) and len(tail) >= 3:
        if tail[1] in ("community", "import-community"):
            vp.imports.append(tail[2])
        if tail[1] in ("community", "export-community"):
            vp.exports.append(tail[2])


def _set_addr(
    table: dict[str, _Addr],
    address: str,
    node: ConfigNode,
    length: int | None,
    *,
    secondary: bool,
) -> None:
    previous = table.get(address)
    if previous is not None:
        node = previous[0]
        length = length if length is not None else previous[1]
    table[address] = (node, length, secondary)


def _md_iface(
    ifaces: dict[tuple[str | None, str], _MdIface],
    node: ConfigNode,
    fw: tuple[str, ...],
    body: tuple[str, ...],
    vrf: str | None,
) -> None:
    key = (vrf, body[1])
    acc = ifaces.setdefault(key, _MdIface(anchor_at(node, len(fw) - len(body) + 2), vrf))
    tail = body[2:]
    if not tail:
        return
    base = len(fw) - len(tail)
    if tail[0] == "description" and len(tail) >= 2:
        acc.description = tail[1]
    elif tail[0] == "admin-state" and len(tail) >= 2:
        acc.disabled = tail[1] == "disable"
    elif tail[0] == "ip-mtu" and len(tail) >= 2:
        acc.mtu = to_int(tail[1])
    elif tail[:3] == ("ipv4", "primary", "address") and len(tail) >= 4:
        acc.primary = tail[3]
        _set_addr(acc.v4, tail[3], anchor_at(node, base + 4), None, secondary=False)
    elif tail[:3] == ("ipv4", "primary", "prefix-length") and len(tail) >= 4:
        if acc.primary is not None and acc.primary in acc.v4:
            first = acc.v4[acc.primary][0]
            _set_addr(acc.v4, acc.primary, first, to_int(tail[3]), secondary=False)
    elif tail[:2] == ("ipv4", "secondary") and len(tail) >= 3:
        length = to_int(tail[4]) if tail[3:4] == ("prefix-length",) and len(tail) >= 5 else None
        _set_addr(acc.v4, tail[2], anchor_at(node, base + 3), length, secondary=True)
    elif tail[:2] == ("ipv6", "address") and len(tail) >= 3:
        length = to_int(tail[4]) if tail[3:4] == ("prefix-length",) and len(tail) >= 5 else None
        _set_addr(acc.v6, tail[2], anchor_at(node, base + 3), length, secondary=False)


def _md_bgp(
    book: PeerBook,
    peer_nodes: dict[tuple[str | None, str], ConfigNode],
    node: ConfigNode,
    fw: tuple[str, ...],
    body: tuple[str, ...],
    vrf: str | None,
) -> None:
    if len(body) < 3:
        return
    name = body[2]
    attrs = body[3:]
    if body[1] == "neighbor":
        if parse_ip(name) is None:
            return
        acc = book.peer(vrf, name)
        peer_nodes.setdefault((vrf, name), anchor_at(node, len(fw) - len(attrs)))
    else:
        acc = book.group(vrf, name)
    if not attrs:
        return
    key = attrs[0]
    if key == "peer-as" and len(attrs) >= 2:
        acc.remote_as = to_asn(attrs[1])
    elif key == "group" and len(attrs) >= 2 and body[1] == "neighbor":
        acc.group = attrs[1]
    elif key == "description" and len(attrs) >= 2:
        acc.description = attrs[1]
    elif key == "local-as" and len(attrs) >= 3 and attrs[1] == "as-number":
        acc.local_as = to_asn(attrs[2])
    elif key == "import" and attrs[1:2] == ("policy",):
        acc.imports.extend(v for v in values(attrs[2:]) if v not in acc.imports)
    elif key == "export" and attrs[1:2] == ("policy",):
        acc.exports.extend(v for v in values(attrs[2:]) if v not in acc.exports)


def _md_route(
    routes: dict[tuple[str | None, str, str], _Route],
    node: ConfigNode,
    fw: tuple[str, ...],
    body: tuple[str, ...],
    vrf: str | None,
) -> None:
    prefix = body[2]
    start = anchor_at(node, len(fw) - len(body) + 3)
    tail = body[3:]
    if tail[:1] == ("route-type",) and len(tail) >= 2:
        tail = tail[2:]
    if not tail:
        return
    if tail[0] == "next-hop" and len(tail) >= 2:
        nh = tail[1]
        entry = routes.setdefault(
            (vrf, prefix, nh),
            (anchor_at(node, len(fw) - len(tail) + 2), RouteTarget(), start),
        )
        target = entry[1]
        address = parse_ip(nh)
        if address is not None:
            target.next_hop = address
        else:
            target.interface = nh
        attr = tail[2:]
    elif tail[0] in ("black-hole", "blackhole"):
        entry = routes.setdefault(
            (vrf, prefix, "black-hole"),
            (anchor_at(node, len(fw) - len(tail) + 1), RouteTarget(), start),
        )
        entry[1].blackhole = True
        target = entry[1]
        attr = tail[1:]
    else:
        return
    if attr[:1] == ("preference",) and len(attr) >= 2:
        target.distance = to_int(attr[1])
    elif attr[:1] == ("tag",) and len(attr) >= 2:
        target.tag = to_int(attr[1])
    elif attr[:1] == ("description",) and len(attr) >= 2:
        target.description = attr[1]


def _md_prefix(
    prefixes: PrefixTable,
    held: dict[tuple[str, str, str], dict[str, int | None]],
    node: ConfigNode,
    fw: tuple[str, ...],
    rel: tuple[str, ...],
) -> None:
    name = rel[2]
    if rel[3] != "prefix":
        return
    prefix = parse_net(rel[4])
    if prefix is None:
        return
    afi = "ipv6" if prefix.version == 6 else "ipv4"
    list_node = anchor_at(node, len(fw) - len(rel) + 3 + 1)
    prefixes.acc(afi, name).add(list_node, prefix_entry("permit", prefix), unique=True)
    tail = rel[5:]
    slot = held.setdefault((afi, name, rel[4]), {})
    if "type" in tail[:-1]:
        slot["kind"] = _KINDS.get(tail[tail.index("type") + 1], 0)
    for key, field_name in (("start-length", "ge"), ("end-length", "le")):
        if key in tail[:-1]:
            slot[field_name] = to_int(tail[tail.index(key) + 1])


def _apply_bounds(
    prefixes: PrefixTable, afi: str, name: str, prefix_text: str, slot: dict[str, int | None]
) -> None:
    acc = prefixes.get((afi, name))
    prefix = parse_net(prefix_text)
    if acc is None or prefix is None:
        return
    kind = slot.get("kind")
    ge, le = slot.get("ge"), slot.get("le")
    if kind == 1:
        ge, le = prefix.prefixlen + 1, prefix.max_prefixlen
    elif kind == 2:
        ge, le = prefix.prefixlen, prefix.max_prefixlen
    elif ge is None and le is None:
        return
    new = prefix_entry("permit", prefix, ge=ge, le=le)
    if new is not None:
        acc.replace(new)
