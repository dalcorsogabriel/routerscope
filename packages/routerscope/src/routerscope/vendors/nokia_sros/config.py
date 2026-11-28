"""Config extraction for Nokia SR OS: classic CLI and MD-CLI (``info`` and ``info flat``)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from routerscope.model import VRF, Device, ParsedConfig, PrefixListEntry, Snapshot
from routerscope.vendors._extract import (
    Builder,
    PeerAcc,
    PeerBook,
    RouteTarget,
    add_prefix_lists,
    apply_interface_vrfs,
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
from routerscope.vendors._tree import (
    ConfigNode,
    looks_like_set,
    parse_brace,
    parse_indented,
    parse_set,
)

_MDCLI = re.compile(r"^\s*(configure\s*\{|/configure\s)", re.MULTILINE)
_Prefixes = dict[tuple[str, str], tuple[list[ConfigNode], list[PrefixListEntry]]]


def parse_sros(text: str, snapshot: Snapshot, vendor: str) -> ParsedConfig:
    """Parse SR OS configuration (MD-CLI brace/flat form or classic CLI) into the model."""
    if looks_like_set(text, "mdcli"):
        return _mdcli(parse_set(text, "mdcli"), snapshot, vendor)
    if _MDCLI.search(text):
        return _mdcli(parse_brace(text, "mdcli"), snapshot, vendor)
    return _classic(parse_indented(text, "sros"), snapshot, vendor)


# --------------------------------------------------------------------------- classic


def _classic(root: ConfigNode, snapshot: Snapshot, vendor: str) -> ParsedConfig:
    b = Builder(snapshot, vendor)
    book = PeerBook()
    prefixes: _Prefixes = {}
    iface_vrf: dict[str, str] = {}
    for node in root.walk():
        w = node.words
        if not w:
            continue
        parent = node.parent.words if node.parent is not None else []
        if w[0] == "name" and len(w) == 2 and parent[:1] == ["system"] and b.device is None:
            b.device = make(Device, ref=b.ref(node), hostname=w[1])
        elif w[0] == "router" and (len(w) == 1 or w[1] == "Base") and "create" not in w:
            _classic_router(b, book, node, None, iface_vrf)
        elif w[0] == "vprn" and len(w) >= 2:
            _classic_vprn(b, book, node, iface_vrf)
        elif w[0] == "port" and len(w) == 2 and parent[:1] != ["router"] and node.children:
            _classic_port(b, node)
        elif w[0] == "prefix-list" and len(w) == 2 and parent[:1] == ["policy-options"]:
            _classic_prefix_list(prefixes, node, w[1])
    book.emit(b)
    add_prefix_lists(b, prefixes)
    apply_interface_vrfs(b, iface_vrf)
    members: dict[str, list[str]] = {}
    for name, vrf in iface_vrf.items():
        members.setdefault(vrf, []).append(name)
    b.vrfs = [v.model_copy(update={"interfaces": tuple(members.get(v.name, ()))}) for v in b.vrfs]
    return b.build()


def _classic_vprn(b: Builder, book: PeerBook, node: ConfigNode, iface_vrf: dict[str, str]) -> None:
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
    _classic_router(b, book, node, name, iface_vrf)


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


def _classic_router(
    b: Builder, book: PeerBook, node: ConfigNode, vrf: str | None, iface_vrf: dict[str, str]
) -> None:
    local_as: int | None = None
    for child in node.children:
        cw = child.words
        if cw[:1] == ["autonomous-system"] and len(cw) == 2:
            local_as = to_asn(cw[1])
    for child in node.children:
        cw = child.words
        if cw[:1] == ["interface"] and len(cw) >= 2:
            _classic_interface(b, child, vrf, iface_vrf)
        elif cw == ["bgp"]:
            _classic_bgp(book, child, vrf, local_as)
        elif cw[:1] == ["static-route-entry"] and len(cw) == 2:
            _classic_static(b, child, vrf)
        elif cw[:1] == ["static-route"] and len(cw) >= 4 and cw[2] == "next-hop":
            make_static_route(b, child, parse_net(cw[1]), parse_route_target(cw[2:]), vrf)


def _classic_interface(
    b: Builder, node: ConfigNode, vrf: str | None, iface_vrf: dict[str, str]
) -> None:
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
        elif cw == ["ipv6"]:
            for sub in child.children:
                sw = sub.words
                if sw[:1] == ["address"] and len(sw) >= 2:
                    addresses.append((sub, parse_iface_addr(sw[1]), False))
    iface = b.interface(node, name, description=description, enabled=enabled, mtu=mtu, vrf=vrf)
    if iface is None:
        return
    if vrf:
        iface_vrf[name] = vrf
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
        elif cw == ["black-hole"]:
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
        make_static_route(b, child, prefix, target, vrf)


def _classic_prefix_list(prefixes: _Prefixes, node: ConfigNode, name: str) -> None:
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
        nodes, entries = prefixes.setdefault((afi, name), ([], []))
        if node not in nodes:
            nodes.append(node)
        entries.append(item)


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


@dataclass
class _MdIface:
    node: ConfigNode
    vrf: str | None
    description: str | None = None
    disabled: bool = False
    mtu: int | None = None
    v4: dict[str, tuple[ConfigNode, int | None]] = field(default_factory=dict)
    v6: dict[str, tuple[ConfigNode, int | None]] = field(default_factory=dict)
    primary: str | None = None


def _anchor(node: ConfigNode, k: int) -> ConfigNode:
    current = node
    while (
        current.parent is not None
        and not current.parent.is_root
        and len(current.parent.flat_words) >= k
    ):
        current = current.parent
    return current


def _values(words: tuple[str, ...]) -> list[str]:
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


def _mdcli(root: ConfigNode, snapshot: Snapshot, vendor: str) -> ParsedConfig:
    b = Builder(snapshot, vendor)
    book = PeerBook()
    prefixes: _Prefixes = {}
    ifaces: dict[tuple[str | None, str], _MdIface] = {}
    peer_nodes: dict[tuple[str | None, str], ConfigNode] = {}
    rds: dict[str, tuple[ConfigNode, str | None]] = {}
    routes: dict[tuple[str | None, str, str], tuple[ConfigNode, RouteTarget]] = {}
    pl_bounds: dict[tuple[str, str], dict[str, int | None]] = {}
    pl_nodes: dict[tuple[str, str, str], ConfigNode] = {}
    local_as: dict[str | None, int | None] = {}

    for node in root.walk():
        fw = node.flat_words
        if len(fw) < 2 or fw[0] != "configure" or _inactive(node):
            continue
        rel = fw[1:]
        if rel[:2] == ("system", "name") and len(rel) == 3 and b.device is None:
            b.device = make(Device, ref=b.ref(node), hostname=rel[2])
            continue
        vrf: str | None = None
        base = 0
        if rel[:2] == ("router", "Base"):
            base = 2
        elif rel[:2] == ("service", "vprn") and len(rel) >= 3:
            vrf = rel[2]
            base = 3
            anchor = _anchor(node, 3 + 1)
            rds.setdefault(vrf, (anchor, None))
            if len(rel) >= 5 and rel[3] == "route-distinguisher":
                rds[vrf] = (anchor, rel[4])
        elif rel[0] == "policy-options" and len(rel) >= 5 and rel[1] == "prefix-list":
            _md_prefix(prefixes, pl_bounds, pl_nodes, node, fw, rel)
            continue
        else:
            continue
        body = rel[base:]
        if not body:
            continue
        if body[0] == "autonomous-system" and len(body) >= 2:
            local_as[vrf] = to_asn(body[1])
        elif body[0] == "interface" and len(body) >= 3:
            _md_iface(ifaces, node, fw, body, vrf)
        elif body[:2] == ("bgp", "neighbor") or body[:2] == ("bgp", "group"):
            _md_bgp(book, peer_nodes, node, fw, body, vrf)
        elif body[:1] == ("static-routes",) and len(body) >= 3 and body[1] == "route":
            _md_route(routes, node, fw, body, vrf)

    for (peer_vrf, name), anchor in peer_nodes.items():
        acc = book.peers[(peer_vrf, name)]
        acc.ref = (anchor.line_start, anchor.line_end)
        grp = book.groups.get((peer_vrf, acc.group or ""))
        if acc.local_as is None and (grp is None or grp.local_as is None):
            acc.local_as = local_as.get(peer_vrf)
    book.emit(b)

    iface_vrf: dict[str, str] = {}
    for (iface_scope, name), i in ifaces.items():
        b.interface(
            i.node,
            name,
            description=i.description,
            enabled=not i.disabled,
            mtu=i.mtu,
            vrf=iface_scope,
        )
        if iface_scope:
            iface_vrf[name] = iface_scope
        for table in (i.v4, i.v6):
            for address, (addr_node, length) in table.items():
                if length is not None:
                    b.address(
                        addr_node, name, parse_iface_addr(address, str(length)), vrf=iface_scope
                    )
    for name, (vrf_node, rd) in rds.items():
        vrf_obj = make(VRF, ref=b.ref(vrf_node), name=name, rd=rd)
        if vrf_obj is not None:
            b.vrfs.append(vrf_obj)
    apply_interface_vrfs(b, iface_vrf)
    b.vrfs = [
        v.model_copy(update={"interfaces": tuple(n for n, s in iface_vrf.items() if s == v.name)})
        for v in b.vrfs
    ]
    for (route_vrf, prefix, _), (route_node, target) in routes.items():
        make_static_route(b, route_node, parse_net(prefix), target, route_vrf)
    for key, bounds in pl_bounds.items():
        _apply_bounds(prefixes, key, bounds)
    add_prefix_lists(b, prefixes)
    return b.build()


def _inactive(node: ConfigNode) -> bool:
    current: ConfigNode | None = node
    while current is not None:
        if current.inactive:
            return True
        current = current.parent
    return False


def _md_iface(
    ifaces: dict[tuple[str | None, str], _MdIface],
    node: ConfigNode,
    fw: tuple[str, ...],
    body: tuple[str, ...],
    vrf: str | None,
) -> None:
    key = (vrf, body[1])
    acc = ifaces.setdefault(key, _MdIface(_anchor(node, len(fw) - len(body) + 2), vrf))
    tail = body[2:]
    if tail[0] == "description" and len(tail) >= 2:
        acc.description = tail[1]
    elif tail[0] == "admin-state" and len(tail) >= 2:
        acc.disabled = tail[1] == "disable"
    elif tail[0] == "ip-mtu" and len(tail) >= 2:
        acc.mtu = to_int(tail[1])
    elif tail[:3] == ("ipv4", "primary", "address") and len(tail) >= 4:
        acc.primary = tail[3]
        acc.v4.setdefault(tail[3], (_anchor(node, len(fw) - len(tail) + 4), None))
    elif tail[:3] == ("ipv4", "primary", "prefix-length") and len(tail) >= 4:
        if acc.primary is not None and acc.primary in acc.v4:
            acc.v4[acc.primary] = (acc.v4[acc.primary][0], to_int(tail[3]))
    elif tail[:2] == ("ipv6", "address") and len(tail) >= 3:
        address = tail[2]
        anchor = _anchor(node, len(fw) - len(tail) + 3)
        length = to_int(tail[4]) if len(tail) >= 5 and tail[3] == "prefix-length" else None
        previous = acc.v6.get(address)
        acc.v6[address] = (anchor, length if length is not None else (previous or (0, None))[1])


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
        peer_nodes.setdefault((vrf, name), _anchor(node, len(fw) - len(attrs)))
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
        acc.imports.extend(v for v in _values(attrs[2:]) if v not in acc.imports)
    elif key == "export" and attrs[1:2] == ("policy",):
        acc.exports.extend(v for v in _values(attrs[2:]) if v not in acc.exports)


def _md_route(
    routes: dict[tuple[str | None, str, str], tuple[ConfigNode, RouteTarget]],
    node: ConfigNode,
    fw: tuple[str, ...],
    body: tuple[str, ...],
    vrf: str | None,
) -> None:
    prefix = body[2]
    tail = body[3:]
    consumed = 3
    if tail[:1] == ("route-type",) and len(tail) >= 2:
        tail = tail[2:]
        consumed += 2
    if not tail:
        return
    if tail[0] == "next-hop" and len(tail) >= 2:
        nh = tail[1]
        entry = routes.setdefault(
            (vrf, prefix, nh), (_anchor(node, len(fw) - len(tail) + 2), RouteTarget())
        )
        target = entry[1]
        address = parse_ip(nh)
        if address is not None:
            target.next_hop = address
        else:
            target.interface = nh
        attr = tail[2:]
    elif tail[0] == "black-hole":
        entry = routes.setdefault(
            (vrf, prefix, "black-hole"), (_anchor(node, len(fw) - len(tail) + 1), RouteTarget())
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
    prefixes: _Prefixes,
    bounds: dict[tuple[str, str], dict[str, int | None]],
    nodes: dict[tuple[str, str, str], ConfigNode],
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
    list_node = _anchor(node, len(fw) - len(rel) + 3 + 1)
    tail = rel[5:]
    kind = tail[tail.index("type") + 1] if "type" in tail[:-1] else None
    lengths = {
        k: to_int(tail[tail.index(k) + 1]) for k in ("start-length", "end-length") if k in tail[:-1]
    }
    key = (afi, name)
    entry_key = (afi, name, rel[4])
    nodes.setdefault(entry_key, list_node)
    held = bounds.setdefault((afi + "|" + name, rel[4]), {})
    if kind:
        held["kind"] = {"exact": 0, "longer": 1, "orlonger": 2, "range": 3}.get(kind, 0)
    held.update(
        {
            "ge": lengths.get("start-length", held.get("ge")),
            "le": lengths.get("end-length", held.get("le")),
        }
    )
    plist_nodes, entries = prefixes.setdefault(key, ([], []))
    if not any(n is list_node for n in plist_nodes):
        plist_nodes.append(list_node)
    if all(e.prefix != prefix for e in entries):
        item = prefix_entry("permit", prefix)
        if item is not None:
            entries.append(item)


def _apply_bounds(prefixes: _Prefixes, key: tuple[str, str], held: dict[str, int | None]) -> None:
    afi_name, prefix_text = key
    afi, _, name = afi_name.partition("|")
    pair = prefixes.get((afi, name))
    prefix = parse_net(prefix_text)
    if pair is None or prefix is None:
        return
    kind = held.get("kind")
    ge, le = held.get("ge"), held.get("le")
    if kind == 1:
        ge, le = prefix.prefixlen + 1, prefix.max_prefixlen
    elif kind == 2:
        ge, le = prefix.prefixlen, prefix.max_prefixlen
    elif kind in (0, None) and ge is None and le is None:
        return
    new = prefix_entry("permit", prefix, ge=ge, le=le)
    if new is None:
        return
    entries = pair[1]
    for i, e in enumerate(entries):
        if e.prefix == prefix:
            entries[i] = new
