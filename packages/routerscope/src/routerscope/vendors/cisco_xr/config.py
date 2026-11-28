"""Config extraction for Cisco IOS XR."""

from __future__ import annotations

from routerscope.model import VRF, Device, ParsedConfig, PrefixListEntry, Snapshot
from routerscope.vendors._extract import (
    Builder,
    PeerAcc,
    PeerBook,
    add_prefix_lists,
    apply_interface_vrfs,
    make,
    make_static_route,
    parse_iface_addr,
    parse_net,
    parse_route_target,
    prefix_entry,
    rest,
    to_asn,
    to_int,
)
from routerscope.vendors._tree import ConfigNode, parse_indented


def parse_xr(text: str, snapshot: Snapshot, vendor: str) -> ParsedConfig:
    """Parse IOS XR configuration text into the neutral model."""
    root = parse_indented(text, "xr")
    b = Builder(snapshot, vendor)
    book = PeerBook()
    prefixes: dict[tuple[str, str], tuple[list[ConfigNode], list[PrefixListEntry]]] = {}
    iface_vrf: dict[str, str] = {}
    rds: dict[str, str] = {}
    bgp_vrf_nodes: dict[str, ConfigNode] = {}
    for node in root.children:
        w = node.words
        if not w:
            continue
        if w[0] == "hostname" and len(w) >= 2 and b.device is None:
            b.device = make(Device, ref=b.ref(node), hostname=w[1])
        elif w[0] == "interface" and len(w) >= 2:
            _interface(b, node, iface_vrf)
        elif w[0] == "vrf" and len(w) == 2:
            _vrf(b, node, w[1])
        elif w[:2] == ["router", "bgp"] and len(w) >= 3:
            _bgp(book, node, rds, bgp_vrf_nodes)
        elif w[:2] == ["router", "static"]:
            _static(b, node)
        elif w[0] == "prefix-set" and len(w) == 2:
            _prefix_set(prefixes, node, w[1])
    book.emit(b)
    add_prefix_lists(b, prefixes)
    apply_interface_vrfs(b, iface_vrf)
    members: dict[str, list[str]] = {}
    for name, vrf in iface_vrf.items():
        members.setdefault(vrf, []).append(name)
    vrfs = []
    for v in b.vrfs:
        update: dict[str, object] = {"interfaces": tuple(members.get(v.name, ()))}
        if v.rd is None and v.name in rds:
            update["rd"] = rds[v.name]
        vrfs.append(v.model_copy(update=update))
    b.vrfs = vrfs
    return b.build()


def _interface(b: Builder, node: ConfigNode, iface_vrf: dict[str, str]) -> None:
    name = rest(node.text, 1)
    if name is None:
        return
    description: str | None = None
    enabled = True
    mtu: int | None = None
    vrf: str | None = None
    addresses = []
    for child in node.children:
        cw = child.words
        if not cw:
            continue
        if cw[0] == "description":
            description = rest(child.text, 1)
        elif cw == ["shutdown"]:
            enabled = False
        elif cw[0] == "mtu" and len(cw) == 2:
            mtu = to_int(cw[1])
        elif cw[0] == "vrf" and len(cw) == 2:
            vrf = cw[1]
        elif cw[:2] == ["ipv4", "address"] and len(cw) >= 3:
            mask = cw[3] if len(cw) > 3 and cw[3] != "secondary" else None
            addresses.append((child, parse_iface_addr(cw[2], mask), "secondary" in cw[3:]))
        elif cw[:2] == ["ipv6", "address"] and len(cw) >= 3 and "link-local" not in cw:
            addresses.append((child, parse_iface_addr(cw[2]), False))
    iface = b.interface(node, name, description=description, enabled=enabled, mtu=mtu, vrf=vrf)
    if iface is None:
        return
    if vrf:
        iface_vrf[name] = vrf
    for child, addr, secondary in addresses:
        b.address(child, name, addr, vrf=vrf, secondary=secondary)


def _vrf(b: Builder, node: ConfigNode, name: str) -> None:
    imports: list[str] = []
    exports: list[str] = []
    description: str | None = None
    for child in node.walk():
        cw = child.words
        if cw[:1] == ["description"]:
            description = rest(child.text, 1)
        elif cw == ["import", "route-target"] or cw == ["export", "route-target"]:
            targets = [t for c in child.children for t in c.words]
            (imports if cw[0] == "import" else exports).extend(targets)
    vrf = make(
        VRF,
        ref=b.ref(node),
        name=name,
        import_targets=tuple(imports),
        export_targets=tuple(exports),
        description=description,
    )
    if vrf is not None:
        b.vrfs.append(vrf)


def _bgp(
    book: PeerBook, node: ConfigNode, rds: dict[str, str], vrf_nodes: dict[str, ConfigNode]
) -> None:
    for child in node.children:
        w = child.words
        if w[:1] == ["neighbor-group"] and len(w) == 2:
            _neighbor(book.group(None, w[1]), child, "group")
        elif w[:1] == ["neighbor"] and len(w) == 2:
            _neighbor(book.peer(None, w[1]), child, "peer")
        elif w[:1] == ["vrf"] and len(w) == 2:
            vrf_nodes[w[1]] = child
            for sub in child.children:
                sw = sub.words
                if sw[:1] == ["rd"] and len(sw) == 2:
                    rds[w[1]] = sw[1]
                elif sw[:1] == ["neighbor"] and len(sw) == 2:
                    _neighbor(book.peer(w[1], sw[1]), sub, "peer")


def _neighbor(acc: PeerAcc, node: ConfigNode, kind: str) -> None:
    acc.ref = (node.line_start, node.line_end)
    for child in node.children:
        cw = child.words
        if cw[:1] == ["remote-as"] and len(cw) >= 2:
            acc.remote_as = to_asn(cw[1])
        elif cw[:1] == ["local-as"] and len(cw) >= 2:
            acc.local_as = to_asn(cw[1])
        elif cw[:1] == ["description"]:
            acc.description = rest(child.text, 1)
        elif cw[:2] == ["use", "neighbor-group"] and len(cw) == 3:
            acc.group = cw[2]
        elif cw[:1] == ["address-family"]:
            acc.add_family(" ".join(cw[1:]))
            for stmt in child.children:
                sw = stmt.words
                if sw[:1] == ["route-policy"] and len(sw) == 3:
                    if sw[2] == "in":
                        acc.imports.append(sw[1])
                    elif sw[2] == "out":
                        acc.exports.append(sw[1])


def _static(b: Builder, node: ConfigNode) -> None:
    for scope in node.children:
        sw = scope.words
        vrf: str | None = None
        if sw[:1] == ["vrf"] and len(sw) == 2:
            vrf = sw[1]
            families = scope.children
        elif sw[:1] == ["address-family"]:
            families = [scope]
        else:
            continue
        for family in families:
            if family.words[:1] != ["address-family"]:
                continue
            for entry in family.children:
                ew = entry.words
                if len(ew) >= 2 and "/" in ew[0]:
                    make_static_route(b, entry, parse_net(ew[0]), parse_route_target(ew[1:]), vrf)


def _prefix_set(
    acc: dict[tuple[str, str], tuple[list[ConfigNode], list[PrefixListEntry]]],
    node: ConfigNode,
    name: str,
) -> None:
    for entry in node.children:
        ew = entry.text.rstrip(",").split()
        if not ew:
            continue
        prefix = parse_net(ew[0])
        if prefix is None:
            continue
        ge = le = None
        for k in range(1, len(ew) - 1):
            if ew[k] == "ge":
                ge = to_int(ew[k + 1])
            elif ew[k] == "le":
                le = to_int(ew[k + 1])
            elif ew[k] == "eq":
                ge = le = to_int(ew[k + 1])
        item = prefix_entry("permit", prefix, ge=ge, le=le)
        if item is None:
            continue
        afi = "ipv6" if prefix.version == 6 else "ipv4"
        nodes, entries = acc.setdefault((afi, name), ([], []))
        if node not in nodes:
            nodes.append(node)
        entries.append(item)
