"""Config extraction for Huawei VRP."""

from __future__ import annotations

from routerscope.model import VLAN, VRF, Device, ParsedConfig, Snapshot
from routerscope.vendors._extract import (
    Builder,
    PeerBook,
    PrefixTable,
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
from routerscope.vendors._tree import ConfigNode, parse_indented


def parse_vrp(text: str, snapshot: Snapshot, vendor: str) -> ParsedConfig:
    """Parse Huawei VRP ``display current-configuration`` text into the neutral model."""
    root = parse_indented(text, "vrp")
    b = Builder(snapshot, vendor)
    book = PeerBook()
    prefixes = PrefixTable()
    iface_vrf: dict[str, str] = {}
    ifaces: dict[str, list[ConfigNode]] = {}
    for node in root.children:
        w = node.words
        if not w:
            continue
        if w[0] == "sysname" and len(w) >= 2 and b.device is None:
            b.device = make(Device, ref=b.ref(node), hostname=w[1])
        elif w[0] == "interface" and len(w) >= 2:
            ifaces.setdefault(_iface_name(w), []).append(node)
        elif w[:2] == ["ip", "vpn-instance"] and len(w) == 3:
            _vrf(b, node, w[2])
        elif w[0] == "bgp" and len(w) >= 2 and to_asn(w[1]) is not None:
            book.default_local_as = to_asn(w[1])
            _bgp(book, node)
        elif w[0] in ("ip", "ipv6") and len(w) >= 4 and w[1] == "route-static":
            _static(b, node, w)
        elif w[0] == "ip" and len(w) >= 6 and w[1] in ("ip-prefix", "ipv6-prefix"):
            _prefix(prefixes, node, w)
        elif w[:2] == ["vlan", "batch"]:
            _vlan_batch(b, node, w[2:])
        elif w[0] == "vlan" and len(w) == 2:
            _vlan(b, node, w[1])
    for iface_name, iface_nodes in ifaces.items():
        _interface(b, iface_nodes, iface_name, iface_vrf)
    book.emit(b)
    add_prefix_lists(b, prefixes)
    apply_interface_vrfs(b, iface_vrf)
    members: dict[str, list[str]] = {}
    for name, vrf in iface_vrf.items():
        members.setdefault(vrf, []).append(name)
    b.vrfs = [v.model_copy(update={"interfaces": tuple(members.get(v.name, ()))}) for v in b.vrfs]
    return b.build()


def _iface_name(words: list[str]) -> str:
    """Interface name: the first word after ``interface`` (mode words may follow)."""
    if words[1] == "preconfigure" and len(words) > 2:
        return words[2]
    return words[1]


def _interface(b: Builder, nodes: list[ConfigNode], name: str, iface_vrf: dict[str, str]) -> None:
    description: str | None = None
    enabled = True
    mtu: int | None = None
    vrf: str | None = None
    addresses = []
    for child in (c for node in nodes for c in node.children):
        cw = child.words
        if not cw:
            continue
        if cw[0] == "description":
            description = rest(child.text, 1)
        elif cw == ["shutdown"]:
            enabled = False
        elif cw == ["undo", "shutdown"]:
            enabled = True
        elif cw[0] == "mtu" and len(cw) == 2:
            mtu = to_int(cw[1])
        elif cw[:3] == ["ip", "binding", "vpn-instance"] and len(cw) == 4:
            vrf = cw[3]
        elif cw[:2] == ["ip", "address"] and len(cw) >= 3:
            mask = cw[3] if len(cw) > 3 and cw[3] != "sub" else None
            addresses.append((child, parse_iface_addr(cw[2], mask), "sub" in cw[3:]))
        elif (
            cw[:2] == ["ipv6", "address"]
            and len(cw) >= 3
            and not {"eui-64", "link-local"} & set(cw[3:])
        ):
            mask = cw[3] if len(cw) > 3 and to_int(cw[3]) is not None else None
            addresses.append((child, parse_iface_addr(cw[2], mask), False))
    iface = b.interface(nodes, name, description=description, enabled=enabled, mtu=mtu, vrf=vrf)
    if iface is None:
        return
    if vrf:
        iface_vrf[name] = vrf
    for child, addr, secondary in addresses:
        b.address(child, name, addr, vrf=vrf, secondary=secondary)


def _vrf(b: Builder, node: ConfigNode, name: str) -> None:
    rd: str | None = None
    imports: list[str] = []
    exports: list[str] = []
    description: str | None = None
    for child in node.walk():
        cw = child.words
        if not cw:
            continue
        if cw[0] == "route-distinguisher" and len(cw) == 2:
            rd = cw[1]
        elif cw[0] == "description":
            description = rest(child.text, 1)
        elif cw[0] == "vpn-target" and len(cw) >= 2:
            direction = cw[-1]
            targets = cw[1:-1] if direction.endswith("-extcommunity") else cw[1:]
            if direction != "export-extcommunity":
                imports.extend(targets)
            if direction != "import-extcommunity":
                exports.extend(targets)
    vrf = make(
        VRF,
        ref=b.ref(node),
        name=name,
        rd=rd,
        import_targets=tuple(imports),
        export_targets=tuple(exports),
        description=description,
    )
    if vrf is not None:
        b.vrfs.append(vrf)


def _bgp(book: PeerBook, node: ConfigNode) -> None:
    for child in node.children:
        cw = child.words
        if cw[:1] in (["ipv4-family"], ["ipv6-family"]):
            vrf = cw[cw.index("vpn-instance") + 1] if "vpn-instance" in cw[:-1] else None
            afi = "ipv4" if cw[0] == "ipv4-family" else "ipv6"
            kind = next(
                (x for x in cw[1:] if x in ("unicast", "multicast", "vpnv4", "vpnv6")), None
            )
            family = f"{afi} {kind}" if kind else afi
            for stmt in child.children:
                _peer_stmt(book, stmt, vrf, family)
        else:
            _peer_stmt(book, child, None, None)


def _peer_stmt(book: PeerBook, node: ConfigNode, vrf: str | None, family: str | None) -> None:
    w = node.words
    if w[:1] == ["group"] and len(w) >= 2:
        book.group(vrf, w[1]).touch(node)
        return
    if len(w) < 3 or w[0] != "peer":
        return
    name, kind = w[1], w[2]
    acc = book.peer(vrf, name) if parse_ip(name) else book.group(vrf, name)
    acc.touch(node)
    if kind == "as-number" and len(w) >= 4:
        acc.set_remote_as(to_asn(w[3]), node)
    elif kind == "group" and len(w) >= 4:
        acc.group = w[3]
    elif kind == "description":
        acc.description = rest(node.text, 3)
    elif kind == "local-as" and len(w) >= 4:
        acc.local_as = to_asn(w[3])
    elif kind == "route-policy" and len(w) >= 5:
        if w[4] == "import":
            acc.imports.append(w[3])
        elif w[4] == "export":
            acc.exports.append(w[3])
    elif kind == "enable":
        acc.add_family(family)


def _static(b: Builder, node: ConfigNode, w: list[str]) -> None:
    i = 2
    vrf: str | None = None
    if w[i] == "vpn-instance" and i + 1 < len(w):
        vrf = w[i + 1]
        i += 2
    if i >= len(w):
        return
    if "/" in w[i]:
        prefix = parse_net(w[i])
        i += 1
    elif i + 1 < len(w):
        prefix = parse_net(w[i], w[i + 1])
        i += 2
    else:
        return
    make_static_route(b, node, prefix, parse_route_target(w[i:]), vrf)


def _prefix(
    acc: PrefixTable,
    node: ConfigNode,
    w: list[str],
) -> None:
    afi = "ipv6" if w[1] == "ipv6-prefix" else "ipv4"
    name = w[2]
    i = 3
    seq: int | None = None
    if w[i] == "index" and i + 1 < len(w):
        seq = to_int(w[i + 1])
        i += 2
    if i + 2 >= len(w):
        return
    action = w[i]
    prefix = parse_net(w[i + 1], w[i + 2])
    ge = le = None
    tail = w[i + 3 :]
    for k in range(len(tail) - 1):
        if tail[k] == "greater-equal":
            ge = to_int(tail[k + 1])
        elif tail[k] == "less-equal":
            le = to_int(tail[k + 1])
    entry = prefix_entry(action, prefix, seq=seq, ge=ge, le=le)
    if entry is None:
        return
    acc.acc(afi, name).add(node, entry)


def _vlan(b: Builder, node: ConfigNode, ident: str) -> None:
    vid = to_int(ident)
    if vid is None:
        return
    name: str | None = None
    for child in node.children:
        if child.words[:1] in (["name"], ["description"]):
            name = rest(child.text, 1)
    vlan = make(VLAN, ref=b.ref(node), vlan_id=vid, name=name)
    if vlan is not None:
        b.vlans = [v for v in b.vlans if v.vlan_id != vid]
        b.vlans.append(vlan)


def _vlan_batch(b: Builder, node: ConfigNode, tokens: list[str]) -> None:
    ids: list[int] = []
    k = 0
    while k < len(tokens):
        start = to_int(tokens[k])
        if start is None:
            k += 1
            continue
        if k + 2 < len(tokens) and tokens[k + 1] == "to":
            end = to_int(tokens[k + 2])
            if end is not None and start <= end <= 4094:
                ids.extend(range(start, end + 1))
                k += 3
                continue
        ids.append(start)
        k += 1
    known = {v.vlan_id for v in b.vlans}
    for vid in ids:
        if vid not in known:
            vlan = make(VLAN, ref=b.ref(node), vlan_id=vid)
            if vlan is not None:
                b.vlans.append(vlan)
