"""Config extraction for IOS / IOS-XE style syntax (also used by OcNOS)."""

from __future__ import annotations

from routerscope.model import VLAN, VRF, Device, ParsedConfig, PrefixListEntry, Snapshot
from routerscope.vendors._extract import (
    Builder,
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
    safe,
    to_asn,
    to_int,
)
from routerscope.vendors._tree import ConfigNode, parse_indented

_VRF_HEADS = ("ip vrf ", "vrf definition ", "vrf context ")


def parse_ios_like(text: str, snapshot: Snapshot, vendor: str) -> ParsedConfig:
    """Parse IOS-style configuration text into the neutral model."""
    root = parse_indented(text, "ios")
    b = Builder(snapshot, vendor)
    book = PeerBook()
    prefixes: dict[tuple[str, str], tuple[list[ConfigNode], list[PrefixListEntry]]] = {}
    iface_vrf: dict[str, str] = {}
    for node in root.children:
        w = node.words
        if not w:
            continue
        head = w[0]
        if head == "hostname" and len(w) >= 2 and b.device is None:
            b.device = make(Device, ref=b.ref(node), hostname=w[1])
        elif head == "interface" and len(w) >= 2:
            _interface(b, node, iface_vrf)
        elif node.text.startswith(_VRF_HEADS) and len(w) >= 3 and w[2] != "forwarding":
            _vrf(b, node, w[2])
        elif head == "router" and len(w) >= 3 and w[1] == "bgp":
            _bgp(book, node)
        elif head in ("ip", "ipv6") and len(w) >= 3 and w[1] == "route":
            _static(b, node, w)
        elif head in ("ip", "ipv6") and len(w) >= 4 and w[1] == "prefix-list":
            _prefix_list(prefixes, node, w)
        elif head == "vlan" and len(w) == 2:
            _vlan(b, node, w[1])
        elif node.text == "vlan database":
            for child in node.children:
                cw = child.words
                if len(cw) >= 2 and cw[0] == "vlan":
                    name = cw[cw.index("name") + 1] if "name" in cw[:-1] else None
                    vid = to_int(cw[1])
                    if vid is not None:
                        vlan = make(VLAN, ref=b.ref(child), vlan_id=vid, name=name)
                        if vlan is not None:
                            b.vlans.append(vlan)
    book.emit(b)
    add_prefix_lists(b, prefixes)
    _link_vrfs(b, iface_vrf)
    return b.build()


def _link_vrfs(b: Builder, iface_vrf: dict[str, str]) -> None:
    apply_interface_vrfs(b, iface_vrf)
    members: dict[str, list[str]] = {}
    for name, vrf in iface_vrf.items():
        members.setdefault(vrf, []).append(name)
    b.vrfs = [v.model_copy(update={"interfaces": tuple(members.get(v.name, ()))}) for v in b.vrfs]


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
        elif cw == ["no", "shutdown"]:
            enabled = True
        elif cw[0] == "mtu" and len(cw) == 2:
            mtu = to_int(cw[1])
        elif cw[:3] == ["ip", "vrf", "forwarding"] and len(cw) >= 4:
            vrf = cw[3]
        elif cw[:2] in (["vrf", "forwarding"], ["vrf", "member"]) and len(cw) >= 3:
            vrf = cw[2]
        elif cw[:2] == ["ip", "address"] and len(cw) >= 3:
            mask = cw[3] if len(cw) > 3 and cw[3] != "secondary" else None
            addresses.append((child, parse_iface_addr(cw[2], mask), "secondary" in cw[3:]))
        elif (
            cw[:2] == ["ipv6", "address"]
            and len(cw) >= 3
            and not {"eui-64", "link-local"} & set(cw[3:])
        ):
            addresses.append((child, parse_iface_addr(cw[2]), False))
    iface = b.interface(node, name, description=description, enabled=enabled, mtu=mtu, vrf=vrf)
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
        if cw[0] == "rd" and len(cw) == 2:
            rd = cw[1]
        elif cw[0] == "description":
            description = rest(child.text, 1)
        elif cw[0] == "route-target" and len(cw) >= 3:
            targets = cw[2:]
            if cw[1] in ("import", "both"):
                imports.extend(targets)
            if cw[1] in ("export", "both"):
                exports.extend(targets)
    vrf = safe(
        lambda: VRF(
            ref=b.ref(node),
            name=name,
            rd=rd,
            import_targets=tuple(imports),
            export_targets=tuple(exports),
            description=description,
        )
    )
    if vrf is not None:
        b.vrfs.append(vrf)


def _bgp(book: PeerBook, node: ConfigNode) -> None:
    for child in node.children:
        if child.words[:1] == ["address-family"]:
            cw = child.words
            vrf = cw[cw.index("vrf") + 1] if "vrf" in cw[:-1] else None
            kept: list[str] = []
            skip = False
            for word in cw[1:]:
                if skip:
                    skip = False
                elif word == "vrf":
                    skip = True
                else:
                    kept.append(word)
            family = " ".join(kept)
            for stmt in child.children:
                _bgp_stmt(book, stmt, vrf, family or None)
        else:
            _bgp_stmt(book, child, None, None)


def _bgp_stmt(book: PeerBook, node: ConfigNode, vrf: str | None, family: str | None) -> None:
    w = node.words
    if len(w) < 3 or w[0] != "neighbor":
        return
    name, kind = w[1], w[2]
    is_peer = _is_ip(name)
    acc = book.peer(vrf, name) if is_peer else book.group(vrf, name)
    acc.touch(node)
    if kind == "remote-as" and len(w) >= 4:
        acc.set_remote_as(to_asn(w[3]), node)
    elif kind == "peer-group":
        if len(w) >= 4:
            acc.group = w[3]
    elif kind == "description":
        acc.description = rest(node.text, 3)
    elif kind == "local-as" and len(w) >= 4:
        acc.local_as = to_asn(w[3])
    elif kind == "route-map" and len(w) >= 5:
        (acc.imports if w[4] == "in" else acc.exports if w[4] == "out" else []).append(w[3])
    elif kind == "activate":
        acc.add_family(family)


def _is_ip(value: str) -> bool:
    return parse_net(value) is not None and ("." in value or ":" in value)


def _static(b: Builder, node: ConfigNode, w: list[str]) -> None:
    i = 2
    vrf: str | None = None
    if i + 1 < len(w) and w[i] == "vrf":
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


def _prefix_list(
    acc: dict[tuple[str, str], tuple[list[ConfigNode], list[PrefixListEntry]]],
    node: ConfigNode,
    w: list[str],
) -> None:
    afi = "ipv6" if w[0] == "ipv6" else "ipv4"
    name = w[2]
    i = 3
    seq: int | None = None
    if w[i] == "seq" and i + 1 < len(w):
        seq = to_int(w[i + 1])
        i += 2
    if i + 1 >= len(w):
        return
    action = w[i]
    prefix = parse_net(w[i + 1])
    ge = le = None
    rest_words = w[i + 2 :]
    for k in range(len(rest_words) - 1):
        if rest_words[k] == "ge":
            ge = to_int(rest_words[k + 1])
        elif rest_words[k] == "le":
            le = to_int(rest_words[k + 1])
        elif rest_words[k] == "eq":
            ge = le = to_int(rest_words[k + 1])
    entry = prefix_entry(action, prefix, seq=seq, ge=ge, le=le)
    if entry is None:
        return
    nodes, entries = acc.setdefault((afi, name), ([], []))
    nodes.append(node)
    entries.append(entry)


def _vlan(b: Builder, node: ConfigNode, ident: str) -> None:
    vid = to_int(ident)
    if vid is None:
        return
    name: str | None = None
    for child in node.children:
        if child.words[:1] == ["name"]:
            name = rest(child.text, 1)
    vlan = safe(lambda: VLAN(ref=b.ref(node), vlan_id=vid, name=name))
    if vlan is not None:
        b.vlans.append(vlan)
