"""Helpers shared by the vendor config extractors: a result builder and value parsers."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
    ip_address,
    ip_network,
)
from typing import Any

from routerscope.model import (
    VLAN,
    VRF,
    BGPPeer,
    Device,
    Interface,
    IPAddress,
    ParsedConfig,
    PrefixList,
    PrefixListEntry,
    Snapshot,
    SourceRef,
    StaticRoute,
)
from routerscope.vendors._tree import ConfigNode

IPAddr = IPv4Address | IPv6Address
IPNet = IPv4Network | IPv6Network


def safe[T](factory: Callable[[], T]) -> T | None:
    """Build a model object, returning ``None`` if its validation rejects the values."""
    try:
        return factory()
    except (ValueError, TypeError):
        return None


def make[T](cls: type[T], **kwargs: Any) -> T | None:
    """``cls(**kwargs)``, or ``None`` if validation rejects the values."""
    try:
        return cls(**kwargs)
    except (ValueError, TypeError):
        return None


def to_int(value: str | None) -> int | None:
    """``int(value)`` for plain decimal digits, else ``None``."""
    if value is not None and value.isascii() and value.isdigit():
        return int(value)
    return None


def to_asn(value: str | None) -> int | None:
    """Parse ``64496`` or asdot ``1.10`` (= 1 * 65536 + 10); ``None`` if it is neither."""
    if value is None:
        return None
    if "." in value:
        high, _, low = value.partition(".")
        h, lo = to_int(high), to_int(low)
        if h is None or lo is None or h > 65535 or lo > 65535:
            return None
        number: int | None = h * 65536 + lo
    else:
        number = to_int(value)
    if number is None or not 1 <= number <= 4294967295:
        return None
    return number


def parse_ip(value: str | None) -> IPAddr | None:
    if value is None:
        return None
    try:
        return ip_address(value)
    except ValueError:
        return None


def parse_net(value: str, mask: str | None = None) -> IPNet | None:
    """Parse ``a.b.c.d/len``, or ``a.b.c.d`` plus a netmask / prefix length token."""
    text = value if mask is None else f"{value}/{mask}"
    try:
        return ip_network(text, strict=False)
    except ValueError:
        return None


def parse_iface_addr(value: str, mask: str | None = None) -> IPv4Interface | IPv6Interface | None:
    """Parse an interface address given as ``addr/len`` or ``addr`` + mask/length token."""
    text = value if mask is None else f"{value}/{mask}"
    try:
        ip = ip_address(text.partition("/")[0])
        if isinstance(ip, IPv4Address):
            return IPv4Interface(text)
        return IPv6Interface(text)
    except ValueError:
        return None


_ROUTE_SKIP_1 = frozenset({"permanent", "global", "bfd", "inherit-cost", "no-install", "unicast"})
_ROUTE_SKIP_2 = frozenset({"track", "vrf", "vpn-instance", "color", "weight", "metric"})


@dataclass
class RouteTarget:
    """What follows the prefix of a static route statement."""

    next_hop: IPAddr | None = None
    interface: str | None = None
    blackhole: bool = False
    distance: int | None = None
    tag: int | None = None
    description: str | None = None


def parse_route_target(tokens: list[str]) -> RouteTarget:
    """Parse ``[nexthop] [interface] [distance] [tag N] [name|description X]`` loosely."""
    out = RouteTarget()
    k = 0
    n = len(tokens)
    while k < n:
        tok = tokens[k]
        low = tok.lower()
        if low == "tag" and k + 1 < n:
            out.tag = to_int(tokens[k + 1])
            k += 2
        elif low in ("preference", "distance") and k + 1 < n:
            out.distance = to_int(tokens[k + 1])
            k += 2
        elif low in ("name", "description") and k + 1 < n:
            out.description = " ".join(tokens[k + 1 :])
            break
        elif low in _ROUTE_SKIP_2 and k + 1 < n:
            k += 2
        elif low in _ROUTE_SKIP_1:
            k += 1
        else:
            address = parse_ip(tok)
            number = to_int(tok)
            if address is not None:
                out.next_hop = out.next_hop or address
            elif low.startswith("null"):
                out.blackhole = True
            elif number is not None:
                out.distance = out.distance or number
            elif out.interface is None:
                out.interface = tok
            k += 1
    return out


def make_static_route(
    builder: Builder,
    node: ConfigNode,
    prefix: IPNet | None,
    target: RouteTarget,
    vrf: str | None,
) -> None:
    """Add a :class:`StaticRoute` built from parsed pieces (skipped if invalid)."""
    if prefix is None:
        return
    route = safe(
        lambda: StaticRoute(
            ref=builder.ref(node),
            prefix=prefix,
            next_hop=target.next_hop,
            interface=target.interface,
            blackhole=target.blackhole,
            vrf=vrf,
            distance=target.distance,
            tag=target.tag,
            description=target.description,
        )
    )
    if route is not None:
        builder.static_routes.append(route)


def add_prefix_lists(
    builder: Builder,
    groups: dict[tuple[str, str], tuple[list[ConfigNode], list[PrefixListEntry]]],
) -> None:
    """Turn accumulated (afi, name) -> (nodes, entries) into :class:`PrefixList` objects."""
    for (afi, name), (nodes, entries) in groups.items():
        if not entries:
            continue
        plist = make(
            PrefixList, ref=builder.ref_span(nodes), name=name, afi=afi, entries=tuple(entries)
        )
        if plist is not None:
            builder.prefix_lists.append(plist)


def prefix_entry(
    action: str,
    prefix: IPNet | None,
    *,
    seq: int | None = None,
    ge: int | None = None,
    le: int | None = None,
) -> PrefixListEntry | None:
    if prefix is None or action not in ("permit", "deny"):
        return None
    return make(PrefixListEntry, seq=seq, action=action, prefix=prefix, ge=ge, le=le)


def rest(text: str, skip_words: int) -> str | None:
    """The text after the first ``skip_words`` whitespace-separated words, or ``None``."""
    parts = text.split(None, skip_words)
    if len(parts) <= skip_words:
        return None
    return parts[skip_words].strip() or None


@dataclass
class PeerAcc:
    """A BGP neighbor (or peer group) assembled from several statements."""

    remote_as: int | None = None
    local_as: int | None = None
    description: str | None = None
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    families: list[str] = field(default_factory=list)
    group: str | None = None
    ref: tuple[int, int] | None = None

    def touch(self, node: ConfigNode) -> None:
        if self.ref is None:
            self.ref = (node.line_start, node.line_end)

    def set_remote_as(self, asn: int | None, node: ConfigNode) -> None:
        if asn is not None:
            self.remote_as = asn
            self.ref = (node.line_start, node.line_end)

    def add_family(self, family: str | None) -> None:
        if family and family not in self.families:
            self.families.append(family)


class PeerBook:
    """Collects neighbors and peer groups keyed by (vrf, name), then emits :class:`BGPPeer`."""

    def __init__(self) -> None:
        self.peers: dict[tuple[str | None, str], PeerAcc] = {}
        self.groups: dict[tuple[str | None, str], PeerAcc] = {}

    def peer(self, vrf: str | None, name: str) -> PeerAcc:
        return self.peers.setdefault((vrf, name), PeerAcc())

    def group(self, vrf: str | None, name: str) -> PeerAcc:
        return self.groups.setdefault((vrf, name), PeerAcc())

    def emit(self, builder: Builder) -> None:
        for (vrf, name), acc in self.peers.items():
            address = parse_ip(name)
            if address is None or acc.ref is None:
                continue
            grp = None
            if acc.group is not None:
                grp = self.groups.get((vrf, acc.group)) or self.groups.get((None, acc.group))
            remote_as = acc.remote_as or (grp.remote_as if grp else None)
            if remote_as is None:
                continue
            local_as = acc.local_as or (grp.local_as if grp else None)
            imports = acc.imports or (grp.imports if grp else [])
            exports = acc.exports or (grp.exports if grp else [])
            families = acc.families or (grp.families if grp else [])
            ref = builder.ref_lines(*acc.ref)
            peer = make(
                BGPPeer,
                ref=ref,
                peer=address,
                remote_as=remote_as,
                local_as=local_as,
                vrf=vrf,
                address_families=tuple(families),
                description=acc.description,
                import_policies=tuple(imports),
                export_policies=tuple(exports),
            )
            if peer is not None:
                builder.bgp_peers.append(peer)


class Builder:
    """Accumulates parsed objects for one snapshot and builds the :class:`ParsedConfig`."""

    def __init__(self, snapshot: Snapshot, vendor: str) -> None:
        self.snapshot_id = snapshot.id
        self.vendor = vendor
        self.device: Device | None = None
        self.interfaces: list[Interface] = []
        self.ip_addresses: list[IPAddress] = []
        self.vrfs: list[VRF] = []
        self.bgp_peers: list[BGPPeer] = []
        self.prefix_lists: list[PrefixList] = []
        self.static_routes: list[StaticRoute] = []
        self.vlans: list[VLAN] = []

    def ref_lines(self, start: int, end: int | None = None) -> SourceRef:
        return SourceRef(
            snapshot_id=self.snapshot_id, line_start=start, line_end=end if end else start
        )

    def ref(self, node: ConfigNode) -> SourceRef:
        return self.ref_lines(node.line_start, node.line_end)

    def ref_span(self, nodes: Iterable[ConfigNode]) -> SourceRef:
        items = list(nodes)
        return self.ref_lines(min(n.line_start for n in items), max(n.line_end for n in items))

    def interface(self, node: ConfigNode, name: str, **fields: Any) -> Interface | None:
        """Create an :class:`Interface` from ``node`` and add it; returns it (or ``None``)."""
        iface = safe(lambda: Interface(ref=self.ref(node), name=name, vendor=self.vendor, **fields))
        if iface is not None:
            self.interfaces.append(iface)
        return iface

    def address(
        self,
        node: ConfigNode,
        interface: str,
        address: IPv4Interface | IPv6Interface | None,
        *,
        vrf: str | None = None,
        secondary: bool = False,
    ) -> None:
        if address is None:
            return
        obj = safe(
            lambda: IPAddress(
                ref=self.ref(node),
                interface=interface,
                address=address,
                vrf=vrf,
                secondary=secondary,
            )
        )
        if obj is not None:
            self.ip_addresses.append(obj)

    def build(self) -> ParsedConfig:
        return ParsedConfig(
            snapshot_id=self.snapshot_id,
            vendor=self.vendor,
            device=self.device,
            interfaces=tuple(self.interfaces),
            ip_addresses=tuple(self.ip_addresses),
            vrfs=tuple(self.vrfs),
            bgp_peers=tuple(self.bgp_peers),
            prefix_lists=tuple(self.prefix_lists),
            static_routes=tuple(self.static_routes),
            vlans=tuple(self.vlans),
        )


def apply_interface_vrfs(builder: Builder, mapping: dict[str, str]) -> None:
    """Fill ``vrf`` on interfaces and addresses that lack it, from an interface -> VRF map."""
    if not mapping:
        return
    builder.interfaces = [
        i.model_copy(update={"vrf": mapping[i.name]}) if i.vrf is None and i.name in mapping else i
        for i in builder.interfaces
    ]
    builder.ip_addresses = [
        a.model_copy(update={"vrf": mapping[a.interface]})
        if a.vrf is None and a.interface in mapping
        else a
        for a in builder.ip_addresses
    ]
