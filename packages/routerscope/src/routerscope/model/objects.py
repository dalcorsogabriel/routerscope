"""Vendor-neutral parsed objects.

Every object carries a ``ref`` (:class:`SourceRef`) pointing at the exact snapshot lines it was
parsed from, and a ``kind`` literal so objects can live in a discriminated union.
Collections are tuples so models stay immutable and hashable-friendly.
Use documentation addresses only in examples (RFC 5737 / RFC 3849).
"""

from __future__ import annotations

from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)
from typing import Any, Literal, Self

from netaddr_search import normalize_interface, normalize_mac
from netcmd_safety import VENDORS
from pydantic import Field, field_validator, model_validator

from routerscope.model._base import Asn, Frozen, VendorId
from routerscope.model.provenance import SourceRef

IPAddr = IPv4Address | IPv6Address
IPNet = IPv4Network | IPv6Network
Afi = Literal["ipv4", "ipv6"]


class ParsedObject(Frozen):
    """Base of all parsed objects: a back-reference to the source lines."""

    kind: str
    ref: SourceRef


def _with_normalized_name(data: Any) -> Any:
    """Fill ``name_normalized`` from ``name`` (and ``vendor`` when known) if not supplied."""
    if isinstance(data, dict) and data.get("name_normalized") in (None, ""):
        name = data.get("name")
        if isinstance(name, str):
            vendor = data.get("vendor")
            # Third-party vendor ids have no naming family in netaddr-search: use the default.
            family = vendor if vendor in VENDORS else None
            data = {**data, "name_normalized": normalize_interface(name, family)}
    return data


def _with_normalized_port(data: Any) -> Any:
    """Fill ``interface_normalized`` from ``interface`` (and ``vendor``) if not supplied."""
    if isinstance(data, dict) and data.get("interface_normalized") in (None, ""):
        name = data.get("interface")
        if isinstance(name, str) and name:
            vendor = data.get("vendor")
            family = vendor if vendor in VENDORS else None
            data = {**data, "interface_normalized": normalize_interface(name, family)}
    return data


def _canonical_mac(value: str) -> str:
    mac = normalize_mac(value)
    if mac is None:
        raise ValueError(f"not a MAC address: {value!r}")
    return mac


class Device(ParsedObject):
    """The device itself, as far as the snapshot says."""

    kind: Literal["device"] = "device"
    hostname: str | None = None
    model: str | None = None
    serial: str | None = None
    description: str | None = None


class Version(ParsedObject):
    """Software/hardware version information."""

    kind: Literal["version"] = "version"
    software: str | None = Field(default=None, description="OS family, e.g. 'IOS-XE'.")
    version: str = Field(min_length=1)
    platform: str | None = None
    uptime: str | None = Field(default=None, description="As printed; not parsed.")


class Interface(ParsedObject):
    """An interface. ``name`` is as typed; ``name_normalized`` is the canonical long form."""

    kind: Literal["interface"] = "interface"
    name: str = Field(min_length=1)
    name_normalized: str = ""
    vendor: VendorId | None = Field(default=None, description="Selects the naming family.")
    description: str | None = None
    enabled: bool | None = None
    mtu: int | None = Field(default=None, ge=1)
    vrf: str | None = None
    lag: str | None = Field(default=None, description="Parent LAG name as typed.")

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: Any) -> Any:
        return _with_normalized_name(data)


class IPAddress(ParsedObject):
    """An address assigned to an interface."""

    kind: Literal["ip_address"] = "ip_address"
    interface: str = Field(min_length=1, description="Interface name as typed.")
    address: IPv4Interface | IPv6Interface
    vrf: str | None = None
    secondary: bool = False


class VRF(ParsedObject):
    """A VRF / routing instance."""

    kind: Literal["vrf"] = "vrf"
    name: str = Field(min_length=1)
    rd: str | None = None
    import_targets: tuple[str, ...] = ()
    export_targets: tuple[str, ...] = ()
    interfaces: tuple[str, ...] = ()
    description: str | None = None


class BGPPeer(ParsedObject):
    """A BGP neighbor."""

    kind: Literal["bgp_peer"] = "bgp_peer"
    peer: IPv4Address | IPv6Address
    remote_as: Asn
    local_as: Asn | None = None
    vrf: str | None = None
    address_families: tuple[str, ...] = ()
    state: str | None = None
    description: str | None = None
    import_policies: tuple[str, ...] = Field(default=(), description="Policy names, in order.")
    export_policies: tuple[str, ...] = Field(default=(), description="Policy names, in order.")


class PolicyClause(Frozen):
    """One match condition or action inside a policy term, e.g. ``("prefix-list", "CUSTOMERS")``."""

    type: str = Field(min_length=1)
    value: str = ""


class PolicyTerm(Frozen):
    """One ordered term/sequence of a policy."""

    seq: int | None = None
    name: str | None = None
    disposition: str | None = Field(default=None, description="permit/deny/accept/reject/next.")
    matches: tuple[PolicyClause, ...] = ()
    actions: tuple[PolicyClause, ...] = ()
    raw_lines: tuple[str, ...] = ()
    ref: SourceRef | None = None


class Policy(ParsedObject):
    """A routing policy (route-map, route-policy, policy-statement, ...), terms in order."""

    kind: Literal["policy"] = "policy"
    name: str = Field(min_length=1)
    policy_type: str | None = Field(default=None, description="Vendor flavour, e.g. 'route-map'.")
    terms: tuple[PolicyTerm, ...] = ()


class PrefixListEntry(Frozen):
    """One prefix-list line."""

    seq: int | None = Field(default=None, ge=0)
    action: Literal["permit", "deny"]
    prefix: IPv4Network | IPv6Network
    ge: int | None = Field(default=None, ge=0, le=128)
    le: int | None = Field(default=None, ge=0, le=128)

    @model_validator(mode="after")
    def _bounds(self) -> Self:
        top = self.prefix.max_prefixlen
        low = self.prefix.prefixlen
        if self.ge is not None and not low <= self.ge <= top:
            raise ValueError(f"ge must be between {low} and {top}")
        if self.le is not None and not low <= self.le <= top:
            raise ValueError(f"le must be between {low} and {top}")
        if self.ge is not None and self.le is not None and self.ge > self.le:
            raise ValueError("ge must be <= le")
        return self


class PrefixList(ParsedObject):
    """A named prefix list."""

    kind: Literal["prefix_list"] = "prefix_list"
    name: str = Field(min_length=1)
    afi: Afi
    entries: tuple[PrefixListEntry, ...] = ()


class ACLEntry(Frozen):
    """A generic ACL/filter line; unparsed vendor detail stays in ``raw``."""

    seq: int | None = Field(default=None, ge=0)
    action: str = Field(min_length=1, description="permit/deny/accept/discard/...")
    protocol: str | None = None
    source: str | None = None
    destination: str | None = None
    raw: str = ""


class ACL(ParsedObject):
    """An access list / firewall filter."""

    kind: Literal["acl"] = "acl"
    name: str = Field(min_length=1)
    afi: Afi | None = None
    acl_type: str | None = Field(default=None, description="e.g. 'standard', 'extended'.")
    entries: tuple[ACLEntry, ...] = ()


class StaticRoute(ParsedObject):
    """A static route. At least a next hop, an interface or ``blackhole`` is required."""

    kind: Literal["static_route"] = "static_route"
    prefix: IPv4Network | IPv6Network
    next_hop: IPv4Address | IPv6Address | None = None
    interface: str | None = None
    blackhole: bool = False
    vrf: str | None = None
    distance: int | None = Field(default=None, ge=1, le=255)
    metric: int | None = Field(default=None, ge=0)
    tag: int | None = Field(default=None, ge=0)
    description: str | None = None

    @model_validator(mode="after")
    def _has_target(self) -> Self:
        if self.next_hop is None and self.interface is None and not self.blackhole:
            raise ValueError("a static route needs next_hop, interface or blackhole")
        return self


class IGPInterface(Frozen):
    """An interface taking part in an IGP."""

    name: str = Field(min_length=1)
    area: str | None = None
    passive: bool = False
    metric: int | None = Field(default=None, ge=0)


class IGP(ParsedObject):
    """An OSPF/OSPFv3/IS-IS process or instance."""

    kind: Literal["igp"] = "igp"
    protocol: Literal["ospf", "ospfv3", "isis"]
    process: str | None = Field(default=None, description="Process id or instance name.")
    router_id: str | None = Field(default=None, description="Router id or IS-IS NET.")
    vrf: str | None = None
    areas: tuple[str, ...] = Field(default=(), description="OSPF areas as typed.")
    levels: tuple[str, ...] = Field(default=(), description="IS-IS levels, e.g. 'level-2'.")
    interfaces: tuple[IGPInterface, ...] = ()


class LAG(ParsedObject):
    """A link aggregation group."""

    kind: Literal["lag"] = "lag"
    name: str = Field(min_length=1)
    name_normalized: str = ""
    vendor: VendorId | None = None
    mode: str | None = Field(default=None, description="lacp/static/...")
    members: tuple[str, ...] = ()
    minimum_links: int | None = Field(default=None, ge=0)
    description: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: Any) -> Any:
        return _with_normalized_name(data)


class VLAN(ParsedObject):
    """A VLAN."""

    kind: Literal["vlan"] = "vlan"
    vlan_id: int = Field(ge=1, le=4094)
    name: str | None = None
    interfaces: tuple[str, ...] = ()


class Transceiver(ParsedObject):
    """An optical/electrical transceiver module and its readings."""

    kind: Literal["transceiver"] = "transceiver"
    interface: str = Field(min_length=1)
    module_type: str | None = None
    vendor_name: str | None = None
    part_number: str | None = None
    serial: str | None = None
    wavelength_nm: float | None = Field(default=None, gt=0, allow_inf_nan=False)
    rx_power_dbm: float | None = Field(default=None, allow_inf_nan=False)
    tx_power_dbm: float | None = Field(default=None, allow_inf_nan=False)
    temperature_c: float | None = Field(default=None, allow_inf_nan=False)


class ARPEntry(ParsedObject):
    """An ARP / IPv6 neighbor cache entry. Age and timers are deliberately not modelled."""

    kind: Literal["arp_entry"] = "arp_entry"
    ip: IPv4Address | IPv6Address
    mac: str = Field(description="Canonical lowercase aa:bb:cc:dd:ee:ff.")
    interface: str | None = Field(default=None, description="Interface name as typed.")
    interface_normalized: str = ""
    vendor: VendorId | None = Field(default=None, description="Selects the naming family.")
    vrf: str | None = None

    @field_validator("mac")
    @classmethod
    def _mac(cls, value: str) -> str:
        return _canonical_mac(value)

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: Any) -> Any:
        return _with_normalized_port(data)


class MACEntry(ParsedObject):
    """A MAC address table (FDB) entry. Age is deliberately not modelled."""

    kind: Literal["mac_entry"] = "mac_entry"
    mac: str = Field(description="Canonical lowercase aa:bb:cc:dd:ee:ff.")
    vlan: int | None = Field(default=None, ge=0, le=4094)
    interface: str | None = Field(default=None, description="Port / source as typed.")
    interface_normalized: str = ""
    vendor: VendorId | None = Field(default=None, description="Selects the naming family.")
    entry_type: Literal["static", "dynamic"] | None = None
    domain: str | None = Field(
        default=None, description="Bridge domain, VPLS service, bridge or VLAN name as printed."
    )

    @field_validator("mac")
    @classmethod
    def _mac(cls, value: str) -> str:
        return _canonical_mac(value)

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: Any) -> Any:
        return _with_normalized_port(data)


ParsedObjectUnion = (
    Device
    | Version
    | Interface
    | IPAddress
    | VRF
    | BGPPeer
    | Policy
    | PrefixList
    | ACL
    | StaticRoute
    | IGP
    | LAG
    | VLAN
    | Transceiver
    | ARPEntry
    | MACEntry
)
