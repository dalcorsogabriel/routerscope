from __future__ import annotations

from ipaddress import IPv4Interface, IPv6Interface, ip_address, ip_network

import pytest
from pydantic import BaseModel, ValidationError
from routerscope.model import (
    ACL,
    IGP,
    LAG,
    VLAN,
    VRF,
    ACLEntry,
    BGPPeer,
    Device,
    IGPInterface,
    Interface,
    IPAddress,
    ParsedConfig,
    ParseResult,
    Policy,
    PolicyClause,
    PolicyTerm,
    PrefixList,
    PrefixListEntry,
    SourceRef,
    StaticRoute,
    Transceiver,
    Version,
)


def roundtrip(model: BaseModel) -> None:
    assert type(model).model_validate_json(model.model_dump_json()) == model


def test_interface_normalization(ref: SourceRef) -> None:
    gi = Interface(ref=ref, name="Gi0/0/1")
    assert gi.name == "Gi0/0/1"
    assert gi.name_normalized == "GigabitEthernet0/0/1"
    huawei = Interface(ref=ref, name="GE0/0/1", vendor="huawei_vrp")
    assert huawei.name_normalized == "GigabitEthernet0/0/1"
    assert Interface(ref=ref, name="weird0").name_normalized == "weird0"
    explicit = Interface(ref=ref, name="Gi0/1", name_normalized="X")
    assert explicit.name_normalized == "X"
    roundtrip(gi)


def test_interface_bad_vendor(ref: SourceRef) -> None:
    with pytest.raises(ValidationError):
        Interface(ref=ref, name="Gi0/1", vendor="acme")  # type: ignore[arg-type]


def test_interface_normalization_error(ref: SourceRef) -> None:
    with pytest.raises(ValidationError):
        Interface.model_validate({"ref": ref, "name": "Gi0/1", "vendor": "nope"})


def test_ref_required_and_extra_forbidden(ref: SourceRef) -> None:
    with pytest.raises(ValidationError):
        Device.model_validate({"hostname": "r1"})
    with pytest.raises(ValidationError):
        Device.model_validate({"ref": ref, "hostname": "r1", "color": "red"})


def test_simple_objects_roundtrip(ref: SourceRef) -> None:
    for model in (
        Device(ref=ref, hostname="r1", model="X", serial="S1"),
        Version(ref=ref, version="1.2.3", software="OS"),
        VRF(ref=ref, name="CUST", rd="64496:1", import_targets=("64496:1",)),
        VLAN(ref=ref, vlan_id=100, name="v100", interfaces=("Gi0/1",)),
        LAG(ref=ref, name="Po1", members=("Gi0/1", "Gi0/2"), mode="lacp", vendor="cisco_ios"),
        Transceiver(ref=ref, interface="Gi0/1", rx_power_dbm=-3.5, wavelength_nm=1310),
        IPAddress(ref=ref, interface="Gi0/1", address=IPv4Interface("192.0.2.1/24")),
        IPAddress(ref=ref, interface="Gi0/1", address=IPv6Interface("2001:db8::1/64")),
    ):
        roundtrip(model)
    assert LAG(ref=ref, name="Po1", vendor="cisco_ios").name_normalized == "Port-channel1"


def test_ip_address_types(ref: SourceRef) -> None:
    v6 = IPAddress.model_validate({"ref": ref, "interface": "x", "address": "2001:db8::1/64"})
    assert isinstance(v6.address, IPv6Interface)
    with pytest.raises(ValidationError):
        IPAddress.model_validate({"ref": ref, "interface": "x", "address": "not-an-ip"})


@pytest.mark.parametrize("asn", [0, 4294967296, -1])
def test_bgp_asn_bounds(ref: SourceRef, asn: int) -> None:
    with pytest.raises(ValidationError):
        BGPPeer(ref=ref, peer=ip_address("192.0.2.1"), remote_as=asn)


def test_bgp_peer(ref: SourceRef) -> None:
    peer = BGPPeer(
        ref=ref,
        peer=ip_address("2001:db8::1"),
        remote_as=4294967295,
        local_as=64496,
        address_families=("ipv6 unicast",),
        import_policies=("IN",),
        export_policies=("OUT",),
    )
    roundtrip(peer)
    with pytest.raises(ValidationError):
        BGPPeer(ref=ref, peer=ip_address("192.0.2.1"), remote_as=64496, local_as=0)


def test_policy_and_prefix_list(ref: SourceRef) -> None:
    term = PolicyTerm(
        seq=10,
        disposition="permit",
        matches=(PolicyClause(type="prefix-list", value="PL"),),
        actions=(PolicyClause(type="local-preference", value="200"),),
        raw_lines=(" match ip address prefix-list PL",),
        ref=ref,
    )
    roundtrip(Policy(ref=ref, name="RM", policy_type="route-map", terms=(term,)))
    entry = PrefixListEntry(
        seq=5, action="permit", prefix=ip_network("198.51.100.0/24"), ge=25, le=28
    )
    roundtrip(PrefixList(ref=ref, name="PL", afi="ipv4", entries=(entry,)))


@pytest.mark.parametrize(("ge", "le"), [(23, None), (None, 33), (30, 26), (None, 23)], ids=str)
def test_prefix_entry_bounds(ge: int | None, le: int | None) -> None:
    with pytest.raises(ValidationError):
        PrefixListEntry(action="permit", prefix=ip_network("198.51.100.0/24"), ge=ge, le=le)


def test_acl(ref: SourceRef) -> None:
    roundtrip(
        ACL(
            ref=ref,
            name="EDGE",
            afi="ipv4",
            entries=(ACLEntry(seq=10, action="deny", protocol="tcp", source="any", raw="x"),),
        )
    )


def test_static_route(ref: SourceRef) -> None:
    net = ip_network("203.0.113.0/24")
    roundtrip(StaticRoute(ref=ref, prefix=net, next_hop=ip_address("192.0.2.1"), distance=5))
    roundtrip(StaticRoute(ref=ref, prefix=net, blackhole=True))
    roundtrip(StaticRoute(ref=ref, prefix=net, interface="Null0"))
    with pytest.raises(ValidationError, match="needs next_hop"):
        StaticRoute(ref=ref, prefix=net)
    with pytest.raises(ValidationError):
        StaticRoute(ref=ref, prefix=net, blackhole=True, distance=256)


def test_igp(ref: SourceRef) -> None:
    roundtrip(
        IGP(
            ref=ref,
            protocol="ospf",
            process="1",
            areas=("0",),
            interfaces=(IGPInterface(name="Gi0/1", area="0", passive=True, metric=10),),
        )
    )
    roundtrip(IGP(ref=ref, protocol="isis", levels=("level-2",)))
    with pytest.raises(ValidationError):
        IGP(ref=ref, protocol="rip")  # type: ignore[arg-type]


def test_vlan_bounds(ref: SourceRef) -> None:
    for bad in (0, 4095):
        with pytest.raises(ValidationError):
            VLAN(ref=ref, vlan_id=bad)


def test_transceiver_rejects_nan(ref: SourceRef) -> None:
    with pytest.raises(ValidationError):
        Transceiver(ref=ref, interface="x", rx_power_dbm=float("nan"))


def test_parsed_config(snapshot: object, ref: SourceRef) -> None:
    sid = ref.snapshot_id
    cfg = ParsedConfig(
        snapshot_id=sid,
        vendor="cisco_ios",
        device=Device(ref=ref, hostname="r1"),
        version=Version(ref=ref, version="1"),
        interfaces=(Interface(ref=ref, name="Gi0/0"),),
        vlans=(VLAN(ref=ref, vlan_id=10),),
    )
    roundtrip(cfg)
    assert [o.kind for o in cfg.iter_objects()] == ["device", "version", "interface", "vlan"]


def test_parsed_config_ref_mismatch(ref: SourceRef) -> None:
    other = "0" * 64
    with pytest.raises(ValidationError, match="ref points at snapshot"):
        ParsedConfig(snapshot_id=other, interfaces=(Interface(ref=ref, name="Gi0/0"),))
    with pytest.raises(ValidationError):
        ParsedConfig(snapshot_id=ref.snapshot_id, vendor="Bad Id")


def test_parse_result_discriminated_union(ref: SourceRef) -> None:
    result = ParseResult(
        snapshot_id=ref.snapshot_id,
        command="show version",
        vendor="acme_os",
        objects=(Version(ref=ref, version="1"), Interface(ref=ref, name="Gi0/0")),
    )
    again = ParseResult.model_validate_json(result.model_dump_json())
    assert again == result
    assert isinstance(again.objects[1], Interface)
    with pytest.raises(ValidationError):
        ParseResult(snapshot_id="0" * 64, command="x", objects=(Version(ref=ref, version="1"),))
    with pytest.raises(ValidationError):
        ParseResult.model_validate(
            {"snapshot_id": ref.snapshot_id, "command": "x", "objects": [{"kind": "nope"}]}
        )
