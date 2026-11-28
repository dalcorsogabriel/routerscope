"""Semantic diff: natural keys, volatile fields, entry-level diffs, registry and fallbacks."""

from __future__ import annotations

import json
from collections.abc import Iterator
from ipaddress import ip_address, ip_interface, ip_network
from typing import Any, Literal

import pytest
from pydantic import Field
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
    ParsedObject,
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
from routerscope.services.diff import ItemSpec, diff_objects, register_kind
from routerscope.services.diff import semantic as sem

SNAP_A = "a" * 64
SNAP_B = "b" * 64


def ref(snap: str = SNAP_A, start: int = 1, end: int | None = None) -> SourceRef:
    return SourceRef(snapshot_id=snap, line_start=start, line_end=end or start)


def iface(name: str = "GigabitEthernet0/0/1", snap: str = SNAP_A, **kw: Any) -> Interface:
    return Interface(ref=ref(snap), name=name, **kw)


class Widget(ParsedObject):
    """A kind the registry has never heard of."""

    kind: Literal["widget"] = "widget"
    name: str
    color: str = ""
    uptime: str = ""


class Blob(ParsedObject):
    kind: Literal["blob"] = "blob"
    payload: str = ""
    age: int = 0


class ARPEntry(ParsedObject):
    kind: Literal["arp_entry"] = "arp_entry"
    ip: str
    vrf: str | None = None
    mac: str = ""
    age: int = 0


class MACEntry(ParsedObject):
    kind: Literal["mac_entry"] = "mac_entry"
    mac: str
    vlan: int = 1
    interface: str = ""
    age: int = 0


class Weird(ParsedObject):
    kind: Literal["weird"] = "weird"
    tag: str = Field(default="x")


@pytest.fixture(autouse=True)
def _restore_registry() -> Iterator[None]:
    saved = dict(sem._REGISTRY)
    yield
    sem._REGISTRY.clear()
    sem._REGISTRY.update(saved)


def only(diff: Any) -> Any:
    assert len(diff.changes) == 1, diff.changes
    return diff.changes[0]


# --------------------------------------------------------------------------- basics


def test_identical_is_empty() -> None:
    objs = [iface(), Device(ref=ref(), hostname="R1")]
    assert diff_objects(objs, list(objs)).is_empty


def test_added_removed_changed_with_refs() -> None:
    old = [iface("GigabitEthernet0/0/1", description="old"), iface("Loopback0")]
    new = [
        Interface(ref=ref(SNAP_B, 4, 6), name="GigabitEthernet0/0/1", description="new"),
        Interface(ref=ref(SNAP_B, 9), name="Loopback1"),
    ]
    diff = diff_objects(old, new)
    assert [c.op for c in diff.changes] == ["changed", "removed", "added"]
    changed, removed, added = diff.changes
    assert changed.old_ref == ref(SNAP_A) and changed.new_ref == ref(SNAP_B, 4, 6)
    assert [(f.field, f.old, f.new) for f in changed.fields] == [("description", "old", "new")]
    assert removed.old_ref is not None and removed.new_ref is None
    assert added.new_ref == ref(SNAP_B, 9) and added.old_ref is None
    assert diff.added == (added,) and diff.removed == (removed,) and diff.changed == (changed,)
    assert diff.of_kind("interface") == diff.changes
    assert changed.label == "interface GigabitEthernet0/0/1"


def test_ref_and_line_changes_alone_are_not_changes() -> None:
    a = [iface(snap=SNAP_A)]
    b = [Interface(ref=ref(SNAP_B, 50, 60), name="GigabitEthernet0/0/1")]
    assert diff_objects(a, b).is_empty


def test_typed_name_variants_share_a_key() -> None:
    a = [Interface(ref=ref(), name="Gi0/0/1", vendor="cisco_ios")]
    b = [Interface(ref=ref(), name="GigabitEthernet0/0/1", vendor="cisco_ios")]
    change = only(diff_objects(a, b))
    assert change.op == "changed"
    assert [f.field for f in change.fields] == ["name"]


def test_duplicate_keys_are_paired_in_order() -> None:
    a = [iface(description="one"), iface(description="two")]
    b = [iface(description="one"), iface(description="TWO")]
    change = only(diff_objects(a, b))
    assert change.key[-1] == "#2"
    assert change.fields[0].new == "TWO"


def test_sources_parsed_config_and_parse_result() -> None:
    snap = SNAP_A
    cfg = ParsedConfig(snapshot_id=snap, interfaces=(iface(snap=snap),))
    result = ParseResult(snapshot_id=snap, command="show x", objects=(iface(snap=snap),))
    assert diff_objects(cfg, result).is_empty
    other = ParsedConfig(snapshot_id=SNAP_B)
    assert only(diff_objects(cfg, other)).op == "removed"
    assert only(diff_objects(other, result)).op == "added"


def test_inverted_matches_swapped_diff_and_serializes() -> None:
    a = [iface(description="x"), iface("Loopback0")]
    b = [iface(description="y"), iface("Loopback1")]
    forward = diff_objects(a, b)
    assert forward.inverted() == diff_objects(b, a)
    assert forward.inverted().inverted() == forward
    json.dumps(forward.to_dict())
    text = forward.render_text()
    assert "~ interface GigabitEthernet0/0/1" in text
    assert 'description: "x" -> "y"' in text
    assert "- interface Loopback0" in text and "+ interface Loopback1" in text
    assert forward.to_dict()["changed"] == 1


# --------------------------------------------------------------------------- natural keys


def peer(vrf: str | None, addr: str, **kw: Any) -> BGPPeer:
    return BGPPeer(ref=ref(), peer=ip_address(addr), remote_as=64500, vrf=vrf, **kw)


def route(prefix: str, nh: str | None = None, **kw: Any) -> StaticRoute:
    nexthop = ip_address(nh) if nh else None
    return StaticRoute(ref=ref(), prefix=ip_network(prefix), next_hop=nexthop, **kw)


CASES: list[tuple[str, Any, Any, str, tuple[str, ...]]] = [
    # (id, old, new-with-same-key-different-field, changed field, key)
    (
        "interface",
        iface(mtu=1500),
        iface(mtu=9000),
        "mtu",
        ("GigabitEthernet0/0/1",),
    ),
    (
        "ip_address",
        IPAddress(ref=ref(), interface="Gi0/0/1", address=ip_interface("192.0.2.1/24")),
        IPAddress(
            ref=ref(),
            interface="GigabitEthernet0/0/1",
            address=ip_interface("192.0.2.1/24"),
            secondary=True,
        ),
        "secondary",
        ("GigabitEthernet0/0/1", "192.0.2.1/24", ""),
    ),
    (
        "vrf",
        VRF(ref=ref(), name="CUST-A", rd="64496:100"),
        VRF(ref=ref(), name="CUST-A", rd="64496:200"),
        "rd",
        ("CUST-A",),
    ),
    (
        "bgp_peer",
        peer("CUST-A", "192.0.2.2", state="Established"),
        peer("CUST-A", "192.0.2.2", state="Idle"),
        "state",
        ("CUST-A", "192.0.2.2"),
    ),
    (
        "static_route",
        route("198.51.100.0/24", "192.0.2.1", distance=1),
        route("198.51.100.0/24", "192.0.2.1", distance=200),
        "distance",
        ("", "198.51.100.0/24", "192.0.2.1", "", ""),
    ),
    (
        "prefix_list",
        PrefixList(ref=ref(), name="PL", afi="ipv4"),
        PrefixList(
            ref=ref(),
            name="PL",
            afi="ipv4",
            entries=(PrefixListEntry(seq=5, action="permit", prefix=ip_network("192.0.2.0/24")),),
        ),
        "",
        ("PL", "ipv4"),
    ),
    (
        "vlan",
        VLAN(ref=ref(), vlan_id=10, name="USERS"),
        VLAN(ref=ref(), vlan_id=10, name="CUSTOMERS"),
        "name",
        ("10",),
    ),
    (
        "lag",
        LAG(ref=ref(), name="Po1", mode="lacp"),
        LAG(ref=ref(), name="Po1", mode="static"),
        "mode",
        ("Port-channel1",),
    ),
    (
        "igp",
        IGP(ref=ref(), protocol="ospf", process="1", router_id="192.0.2.9"),
        IGP(ref=ref(), protocol="ospf", process="1", router_id="192.0.2.10"),
        "router_id",
        ("ospf", "1", ""),
    ),
    (
        "device",
        Device(ref=ref(), hostname="R1"),
        Device(ref=ref(), hostname="R2"),
        "hostname",
        (),
    ),
    (
        "version",
        Version(ref=ref(), version="17.3.1"),
        Version(ref=ref(), version="17.9.2"),
        "version",
        (),
    ),
    (
        "transceiver",
        Transceiver(ref=ref(), interface="Te0/0/1", part_number="SFP-10G"),
        Transceiver(ref=ref(), interface="TenGigabitEthernet0/0/1", part_number="SFP-10G-LR"),
        "part_number",
        ("TenGigabitEthernet0/0/1",),
    ),
    (
        "acl",
        ACL(ref=ref(), name="EDGE-IN", afi="ipv4", acl_type="extended"),
        ACL(ref=ref(), name="EDGE-IN", afi="ipv4", acl_type="standard"),
        "acl_type",
        ("EDGE-IN", "ipv4"),
    ),
    (
        "policy",
        Policy(ref=ref(), name="EXPORT", policy_type="route-map"),
        Policy(ref=ref(), name="EXPORT", policy_type="route-policy"),
        "policy_type",
        ("EXPORT",),
    ),
]


@pytest.mark.parametrize(("case"), CASES, ids=[c[0] for c in CASES])
def test_natural_key_per_kind(case: tuple[str, Any, Any, str, tuple[str, ...]]) -> None:
    kind, old, new, field_name, key = case
    change = only(diff_objects([old], [new]))
    assert change.kind == kind and change.op == "changed" and change.key == key
    if field_name:
        assert [f.field for f in change.fields] == [field_name]


def test_different_keys_do_not_pair() -> None:
    cases = [
        (peer("A", "192.0.2.2"), peer("B", "192.0.2.2")),  # vrf is part of the key
        (peer(None, "192.0.2.2"), peer(None, "192.0.2.3")),
        (route("198.51.100.0/24", "192.0.2.1"), route("198.51.100.0/24", "192.0.2.2")),
        (route("198.51.100.0/24", "192.0.2.1"), route("198.51.100.0/25", "192.0.2.1")),
        (
            PrefixList(ref=ref(), name="PL", afi="ipv4"),
            PrefixList(ref=ref(), name="PL", afi="ipv6"),
        ),
        (VLAN(ref=ref(), vlan_id=10), VLAN(ref=ref(), vlan_id=11)),
        (
            IPAddress(ref=ref(), interface="Lo0", address=ip_interface("192.0.2.1/32")),
            IPAddress(ref=ref(), interface="Lo0", address=ip_interface("192.0.2.1/32"), vrf="CUST"),
        ),
    ]
    for old, new in cases:
        diff = diff_objects([old], [new])
        assert sorted(c.op for c in diff.changes) == ["added", "removed"], (old, new)


def test_static_route_blackhole_and_interface_keys() -> None:
    bh = StaticRoute(ref=ref(), prefix=ip_network("203.0.113.0/24"), blackhole=True)
    via = StaticRoute(ref=ref(), prefix=ip_network("203.0.113.0/24"), interface="Null0")
    assert len(diff_objects([bh], [via]).changes) == 2
    assert diff_objects([bh], [bh]).is_empty


def test_bgp_state_change_is_a_change() -> None:
    change = only(
        diff_objects(
            [peer(None, "2001:db8::1", state="Established")],
            [peer(None, "2001:db8::1", state="Active")],
        )
    )
    assert [(f.field, f.old, f.new) for f in change.fields] == [("state", "Established", "Active")]


def test_unordered_fields_compare_as_sets() -> None:
    a = VRF(ref=ref(), name="V", import_targets=("64496:1", "64496:2"), interfaces=("a", "b"))
    b = VRF(ref=ref(), name="V", import_targets=("64496:2", "64496:1"), interfaces=("b", "a"))
    assert diff_objects([a], [b]).is_empty
    c = VRF(ref=ref(), name="V", import_targets=("64496:2", "64496:3"), interfaces=("a", "b"))
    assert [f.field for f in only(diff_objects([a], [c])).fields] == ["import_targets"]
    # ordered fields do care about order
    p1 = peer(None, "192.0.2.5", import_policies=("A", "B"))
    p2 = peer(None, "192.0.2.5", import_policies=("B", "A"))
    assert [f.field for f in only(diff_objects([p1], [p2])).fields] == ["import_policies"]
    # a list field turning into something else is still reported
    assert diff_objects([a], [b.model_copy(update={"description": "d"})]).changed


# --------------------------------------------------------------------------- volatile


def test_volatile_fields_ignored_by_default() -> None:
    v1 = Version(ref=ref(), version="17.3.1", uptime="1 week")
    v2 = Version(ref=ref(), version="17.3.1", uptime="2 weeks")
    assert diff_objects([v1], [v2]).is_empty
    change = only(diff_objects([v1], [v2], include_volatile=True))
    assert [f.field for f in change.fields] == ["uptime"]
    v3 = v2.model_copy(update={"version": "17.9.1"})
    assert [f.field for f in only(diff_objects([v1], [v3])).fields] == ["version"]


def test_transceiver_readings_are_volatile() -> None:
    t1 = Transceiver(ref=ref(), interface="Te0/0/1", rx_power_dbm=-2.1, temperature_c=31.0)
    t2 = Transceiver(ref=ref(), interface="Te0/0/1", rx_power_dbm=-2.4, temperature_c=33.0)
    assert diff_objects([t1], [t2]).is_empty
    change = only(diff_objects([t1], [t2], include_volatile=True))
    assert {f.field for f in change.fields} == {"rx_power_dbm", "temperature_c"}


def test_registered_volatile_for_arp_and_mac_kinds() -> None:
    a1 = ARPEntry(ref=ref(), ip="192.0.2.1", mac="aa", age=1)
    a2 = ARPEntry(ref=ref(), ip="192.0.2.1", mac="aa", age=99)
    assert diff_objects([a1], [a2]).is_empty
    assert only(diff_objects([a1], [a2], include_volatile=True)).fields[0].field == "age"
    a3 = a1.model_copy(update={"mac": "bb"})
    assert only(diff_objects([a1], [a3])).fields[0].field == "mac"
    assert len(diff_objects([a1], [a1.model_copy(update={"vrf": "X"})]).changes) == 2

    m1 = MACEntry(ref=ref(), mac="aa", vlan=10, interface="Gi0/1", age=3)
    m2 = MACEntry(ref=ref(), mac="aa", vlan=10, interface="Gi0/2", age=9)
    assert [f.field for f in only(diff_objects([m1], [m2])).fields] == ["interface"]
    assert len(diff_objects([m1], [m1.model_copy(update={"vlan": 11})]).changes) == 2


# --------------------------------------------------------------------------- entries


def pl(*entries: PrefixListEntry) -> PrefixList:
    return PrefixList(ref=ref(), name="PL", afi="ipv4", entries=entries)


def ple(seq: int | None, prefix: str, action: str = "permit", **kw: Any) -> PrefixListEntry:
    return PrefixListEntry(seq=seq, action=action, prefix=ip_network(prefix), **kw)  # type: ignore[arg-type]


def test_prefix_list_entry_level_diff_by_seq() -> None:
    old = pl(ple(5, "192.0.2.0/24"), ple(10, "198.51.100.0/24"))
    new = pl(ple(5, "192.0.2.0/24", le=28), ple(15, "203.0.113.0/24"))
    change = only(diff_objects([old], [new]))
    assert change.fields == ()
    ops = {(i.op, i.key) for i in change.items}
    assert ops == {("changed", "seq 5"), ("removed", "seq 10"), ("added", "seq 15")}
    changed = next(i for i in change.items if i.op == "changed")
    assert [(f.field, f.old, f.new) for f in changed.fields] == [("le", None, 28)]
    assert "seq 5" in diff_objects([old], [new]).render_text()


def test_prefix_list_without_seq_keys_by_content_and_order() -> None:
    a = pl(ple(None, "192.0.2.0/24", ge=25), ple(None, "198.51.100.0/24", "deny", le=26))
    same = pl(ple(None, "192.0.2.0/24", ge=25), ple(None, "198.51.100.0/24", "deny", le=26))
    assert diff_objects([a], [same]).is_empty
    reordered = pl(ple(None, "198.51.100.0/24", "deny", le=26), ple(None, "192.0.2.0/24", ge=25))
    change = only(diff_objects([a], [reordered]))
    assert change.items == ()
    assert [f.field for f in change.fields] == ["entries_order"]
    # seq-keyed entries are never an order change
    s1 = pl(ple(5, "192.0.2.0/24"), ple(10, "198.51.100.0/24"))
    s2 = pl(ple(10, "198.51.100.0/24"), ple(5, "192.0.2.0/24"))
    assert diff_objects([s1], [s2]).is_empty


def test_duplicate_entries_get_distinct_keys() -> None:
    a = pl(ple(None, "192.0.2.0/24"), ple(None, "192.0.2.0/24"))
    b = pl(ple(None, "192.0.2.0/24"))
    change = only(diff_objects([a], [b]))
    assert [(i.op, i.key) for i in change.items] == [("removed", "permit 192.0.2.0/24 #2")]


def test_acl_entries_by_seq_and_raw() -> None:
    def acl(*entries: ACLEntry) -> ACL:
        return ACL(ref=ref(), name="EDGE", afi="ipv4", entries=entries)

    old = acl(
        ACLEntry(seq=10, action="permit", raw="permit tcp any any eq 22"),
        ACLEntry(action="deny", protocol="ip", source="any", destination="any"),
    )
    new = acl(
        ACLEntry(seq=10, action="permit", raw="permit tcp any any eq 443"),
        ACLEntry(action="deny", protocol="ip", source="any", destination="any"),
        ACLEntry(action="permit", raw="permit icmp any any"),
    )
    change = only(diff_objects([old], [new]))
    assert {(i.op, i.key) for i in change.items} == {
        ("changed", "seq 10"),
        ("added", "permit icmp any any"),
    }


def term(seq: int | None = None, name: str | None = None, **kw: Any) -> PolicyTerm:
    return PolicyTerm(seq=seq, name=name, **kw)


def test_policy_terms_by_seq_name_and_ordinal() -> None:
    def pol(*terms: PolicyTerm) -> Policy:
        return Policy(ref=ref(), name="P", terms=terms)

    clause = PolicyClause(type="prefix-list", value="CUST")
    t10 = term(10, disposition="permit", matches=(clause,))
    t10b = term(10, disposition="deny", matches=(clause,), ref=ref(SNAP_A, 3, 4))
    change = only(diff_objects([pol(t10)], [pol(t10b)]))
    (item,) = change.items
    assert item.key == "seq 10" and [f.field for f in item.fields] == ["disposition"]

    # raw_lines are ignored once clauses are parsed; they matter for unparsed terms
    raw1 = term(20, raw_lines=("set a",))
    raw2 = term(20, raw_lines=("set b",))
    assert only(diff_objects([pol(raw1)], [pol(raw2)])).items[0].fields[0].field == "raw_lines"
    noisy1 = term(30, matches=(clause,), raw_lines=("match x",))
    noisy2 = term(30, matches=(clause,), raw_lines=("match   x",))
    assert diff_objects([pol(noisy1)], [pol(noisy2)]).is_empty

    named_a = pol(term(name="T1"), term(name="T2"), term())
    named_b = pol(term(name="T2"), term(name="T1"), term())
    change = only(diff_objects([named_a], [named_b]))
    assert [f.field for f in change.fields] == ["terms_order"]
    added = diff_objects([pol(term())], [pol(term(), term())])
    assert [(i.op, i.key) for i in only(added).items] == [("added", "#2")]


def test_igp_interfaces_entry_level() -> None:
    a = IGP(
        ref=ref(),
        protocol="isis",
        process="CORE",
        areas=("49.0001", "49.0002"),
        interfaces=(IGPInterface(name="Lo0", passive=True), IGPInterface(name="Te0/0/1")),
    )
    b = IGP(
        ref=ref(),
        protocol="isis",
        process="CORE",
        areas=("49.0002", "49.0001"),
        interfaces=(
            IGPInterface(name="Lo0", passive=True),
            IGPInterface(name="Te0/0/2", metric=10),
        ),
    )
    change = only(diff_objects([a], [b]))
    assert change.fields == ()
    assert {(i.op, i.key) for i in change.items} == {
        ("removed", "Te0/0/1"),
        ("added", "Te0/0/2"),
    }


# --------------------------------------------------------------------------- registry


def test_unknown_kind_with_name_uses_generic_key_and_generic_volatile() -> None:
    w1 = Widget(ref=ref(), name="w", color="red", uptime="1d")
    w2 = Widget(ref=ref(), name="w", color="blue", uptime="9d")
    change = only(diff_objects([w1], [w2]))
    assert change.kind == "widget" and change.key == ("w",)
    assert [f.field for f in change.fields] == ["color"]
    assert only(diff_objects([w1], [w2], include_volatile=True)).fields[1].field == "uptime"
    assert "widget w" in diff_objects([w1], []).render_text()


def test_unknown_kind_without_name_keys_by_content() -> None:
    b1 = Blob(ref=ref(), payload="x", age=1)
    assert diff_objects([b1], [Blob(ref=ref(), payload="x", age=5)]).is_empty
    diff = diff_objects([b1], [Blob(ref=ref(), payload="y", age=1)])
    assert sorted(c.op for c in diff.changes) == ["added", "removed"]


def test_unknown_kinds_sort_after_known_ones() -> None:
    diff = diff_objects([], [Widget(ref=ref(), name="w"), iface(), Blob(ref=ref(), payload="p")])
    assert [c.kind for c in diff.changes] == ["interface", "blob", "widget"]


def test_register_kind_is_one_line() -> None:
    register_kind("widget", ("name", "color"), volatile=("uptime",))
    w1 = Widget(ref=ref(), name="w", color="red")
    w2 = Widget(ref=ref(), name="w", color="blue")
    assert sorted(c.op for c in diff_objects([w1], [w2]).changes) == ["added", "removed"]
    with pytest.raises(ValueError, match="already registered"):
        register_kind("widget", ("name",))
    spec = register_kind("widget", ("name",), replace=True, items=[ItemSpec("x", lambda i, n: "")])
    assert sem.registry()["widget"] is spec


def test_missing_key_fields_fall_back_to_generic_key() -> None:
    register_kind("weird", ("does_not_exist",))
    diff = diff_objects([Weird(ref=ref(), tag="a")], [Weird(ref=ref(), tag="b")])
    assert sorted(c.op for c in diff.changes) == ["added", "removed"]
    register_kind("weird", lambda o: (o.nope,), replace=True)
    assert diff_objects([Weird(ref=ref())], [Weird(ref=ref())]).is_empty


def test_custom_specs_argument_overrides_registry() -> None:
    specs = {"widget": sem.KindSpec("widget", ("color",))}
    a = [Widget(ref=ref(), name="a", color="red")]
    b = [Widget(ref=ref(), name="b", color="red")]
    assert [f.field for f in only(diff_objects(a, b, specs=specs)).fields] == ["name"]


def test_generic_key_helper() -> None:
    assert sem.generic_key(Widget(ref=ref(), name="n")) == ("n",)
    assert sem.generic_key(Blob(ref=ref(), payload="p", age=3))[0].startswith("{")
