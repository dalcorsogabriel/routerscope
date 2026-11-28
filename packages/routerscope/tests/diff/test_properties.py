"""Property tests: identity, inversion and robustness on arbitrary input."""

from __future__ import annotations

from collections import Counter
from ipaddress import ip_address

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from routerscope.model import VLAN, BGPPeer, Interface, SourceRef, split_lines
from routerscope.services.diff import diff_config, diff_lines, diff_objects

VENDORS = [
    "cisco_ios",
    "cisco_xr",
    "huawei_vrp",
    "ipinfusion_ocnos",
    "juniper_junos",
    "mikrotik_ros7",
    "nokia_sros",
    None,
]

# A small alphabet makes collisions (same statement on both sides) likely.
WORDS = st.sampled_from(["interface", "ip", "address", "shutdown", "description", "a", "b", "10"])
STATEMENT = st.lists(WORDS, min_size=1, max_size=4).map(" ".join)
INDENTED = st.lists(st.tuples(st.integers(0, 3), STATEMENT), max_size=14).map(
    lambda rows: "\n".join(" " * depth + text for depth, text in rows)
)

SNAP = "c" * 64


def ref() -> SourceRef:
    return SourceRef(snapshot_id=SNAP, line_start=1, line_end=1)


@settings(max_examples=150, deadline=None)
@given(text=INDENTED, vendor=st.sampled_from(VENDORS))
def test_diff_of_identical_text_is_empty(text: str, vendor: str | None) -> None:
    assert diff_config(text, text, vendor).is_empty


@settings(max_examples=200, deadline=None)
@given(a=INDENTED, b=INDENTED)
def test_config_diff_is_symmetric(a: str, b: str) -> None:
    def signature(old: str, new: str, invert: bool) -> Counter[tuple[str, tuple[str, ...], str]]:
        out: Counter[tuple[str, tuple[str, ...], str]] = Counter()
        for change in diff_config(old, new, "cisco_ios").changes():
            op = change.op
            if invert:
                op = "removed" if op == "added" else "added"
            out[(op, change.path, change.text)] += 1
        return out

    assert signature(a, b, False) == signature(b, a, True)
    forward = diff_config(a, b, "cisco_ios").stats
    backward = diff_config(b, a, "cisco_ios").stats
    assert forward == {"added": backward["removed"], "removed": backward["added"]}


@settings(max_examples=150, deadline=None)
@given(a=st.text(max_size=300), b=st.text(max_size=300), vendor=st.sampled_from(VENDORS))
def test_config_diff_never_raises_on_arbitrary_text(a: str, b: str, vendor: str | None) -> None:
    diff = diff_config(a, b, vendor)
    diff.render_text(line_numbers=True)
    diff.to_dict()
    diff_lines(a, b).render_text()


@settings(max_examples=100, deadline=None)
@given(a=st.text(alphabet='{}; \n\t#/"[]set interfacs0123456789', max_size=200))
@pytest.mark.parametrize("vendor", ["juniper_junos", "nokia_sros", "mikrotik_ros7"])
def test_structured_syntaxes_never_raise(vendor: str, a: str) -> None:
    diff_config(a, "set interfaces a unit 0\n", vendor)
    diff_config("interfaces {\n a {\n b;\n }\n}\n", a, vendor)
    diff_config(a, a, vendor)


@settings(max_examples=100, deadline=None)
@given(a=st.text(max_size=200), b=st.text(max_size=200))
def test_line_diff_applies(a: str, b: str) -> None:
    diff = diff_lines(a, b, ignore_whitespace=False)
    assert [t for m, t in diff.rows if m != "+"] == split_lines(a)
    assert [t for m, t in diff.rows if m != "-"] == split_lines(b)
    assert diff.is_empty == (split_lines(a) == split_lines(b))


NAMES = st.sampled_from(["Gi0/0", "Gi0/1", "Loopback0", "Te0/0/1"])
INTERFACES = st.builds(
    Interface,
    ref=st.just(ref()),
    name=NAMES,
    description=st.one_of(st.none(), st.sampled_from(["x", "y"])),
    mtu=st.one_of(st.none(), st.sampled_from([1500, 9000])),
)
PEERS = st.builds(
    BGPPeer,
    ref=st.just(ref()),
    peer=st.sampled_from(["192.0.2.1", "192.0.2.2", "2001:db8::1"]).map(ip_address),
    remote_as=st.sampled_from([64496, 64497]),
    vrf=st.one_of(st.none(), st.just("CUST")),
    state=st.one_of(st.none(), st.sampled_from(["Established", "Idle"])),
)
VLANS = st.builds(VLAN, ref=st.just(ref()), vlan_id=st.sampled_from([10, 20, 30]))
OBJECTS = st.lists(st.one_of(INTERFACES, PEERS, VLANS), max_size=8)


@settings(max_examples=200, deadline=None)
@given(objs=OBJECTS)
def test_semantic_diff_of_identical_is_empty(objs: list[object]) -> None:
    assert diff_objects(objs, list(objs)).is_empty  # type: ignore[arg-type]


@settings(max_examples=200, deadline=None)
@given(a=OBJECTS, b=OBJECTS)
def test_semantic_diff_inverse(a: list[object], b: list[object]) -> None:
    forward = diff_objects(a, b)  # type: ignore[arg-type]
    backward = diff_objects(b, a)  # type: ignore[arg-type]
    assert forward.inverted() == backward
    assert backward.inverted() == forward
