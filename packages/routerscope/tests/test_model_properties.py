"""Hypothesis round-trip properties for key model classes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from ipaddress import IPv4Network, IPv6Network, ip_network

from hypothesis import given
from hypothesis import strategies as st
from routerscope.model import (
    BGPPeer,
    Interface,
    IPAddress,
    PrefixListEntry,
    Snapshot,
    Source,
    SourceRef,
    StaticRoute,
)

hexes = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)
text = st.text(min_size=1, max_size=20)

offsets = st.builds(
    timezone,
    st.timedeltas(min_value=timedelta(hours=-23), max_value=timedelta(hours=23)),
)  # fixed offsets: zoneinfo data is not available on every platform


def networks(version: int) -> st.SearchStrategy[IPv4Network | IPv6Network]:
    top = 32 if version == 4 else 128
    return st.tuples(st.ip_addresses(v=version), st.integers(0, top)).map(
        lambda t: ip_network(t, strict=False)
    )


@st.composite
def refs(draw: st.DrawFn) -> SourceRef:
    start = draw(st.integers(1, 10_000))
    return SourceRef(
        snapshot_id=draw(hexes), line_start=start, line_end=start + draw(st.integers(0, 500))
    )


@given(
    hexes,
    st.datetimes(
        min_value=datetime(1990, 1, 1),
        max_value=datetime(2100, 1, 1),
        timezones=offsets,
    ),
    st.integers(0, 10**9),
    st.integers(0, 10**6),
    st.sampled_from(
        ["file", "session_log", "oxidized", "rancid", "paste", "drop_folder", "collector"]
    ),
    st.one_of(st.none(), st.sampled_from(["cisco_ios", "huawei_vrp", "nokia_sros"])),
)
def test_snapshot_roundtrip(
    sid: str, when: datetime, size: int, lines: int, kind: str, vendor: str | None
) -> None:
    snap = Snapshot(
        id=sid,
        vendor=vendor,
        kind="config",
        captured_at=when,
        source=Source(kind=kind, uri="x", importer="i"),  # type: ignore[arg-type]
        size=size,
        line_count=lines,
    )
    assert snap.captured_at.utcoffset() == UTC.utcoffset(None)
    assert Snapshot.model_validate_json(snap.model_dump_json()) == snap


@given(refs())
def test_sourceref_roundtrip(r: SourceRef) -> None:
    assert SourceRef.model_validate_json(r.model_dump_json()) == r


@given(refs(), st.ip_addresses(v=4) | st.ip_addresses(v=6), st.integers(1, 4294967295), text)
def test_bgp_peer_roundtrip(r: SourceRef, addr: object, asn: int, desc: str) -> None:
    peer = BGPPeer(ref=r, peer=addr, remote_as=asn, description=desc)  # type: ignore[arg-type]
    assert BGPPeer.model_validate_json(peer.model_dump_json()) == peer


@given(refs(), st.ip_addresses(v=4).flatmap(lambda a: st.integers(0, 32).map(lambda n: f"{a}/{n}")))
def test_ip_address_roundtrip(r: SourceRef, cidr: str) -> None:
    obj = IPAddress.model_validate({"ref": r, "interface": "e0", "address": cidr})
    assert IPAddress.model_validate_json(obj.model_dump_json()) == obj


@given(refs(), networks(6), st.integers(1, 255))
def test_static_route_roundtrip(r: SourceRef, net: object, dist: int) -> None:
    route = StaticRoute(ref=r, prefix=net, blackhole=True, distance=dist)  # type: ignore[arg-type]
    assert StaticRoute.model_validate_json(route.model_dump_json()) == route


@given(refs(), text)
def test_interface_roundtrip(r: SourceRef, name: str) -> None:
    iface = Interface(ref=r, name=name)
    assert Interface.model_validate_json(iface.model_dump_json()) == iface


@given(networks(4), st.data())
def test_prefix_entry_roundtrip(net: object, data: st.DataObject) -> None:
    assert isinstance(net, IPv4Network)
    ge = data.draw(st.integers(net.prefixlen, 32))
    le = data.draw(st.integers(ge, 32))
    entry = PrefixListEntry(action="permit", prefix=net, ge=ge, le=le)
    assert PrefixListEntry.model_validate_json(entry.model_dump_json()) == entry
