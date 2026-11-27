from __future__ import annotations

import ipaddress
import sqlite3

import pytest
from hypothesis import given
from hypothesis import strategies as st
from netaddr_search import (
    SQL_COVERING,
    SQL_INSIDE,
    SQL_OVERLAPS,
    MatchKind,
    Relation,
    bounds,
    bounds_int,
    find_ips,
    parse_network,
    query_params,
    relation,
    sql_fragments,
)

N = ipaddress.ip_network


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("192.0.2.1", "192.0.2.1/32"),
        ("  192.0.2.1 \n", "192.0.2.1/32"),
        ("2001:db8::1", "2001:db8::1/128"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1/128"),
        ("192.0.2.0/24", "192.0.2.0/24"),
        ("192.0.2.5/24", "192.0.2.0/24"),
        ("2001:db8::/32", "2001:db8::/32"),
        ("2001:db8::5/32", "2001:db8::/32"),
        ("192.0.2.0 255.255.255.0", "192.0.2.0/24"),
        ("192.0.2.0   255.255.255.252", "192.0.2.0/30"),
        ("192.0.2.0 0.0.0.255", "192.0.2.0/24"),
        ("198.51.100.0 0.0.3.255", "198.51.100.0/22"),
        ("192.0.2.1 0.0.0.0", "192.0.2.1/32"),
        ("0.0.0.0 0.0.0.0", "0.0.0.0/0"),
        ("192.0.2.1 255.255.255.255", "192.0.2.1/32"),
    ],
)
def test_parse_valid(text: str, expected: str) -> None:
    assert parse_network(text) == N(expected)


@pytest.mark.parametrize(
    "text",
    [
        "",
        " ",
        "foo",
        "192.0.2",
        "192.0.2.256",
        "192.0.2.0/33",
        "2001:db8::/129",
        "192.0.2.0 0.255.0.255",
        "192.0.2.0 255.0.255.0",
        "192.0.2.0 foo",
        "192.0.2.0 255.255.255.0 extra",
        "2001:db8::1 ffff::",
        "fe80::1%eth0",
        "01.0.0.1",
    ],
)
def test_parse_invalid(text: str) -> None:
    assert parse_network(text) is None


def test_parse_non_string() -> None:
    with pytest.raises(TypeError):
        parse_network(None)  # type: ignore[arg-type]


def test_parse_any_and_host_ambiguity() -> None:
    assert str(parse_network("0.0.0.0 255.255.255.255")) == "0.0.0.0/0"
    assert str(parse_network("192.0.2.1 255.255.255.255")) == "192.0.2.1/32"
    assert str(parse_network("192.0.2.1 0.0.0.0")) == "192.0.2.1/32"


def test_relation_table() -> None:
    a, b, c = N("192.0.2.0/24"), N("192.0.2.128/25"), N("198.51.100.0/24")
    assert relation(a, a) is Relation.EQUAL
    assert relation(b, a) is Relation.INSIDE
    assert relation(a, b) is Relation.CONTAINS
    assert relation(a, c) is Relation.DISJOINT
    assert relation(a, N("2001:db8::/32")) is Relation.DISJOINT
    assert relation(N("2001:db8:1::/48"), N("2001:db8::/32")) is Relation.INSIDE


def test_bounds() -> None:
    assert bounds(N("192.0.2.0/24")) == (4, bytes([192, 0, 2, 0]), bytes([192, 0, 2, 255]))
    v, s, e = bounds(N("2001:db8::/32"))
    assert (v, len(s), len(e)) == (6, 16, 16)
    assert bounds_int(N("192.0.2.0/24")) == (4, 0xC0000200, 0xC00002FF)


_v4_nets = st.builds(
    lambda a, p: ipaddress.IPv4Network((a, p), strict=False),
    st.integers(0, 2**32 - 1),
    st.integers(0, 32),
)
_v6_nets = st.builds(
    lambda a, p: ipaddress.IPv6Network((a, p), strict=False),
    st.integers(0, 2**128 - 1),
    st.integers(0, 128),
)
_nets = st.one_of(_v4_nets, _v6_nets)


@given(_nets)
def test_parse_roundtrip(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> None:
    assert parse_network(str(net)) == net


@given(_nets, _nets)
def test_relation_properties(
    a: ipaddress.IPv4Network | ipaddress.IPv6Network,
    b: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> None:
    assert relation(a, a) is Relation.EQUAL
    r = relation(a, b)
    flip = {
        Relation.INSIDE: Relation.CONTAINS,
        Relation.CONTAINS: Relation.INSIDE,
        Relation.EQUAL: Relation.EQUAL,
        Relation.DISJOINT: Relation.DISJOINT,
    }
    assert relation(b, a) is flip[r]


@given(_nets, _nets)
def test_bounds_order_matches_int_order(
    a: ipaddress.IPv4Network | ipaddress.IPv6Network,
    b: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> None:
    if a.version != b.version:
        return
    (_, as_, ae), (_, bs, be) = bounds(a), bounds(b)
    (_, ais, aie), (_, bis, bie) = bounds_int(a), bounds_int(b)
    assert (as_ < bs) == (ais < bis)
    assert (ae <= be) == (aie <= bie)
    assert int.from_bytes(as_, "big") == ais


def _sql_fixture() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
        N("0.0.0.0/0"),
        N("::/0"),
        N("128.0.0.0/1"),
        N("255.255.255.255/32"),
        N("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"),
        N("8000::/1"),
        N("a000::/3"),
    ]
    for plen in (8, 16, 22, 24, 25, 30, 32):
        for base in ("192.0.2.0", "198.51.100.0", "203.0.113.128", "200.0.0.0", "10.255.0.0"):
            nets.append(ipaddress.IPv4Network((base, plen), strict=False))
    for plen in (16, 32, 48, 64, 128):
        for base in ("2001:db8::", "2001:db8:8000::", "8000::1", "fe80::", "ffff::"):
            nets.append(ipaddress.IPv6Network((base, plen), strict=False))
    return sorted(set(nets), key=lambda n: (n.version, n.network_address, n.prefixlen))


def test_sql_matches_relation() -> None:
    nets = _sql_fixture()
    assert any(int(n.network_address) >= 2**63 and n.version == 6 for n in nets)
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE p (id INTEGER PRIMARY KEY, version INT, start BLOB, end BLOB)")
    for i, n in enumerate(nets):
        v, s, e = bounds(n)
        db.execute("INSERT INTO p VALUES (?, ?, ?, ?)", (i, v, s, e))
    queries = [*nets, N("192.0.2.0/23"), N("2001:db8:8000::/33"), N("1.2.3.4/32")]
    for q in queries:
        params = query_params(q)
        for sql, accept in (
            (SQL_INSIDE, {Relation.INSIDE, Relation.EQUAL}),
            (SQL_COVERING, {Relation.CONTAINS, Relation.EQUAL}),
            (SQL_OVERLAPS, {Relation.INSIDE, Relation.CONTAINS, Relation.EQUAL}),
        ):
            got = {r[0] for r in db.execute(f"SELECT id FROM p WHERE {sql}", params)}
            # relation(row, query): INSIDE means row inside query.
            want = {i for i, n in enumerate(nets) if relation(n, q) in accept}
            assert got == want, (q, sql)
    db.close()


# --- find_ips -------------------------------------------------------------------------------


def _found(text: str) -> list[tuple[str, str, MatchKind]]:
    return [(m.text, str(m.network), m.kind) for m in find_ips(text)]


def test_find_plain_and_prefix() -> None:
    text = "route 192.0.2.0/24 via 198.51.100.1, peer 2001:db8::1 net 2001:db8:1::/48."
    assert _found(text) == [
        ("192.0.2.0/24", "192.0.2.0/24", MatchKind.PREFIX),
        ("198.51.100.1", "198.51.100.1/32", MatchKind.ADDRESS),
        ("2001:db8::1", "2001:db8::1/128", MatchKind.ADDRESS),
        ("2001:db8:1::/48", "2001:db8:1::/48", MatchKind.PREFIX),
    ]


def test_find_spans() -> None:
    text = "ip 192.0.2.7 ok"
    (m,) = find_ips(text)
    assert text[m.start : m.end] == m.text == "192.0.2.7"
    assert str(m.address) == "192.0.2.7"


def test_find_interface_address_mask() -> None:
    text = " ip address 192.0.2.1 255.255.255.0\n"
    (m,) = find_ips(text)
    assert str(m.address) == "192.0.2.1"
    assert str(m.network) == "192.0.2.0/24"
    assert m.kind is MatchKind.MASK
    assert m.text == "192.0.2.1 255.255.255.0"


def test_find_wildcard_pair() -> None:
    (m,) = find_ips("network 203.0.113.0 0.0.0.255 area 0")
    assert str(m.network) == "203.0.113.0/24"
    assert m.kind is MatchKind.WILDCARD


def test_find_default_route() -> None:
    # Changed: used to be two 0.0.0.0/32 ADDRESS matches.
    m1, m2 = find_ips("ip route 0.0.0.0 0.0.0.0 192.0.2.1")
    assert (m1.text, str(m1.network), m1.kind) == ("0.0.0.0 0.0.0.0", "0.0.0.0/0", MatchKind.MASK)
    assert (m1.start, m1.end) == (9, 24)
    assert (m2.text, str(m2.network), m2.kind) == ("192.0.2.1", "192.0.2.1/32", MatchKind.ADDRESS)


def test_find_acl_any_and_host_wildcard() -> None:
    (m,) = find_ips("permit ip 0.0.0.0 255.255.255.255")
    assert (str(m.network), m.kind) == ("0.0.0.0/0", MatchKind.WILDCARD)
    (m,) = find_ips("permit ip host 192.0.2.1 0.0.0.0")
    assert (str(m.network), m.kind) == ("192.0.2.1/32", MatchKind.WILDCARD)


def test_find_skip_after_version_words() -> None:
    text = "RouterOS version 7.16.1.0 peer 192.0.2.1\nBuild: 7.16.1.1 and 198.51.100.7"
    assert [m.text for m in find_ips(text)] == [
        "7.16.1.0",
        "192.0.2.1",
        "7.16.1.1",
        "198.51.100.7",
    ]
    got = [m.text for m in find_ips(text, skip_after=("version", "build", "release"))]
    assert got == ["192.0.2.1", "198.51.100.7"]
    # word boundary and same line only
    assert [m.text for m in find_ips("subversion 192.0.2.1", skip_after=("version",))] == [
        "192.0.2.1"
    ]
    assert [m.text for m in find_ips("version\n192.0.2.1", skip_after=("version",))] == [
        "192.0.2.1"
    ]
    assert list(find_ips("VERSION=7.16.1.0", skip_after=("version",))) == []


def test_find_nonmask_second_not_paired() -> None:
    got = [m.text for m in find_ips("hop 192.0.2.1 198.51.100.1")]
    assert got == ["192.0.2.1", "198.51.100.1"]


def test_find_prefix_len_too_big() -> None:
    assert _found("192.0.2.1/33") == [("192.0.2.1", "192.0.2.1/32", MatchKind.ADDRESS)]
    assert _found("2001:db8::1/200") == [("2001:db8::1", "2001:db8::1/128", MatchKind.ADDRESS)]


def test_find_ipv6_forms() -> None:
    # Changed: a standalone "::" is no longer matched.
    assert [m.text for m in find_ips("::1 and :: and 2001:db8::")] == ["::1", "2001:db8::"]
    assert list(find_ips("at :: now")) == []
    assert [(m.text, str(m.network)) for m in find_ips("::/0 and ::/128")] == [
        ("::/0", "::/0"),
        ("::/128", "::/128"),
    ]
    (m,) = find_ips("addr ::ffff:192.0.2.1 up")
    assert m.address == ipaddress.IPv6Address("::ffff:c000:201")
    (m,) = find_ips("full 2001:0db8:0000:0000:0000:0000:0000:0001.")
    assert m.text == "2001:0db8:0000:0000:0000:0000:0000:0001"
    (m,) = find_ips("(2001:db8::1:)")
    assert m.text == "2001:db8::1"


@pytest.mark.parametrize(
    "text",
    [
        "version 7.16.1",
        "RouterOS 7.16.1 (stable)",
        "time 10:20:30",
        "mac aa:bb:cc:dd:ee:ff",
        "mac aabb.ccdd.eeff",
        "port 1/1/1",
        "port 1/1/c1/1",
        "Gi0/0/1",
        "std::string",
        "key::value",
        "2001:db8::1g",
        "1.2.3.4.5",
        "300.1.1.1",
        "a.b.c.d",
        "1:2:3",
        "abc192.0.2.1",
    ],
)
def test_find_negatives(text: str) -> None:
    assert list(find_ips(text)) == []


def test_find_multiline_no_cross_line_pair() -> None:
    got = [m.text for m in find_ips("192.0.2.1\n255.255.255.0")]
    assert got == ["192.0.2.1", "255.255.255.0"]


def test_sql_fragments_default_equals_constants() -> None:
    frags = sql_fragments()
    assert frags == {"inside": SQL_INSIDE, "covering": SQL_COVERING, "overlaps": SQL_OVERLAPS}


def test_sql_fragments_prefix_sqlite() -> None:
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE t (name TEXT, ip_version INTEGER, ip_start BLOB, ip_end BLOB)")
    rows = ["192.0.2.0/24", "192.0.2.128/25", "198.51.100.0/24", "2001:db8::/32"]
    for r in rows:
        v, a, b = bounds(N(r))
        db.execute("INSERT INTO t VALUES (?, ?, ?, ?)", (r, v, a, b))
    frags = sql_fragments("ip_")
    params = query_params(N("192.0.2.0/24"))
    got = {
        k: {r[0] for r in db.execute(f"SELECT name FROM t WHERE {sql}", params)}
        for k, sql in frags.items()
    }
    db.close()
    assert got["inside"] == {"192.0.2.0/24", "192.0.2.128/25"}
    assert got["covering"] == {"192.0.2.0/24"}
    assert got["overlaps"] == {"192.0.2.0/24", "192.0.2.128/25"}


def test_sql_fragments_rejects_bad_prefix() -> None:
    with pytest.raises(ValueError, match="prefix"):
        sql_fragments('x" OR 1=1 --')
