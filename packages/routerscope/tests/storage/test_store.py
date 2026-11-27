from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from routerscope.model import (
    ParsedConfig,
    ParseResult,
    Source,
    SourceRef,
    Version,
    split_lines,
)
from routerscope.storage import (
    QuerySyntaxError,
    Redactor,
    Store,
    UnknownSnapshotError,
    UnredactedDataError,
)

T0 = datetime(2025, 1, 1, 12, 0, tzinfo=UTC)

CONFIG = """\
hostname r1
interface GigabitEthernet0/0/1
 ip address 192.0.2.1 255.255.255.0
 ipv6 address 2001:db8::1/64
 mac-address 0000.5e00.5301
!
router bgp 64496
 neighbor 192.0.2.2 remote-as 64497
 neighbor 198.51.100.1 remote-as 65536
 neighbor 192.0.2.2 route-map RM-IN in
route-policy PASS-ALL
ip community-list 1 permit 64496:100
ip route 0.0.0.0 0.0.0.0 192.0.2.254
"""


def add(
    store: Store,
    content: str,
    src: Source,
    at: datetime = T0,
    host: str | None = "r1",
    **kw: object,
) -> str:
    snap = store.add_snapshot(
        content,
        source=src,
        kind=kw.pop("kind", "config"),  # type: ignore[arg-type]
        captured_at=at,
        hostname=host,
        vendor=kw.pop("vendor", "cisco_ios"),  # type: ignore[arg-type]
        command=kw.pop("command", None),  # type: ignore[arg-type]
    )
    return snap.id


def test_roundtrip_and_dedupe(store: Store, src: Source) -> None:
    a = store.add_snapshot(
        CONFIG, source=src, kind="config", captured_at=T0, hostname="r1", vendor="cisco_ios"
    )
    assert a.line_count == len(split_lines(CONFIG))
    assert store.get_content(a.id) == CONFIG
    assert store.get_snapshot(a.id) == a
    # same content, new time and host: one content row, two observations
    add(store, CONFIG, src, T0 + timedelta(days=1), host="r2")
    # exact same observation again is a no-op
    add(store, CONFIG, src, T0 + timedelta(days=1), host="r2")
    n = store._conn.execute("SELECT count(*) FROM contents").fetchone()[0]
    assert n == 1
    assert len(store.observations(a.id)) == 2
    assert store._conn.execute("SELECT count(*) FROM ip_addrs").fetchone()[0] == 7


def test_bytes_content_and_missing(store: Store, src: Source) -> None:
    sid = add(store, "hostname r1\n", src)  # str
    snap = store.add_snapshot(
        b"hostname r1\n", source=src, kind="config", captured_at=T0, hostname="r1"
    )
    assert snap.id == sid
    assert store.get_content("0" * 64) is None
    assert store.get_snapshot("0" * 64) is None
    assert store.get_lines("0" * 64, 1, 2) == []
    assert store.get_lines(sid, 3, 1) == []
    assert store.get_lines(sid, 1, 5) == ["hostname r1"]
    assert store.get_snapshot(sid) is not None


def test_naive_datetime_rejected(store: Store, src: Source) -> None:
    with pytest.raises(ValueError):
        store.snapshot_at("r1", datetime(2025, 1, 1))


def test_history_and_time_travel(store: Store, src: Source) -> None:
    ids = [
        add(store, f"hostname r1\n! rev {i}\n", src, T0 + timedelta(hours=i), command=None)
        for i in (3, 1, 2)
    ]
    add(store, "show version\n", src, T0, kind="command_output", command="show version")
    add(store, "x\n", src, T0, host="other")
    hist = store.history("R1", kind="config")
    assert [h.captured_at.hour - 12 for h in hist] == [1, 2, 3]
    assert hist[0].id == ids[1]
    assert len(store.history("r1")) == 4
    assert len(store.history("r1", command="show version")) == 1
    assert store.history("nobody") == []
    at = T0 + timedelta(hours=2, minutes=30)
    got = store.snapshot_at("r1", at, kind="config")
    assert got is not None
    assert got.id == ids[2]
    assert store.snapshot_at("r1", T0 + timedelta(hours=2), kind="config") is not None
    assert store.snapshot_at("r1", T0 - timedelta(days=1)) is None
    # an aware non-UTC datetime is compared as an instant
    tz = timezone_plus(3)
    latest = store.snapshot_at("r1", (T0 + timedelta(hours=10)).astimezone(tz), kind="config")
    assert latest is not None
    assert latest.id == ids[0]


def timezone_plus(hours: int):  # type: ignore[no-untyped-def]
    from datetime import timezone

    return timezone(timedelta(hours=hours))


def test_devices(store: Store, src: Source) -> None:
    add(store, "a\n", src, T0, host="r1", vendor="cisco_ios")
    add(store, "b\n", src, T0 + timedelta(days=1), host="R1", vendor="third_party")
    add(store, "c\n", src, T0, host=None)
    devs = store.devices()
    assert len(devs) == 1
    assert devs[0].observations == 2
    assert devs[0].vendor == "third_party"
    assert devs[0].last_seen - devs[0].first_seen == timedelta(days=1)


def test_source_metadata_roundtrip(store: Store) -> None:
    s = Source(
        kind="oxidized",
        uri="ssh://user:pw@host/repo.git",
        importer="oxidized",
        git_commit="abc123",
    )
    sid = add(store, "hostname r1\n", s)
    got = store.get_snapshot(sid)
    assert got is not None
    assert got.source.uri == "ssh://host/repo.git"
    assert got.source.git_commit == "abc123"
    assert got.hostname == "r1"
    assert got.command is None


def test_third_party_vendor_id_accepted(store: Store, src: Source) -> None:
    sid = add(store, "interface Gi0/1\n", src, vendor="acme_os")
    assert store.find_interface("GigabitEthernet0/1", "acme_os")
    assert store.get_snapshot(sid) is not None


# ------------------------------------------------------------------------------ queries


@pytest.fixture
def loaded(store: Store, src: Source) -> tuple[Store, str]:
    return store, add(store, CONFIG, src)


def test_search_text_hits_network_text(loaded: tuple[Store, str]) -> None:
    store, sid = loaded
    for query, line in [
        ("GigabitEthernet0/0/1", 2),
        ("gigabitethernet0/0/1", 2),
        ("0/0/1", 2),
        ("route-policy", 11),
        ("policy", 11),
        ("192.0.2.1", 3),
        ("AS65536", None),
        ("remote-as 65536", 9),
    ]:
        hits = store.search_text(query, literal=True)
        if line is None:
            assert hits == []
        else:
            assert (sid, line) in [(h.snapshot_id, h.line_no) for h in hits], query
            assert all(query.lower() in h.text.lower() for h in hits)
    boolean = store.search_text("remote AND 65536")
    assert [h.line_no for h in boolean] == [9]
    assert store.search_text("zzzzqqq") == []
    assert len(store.search_text("neighbor", limit=2)) == 2


def test_search_text_errors(store: Store) -> None:
    with pytest.raises(QuerySyntaxError):
        store.search_text("   ")
    with pytest.raises(QuerySyntaxError):
        store.search_text('"unbalanced')
    with pytest.raises(QuerySyntaxError):
        store.search_text("route AND (policy")
    with pytest.raises(ValueError):
        store.search_text("abc", limit=0)


def test_search_line_numbers_across_contents(store: Store, src: Source) -> None:
    a = add(store, "alpha\n\nneedle-one here\n", src, host="a")
    b = add(store, "\n\n\nbeta needle-one\n", src, host="b")
    hits = {
        (h.snapshot_id, h.line_no): h.text for h in store.search_text("needle-one", literal=True)
    }
    assert hits == {(a, 3): "needle-one here", (b, 4): "beta needle-one"}
    empty = add(store, "", src, host="e")
    assert store.get_snapshot(empty) is not None
    assert len(store.search_text("needle-one", literal=True)) == 2


def test_line_numbers_follow_split_lines(store: Store, src: Source) -> None:
    text = "first\x0cstill first\nsecond\u2028still second\r\nthird needle-x\rfourth\n"
    sid = add(store, text, src)
    snap = store.get_snapshot(sid)
    assert snap is not None
    assert snap.line_count == 4
    [hit] = store.search_text("needle-x", literal=True)
    assert hit.line_no == 3
    assert hit.text == "third needle-x"
    assert store.get_lines(sid, 2, 2) == ["second\u2028still second"]
    assert store.get_lines(sid, 1, 1) == ["first\x0cstill first"]


def test_find_prefix_relations(store: Store, src: Source) -> None:
    sid = add(
        store,
        "\n".join(
            [
                "a 192.0.2.0/24",
                "b 192.0.2.128/25",
                "c 192.0.2.130",
                "d 198.51.100.1",
                "e 0.0.0.0/0",
                "f 2001:db8::/32",
                "g 2001:db8:8000::1",
                "h ::/0",
                "i ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff0/124",
            ]
        )
        + "\n",
        src,
    )

    def lines(prefix: str, rel: str) -> list[int]:
        return [h.line_no for h in store.find_prefix(prefix, rel)]  # type: ignore[arg-type]

    assert lines("192.0.2.0/24", "inside") == [1, 2, 3]
    assert lines("192.0.2.128/25", "inside") == [2, 3]
    assert lines("192.0.2.130", "covering") == [1, 2, 3, 5]
    assert lines("192.0.2.128/25", "exact") == [2]
    assert lines("192.0.2.0/25", "overlaps") == [1, 5]
    assert lines("2001:db8::/32", "inside") == [6, 7]
    assert lines("2001:db8:8000::1", "covering") == [6, 7, 8]
    assert lines("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff5", "covering") == [8, 9]
    assert lines("ffff:ffff:ffff:ffff::/64", "inside") == [9]
    hit = store.find_prefix("192.0.2.0/24")[0]
    assert (hit.snapshot_id, hit.text, hit.matched) == (sid, "a 192.0.2.0/24", "192.0.2.0/24")
    with pytest.raises(ValueError):
        store.find_prefix("nonsense")
    with pytest.raises(ValueError):
        store.find_prefix("192.0.2.0/24", "bogus")  # type: ignore[arg-type]
    from ipaddress import ip_network

    assert len(store.find_prefix(ip_network("192.0.2.0/24"), limit=1)) == 1


def test_find_mac_asn_community_interface(loaded: tuple[Store, str]) -> None:
    store, sid = loaded
    assert [h.line_no for h in store.find_mac("00-00-5E-00-53-01")] == [5]
    assert [h.line_no for h in store.find_asn(64497)] == [8]
    assert [h.line_no for h in store.find_asn("AS65536")] == [9]
    assert [h.line_no for h in store.find_asn("64496")] == [7]
    assert [h.line_no for h in store.find_community("64496:100")] == [12]
    assert [h.line_no for h in store.find_interface("Gi0/0/1")] == [2]
    assert [h.line_no for h in store.find_interface("gigabitethernet0/0/1", "cisco_ios")] == [2]
    assert store.find_interface("Gi0/0/2") == []
    assert store.find_mac("00-00-5E-00-53-01")[0].snapshot_id == sid
    for bad in ("zz", "AS-1", "0", "99999999999"):
        with pytest.raises(ValueError):
            store.find_asn(bad)
    with pytest.raises(ValueError):
        store.find_mac("nope")


def test_well_known_community(store: Store, src: Source) -> None:
    add(store, "route-map X\n set community no-export additive\n", src)
    assert [h.line_no for h in store.find_community("No-Export")] == [2]


def test_sql_injection_is_inert(loaded: tuple[Store, str]) -> None:
    store, _ = loaded
    evil = "x'; DROP TABLE contents; --"
    assert store.search_text(evil, literal=True) == []
    assert store.find_community(evil) == []
    assert store.find_interface(evil) == []
    assert store._conn.execute("SELECT count(*) FROM contents").fetchone()[0] == 1


# -------------------------------------------------------------------------------- parsed


def test_parsed_roundtrip_and_guards(store: Store, src: Source, redactor: Redactor) -> None:
    sid = add(store, CONFIG, src)
    ref = SourceRef(snapshot_id=sid, line_start=1, line_end=1)
    cfg = ParsedConfig(
        snapshot_id=sid,
        vendor="cisco_ios",
        version=Version(ref=ref, software="IOS", version="15.2"),
    )
    store.add_parsed(cfg, plugin="cisco_ios")
    store.add_parsed(cfg, plugin="cisco_ios")  # replace, no duplicate
    assert store.get_parsed_config(sid, "cisco_ios") == cfg
    assert store.get_parsed_config(sid, "other") is None
    res = ParseResult(snapshot_id=sid, command="show version", vendor="cisco_ios")
    store.add_parsed(res, plugin="cisco_ios")
    assert store.get_parse_result(sid, "cisco_ios", "show version") == res
    assert store.get_parse_result(sid, "cisco_ios", "show other") is None
    assert store._conn.execute("SELECT count(*) FROM parsed").fetchone()[0] == 2

    ghost = ParsedConfig(snapshot_id="a" * 64)
    with pytest.raises(UnknownSnapshotError):
        store.add_parsed(ghost, plugin="p")
    leaky = ParseResult(snapshot_id=sid, command="enable secret=hunter2-test")
    with pytest.raises(UnredactedDataError):
        store.add_parsed(leaky, plugin="p")


# ------------------------------------------------------------------------------- secrets

SECRETS = ["0822455D0A16", "$9$abcDEF123xyz", "hunter2-test"]
SECRET_TEXT = """\
hostname r1
username admin password 7 0822455D0A16
snmp-server community public
set system root-authentication encrypted-password "$9$abcDEF123xyz"
radius-server host 192.0.2.9 key secret=hunter2-test
router bgp 64496
"""


def test_secrets_never_reach_storage(tmp_path: Path, src: Source, redactor: Redactor) -> None:
    path = tmp_path / "secrets.db"
    s = Source(kind="paste", uri="ssh://admin:hunter2-test@192.0.2.9/x", importer="t")
    with Store.open(path, redactor=redactor) as store:
        snap = store.add_snapshot(
            SECRET_TEXT,
            source=s,
            kind="config",
            captured_at=T0,
            hostname="r1",
            vendor="cisco_ios",
            command="show run | include secret=hunter2-test",
        )
        text = store.get_content(snap.id)
        assert text is not None
        assert not any(sec in text for sec in SECRETS)
        for sec in SECRETS:
            assert store.search_text(sec, literal=True) == []
            assert store.search_text(sec[:6], literal=True) == [] or sec[:6] in text
        assert store.search_text("password 7", literal=True)
        # every table, every column
        conn = store._conn
        for (table,) in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'lines_fts%'"
        ).fetchall():
            for row in conn.execute(f'SELECT * FROM "{table}"').fetchall():
                blob = " ".join(str(c) for c in row)
                assert not any(sec in blob for sec in SECRETS), table
        assert "secret=hunter2-test" not in (snap.command or "")
        assert snap.source.uri == "ssh://192.0.2.9/x"
        store._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    raw = b"".join(p.read_bytes() for p in tmp_path.glob("secrets.db*"))
    for sec in SECRETS:
        assert sec.encode() not in raw


def test_redactor_is_required() -> None:
    with pytest.raises(TypeError):
        Store.open(":memory:")  # type: ignore[call-arg]


# ------------------------------------------------------------------------------- performance


def test_performance_smoke(tmp_path: Path, src: Source, redactor: Redactor) -> None:
    lines = []
    for i in range(20_000):
        lines.append(
            f" neighbor 192.0.{2 + i % 200}.{i % 250 + 1} remote-as {64496 + i % 16}"
            f" description link-{i} Gi0/{i % 48}/{i % 4}"
            if i % 2
            else f"ip route 198.51.{i % 100}.0 255.255.255.0 203.0.113.{i % 250 + 1} # {i}"
        )
    text = "\n".join(lines) + "\n"
    with Store.open(tmp_path / "perf.db", redactor=redactor) as store:
        t = time.perf_counter()
        add(store, text, src)
        ingest = time.perf_counter() - t
        t = time.perf_counter()
        assert store.search_text("link-19999", literal=True)
        assert store.find_prefix("198.51.0.0/16", "inside")
        assert store.find_prefix("192.0.2.1", "covering") is not None
        assert store.find_asn(64501)
        assert store.find_interface("Gi0/1/1")
        assert store.find_mac("00-00-5E-00-53-01") == []
        assert store.find_community("64496:1") == []
        query = time.perf_counter() - t
    assert ingest < 60
    assert query < 20
