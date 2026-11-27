"""Regression tests for review findings: input validation, transactions, search, filters."""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from routerscope.model import ParsedConfig, Source
from routerscope.storage import (
    DatabaseBusyError,
    InvalidInputError,
    QuerySyntaxError,
    Redactor,
    StorageError,
    Store,
)
from routerscope.storage.store import _strip_uri_credentials

T0 = datetime(2025, 1, 1, 12, 0, tzinfo=UTC)


def add(
    store: Store,
    content: str,
    src: Source,
    at: datetime = T0,
    host: str | None = "r1",
    vendor: str | None = "cisco_ios",
    kind: str = "config",
    command: str | None = None,
) -> str:
    return store.add_snapshot(
        content,
        source=src,
        kind=kind,  # type: ignore[arg-type]
        captured_at=at,
        hostname=host,
        vendor=vendor,
        command=command,
    ).id


# ------------------------------------------------------------------------- 1. source URIs


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("https://user:p@ss/word@host/x", "https://host/x"),
        ("https://user:pa/ss@host/x", "https://host/x"),
        ("https://user:pw@host:8443/x?token=abc#frag", "https://host:8443/x"),
        ("ssh://admin@198.51.100.7/repo.git", "ssh://198.51.100.7/repo.git"),
        ("https://[2001:db8::1]:443/x?a=b", "https://[2001:db8::1]:443/x"),
        ("https://host:8080/a?email=x@y.example", "https://host:8080/a"),
        ("https://host/users/@name", "https://host/users/@name"),
        ("file:///etc/routers/a.cfg", "file:///etc/routers/a.cfg"),
        ("C:\\logs\\a.txt", "C:\\logs\\a.txt"),
        ("memory://t", "memory://t"),
        ("/var/log/a@b.txt", "/var/log/a@b.txt"),
        ("https://[bad/x?q=1", "https://[bad/x"),
    ],
)
def test_uri_credentials_stripped(uri: str, expected: str) -> None:
    assert _strip_uri_credentials(uri) == expected


def test_uri_and_importer_are_redacted_and_stored_clean(store: Store) -> None:
    s = Source(
        kind="paste",
        uri="https://u:p@ss/word@host/x?secret=abc",
        importer="imp secret=hunter2-test",
        git_commit="c0ffee secret=hunter2-test",
    )
    sid = add(store, "hostname r1\n", s)
    snap = store.get_snapshot(sid)
    assert snap is not None
    assert snap.source.uri == "https://host/x"
    assert snap.source.importer == "imp secret=<redacted>"
    assert snap.source.git_commit == "c0ffee secret=<redacted>"
    dump = " ".join(str(r) for r in store._conn.execute("SELECT * FROM sources"))
    assert "hunter2-test" not in dump
    assert "p@ss" not in dump
    assert "word" not in dump


def test_redactor_applies_to_plain_path_uri(tmp_path: Path) -> None:
    s = Source(kind="file", uri="C:\\logs\\secret=abc.txt", importer="t")
    with Store.open(tmp_path / "a.db", redactor=_fake) as store:
        snap = store.get_snapshot(add(store, "x\n", s))
    assert snap is not None
    assert snap.source.uri == "C:\\logs\\secret=<redacted>.txt"


def _fake(text: str, vendor: str | None) -> str:
    return text.replace("abc", "<redacted>")


# --------------------------------------------------------------------- 2. identifier checks


@pytest.mark.parametrize(
    "host",
    ["secret-host password 7 ABC", "a b", "host\nx", "h\u00e9", "x" * 256, "a;b", "a\ud800"],
)
def test_bad_hostname_rejected_and_not_stored(store: Store, src: Source, host: str) -> None:
    with pytest.raises(InvalidInputError):
        add(store, "x\n", src, host=host)
    assert store._conn.execute("SELECT count(*) FROM observations").fetchone()[0] == 0


def test_hostname_trimmed_and_blank_is_unknown(store: Store, src: Source) -> None:
    sid = add(store, "a\n", src, host="  r1.example:80/x@y  ")
    snap = store.get_snapshot(sid)
    assert snap is not None
    assert snap.hostname == "r1.example:80/x@y"
    blank = store.add_snapshot("b\n", source=src, kind="config", captured_at=T0, hostname="   ")
    assert blank.hostname is None
    assert len(store.history(" r1.example:80/x@y ")) == 1
    add(store, "c\n", src, host="x" * 255)


@pytest.mark.parametrize("vendor", ["Cisco", "cisco ios", "1abc", "", "a-b", "a\n"])
def test_bad_vendor_rejected(store: Store, src: Source, vendor: str) -> None:
    with pytest.raises(InvalidInputError):
        add(store, "x\n", src, vendor=vendor)


@pytest.mark.parametrize("plugin", ["Bad", "a b", "", "x;y"])
def test_bad_plugin_rejected(store: Store, src: Source, plugin: str) -> None:
    sid = add(store, "x\n", src)
    with pytest.raises(InvalidInputError):
        store.add_parsed(ParsedConfig(snapshot_id=sid), plugin=plugin)


def test_invalid_input_is_storage_and_value_error(store: Store, src: Source) -> None:
    with pytest.raises(StorageError):
        add(store, "x\n", src, host="a b")
    with pytest.raises(ValueError):
        add(store, "x\n", src, host="a b")
    with pytest.raises(InvalidInputError):
        store.search_text("abc", limit=0)
    with pytest.raises(InvalidInputError):
        store.snapshot_at("r1", datetime(2025, 1, 1))
    with pytest.raises(InvalidInputError):
        store.find_mac("nope")
    with pytest.raises(InvalidInputError):
        store.find_asn("ASx")
    with pytest.raises(InvalidInputError):
        store.find_prefix("nope")
    with pytest.raises(InvalidInputError):
        store.find_prefix("192.0.2.0/24", "sideways")  # type: ignore[arg-type]
    with pytest.raises(InvalidInputError):
        store.find_interface("  ")
    with pytest.raises(InvalidInputError):
        store.search_text("abc", kind="bogus")  # type: ignore[arg-type]
    with pytest.raises(InvalidInputError):
        store.search_text("abc", hostname="a b")
    with pytest.raises(InvalidInputError):
        store.add_snapshot("x", source=src, kind="bogus", captured_at=T0)  # type: ignore[arg-type]


# --------------------------------------------------------------------- 3. transactions


def test_failed_transaction_rolls_back_and_keeps_original_error(
    store: Store, src: Source, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Boom(RuntimeError):
        pass

    def boom(*_a: object, **_k: object) -> None:
        raise Boom("inner")

    monkeypatch.setattr(Store, "_insert_content", staticmethod(boom))
    with pytest.raises(Boom):
        add(store, "x\n", src)
    assert not store._conn.in_transaction
    assert store._conn.execute("SELECT count(*) FROM sources").fetchone()[0] == 0


def test_rollback_does_not_mask_error_when_already_rolled_back(
    store: Store, src: Source, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(conn: sqlite3.Connection, *_a: object) -> None:
        conn.execute("ROLLBACK")  # transaction gone before our handler runs
        raise KeyError("original")

    monkeypatch.setattr(Store, "_insert_content", staticmethod(boom))
    with pytest.raises(KeyError, match="original"):
        add(store, "x\n", src)
    monkeypatch.undo()
    add(store, "y\n", src)  # store still usable


def test_busy_database_raises_database_busy_error(
    tmp_path: Path, src: Source, redactor: Redactor
) -> None:
    path = tmp_path / "busy.db"
    with Store.open(path, redactor=redactor, timeout=0.05) as store:
        other = sqlite3.connect(str(path), isolation_level=None)
        try:
            other.execute("BEGIN IMMEDIATE")
            with pytest.raises(DatabaseBusyError):
                add(store, "x\n", src)
            assert not store._conn.in_transaction
            other.execute("ROLLBACK")
        finally:
            other.close()
        add(store, "x\n", src)
        assert issubclass(DatabaseBusyError, StorageError)


def test_busy_at_open_is_mapped(tmp_path: Path, redactor: Redactor) -> None:
    path = tmp_path / "busy2.db"
    Store.open(path, redactor=redactor).close()
    holder = sqlite3.connect(str(path), isolation_level=None)
    try:
        holder.execute("PRAGMA journal_mode = DELETE")
        holder.execute("BEGIN EXCLUSIVE")
        with pytest.raises(DatabaseBusyError):
            Store.open(path, redactor=redactor, timeout=0.05)
    finally:
        holder.close()


# --------------------------------------------------------------- 4. search errors, surrogates


def test_only_fts_syntax_errors_become_query_syntax_error(store: Store, src: Source) -> None:
    add(store, "route-policy X\n", src)
    for bad in ['"unbalanced', "foo:bar", "route-policy", "AND OR", "abc AND"]:
        with pytest.raises(QuerySyntaxError):
            store.search_text(bad)
    store._conn.execute("DROP TABLE lines_fts")
    with pytest.raises(sqlite3.OperationalError) as info:
        store.search_text("policy")
    assert not isinstance(info.value, QuerySyntaxError)


def test_lone_surrogates_do_not_crash(store: Store, src: Source) -> None:
    sid = add(store, "v\ud800 needle\n", src)
    assert store.get_content(sid) == "v? needle\n"
    sid2 = store.add_snapshot(
        "x\n",
        source=src,
        kind="command_output",
        captured_at=T0,
        hostname="r1",
        command="show \udfff",
    ).id
    snap = store.get_snapshot(sid2)
    assert snap is not None
    assert snap.command == "show ?"
    assert [h.line_no for h in store.search_text("needle\ud800", literal=True)] == []
    assert store.search_text("v\ud800 needle", literal=True)
    assert store.search_text("\ud800")  # short query: LIKE '?'
    assert store.history("r1", command="show \udfff")
    assert store.find_community("\ud800") == []
    assert store.find_interface("Gi0/1\ud800") == []


# ------------------------------------------------------------------- 5. short queries


def test_short_queries_use_like_fallback(store: Store, src: Source) -> None:
    sid = add(store, "ip route 10.0.0.0\nset a=1\n50% off_x\nback\\slash\n", src)
    assert [h.line_no for h in store.search_text("a=")] == [2]
    assert [h.line_no for h in store.search_text("IP")] == [1]  # case-insensitive
    assert [h.line_no for h in store.search_text(" a=1 ".strip()[:2])] == [2]
    assert [h.line_no for h in store.search_text("%")] == [3]
    assert [h.line_no for h in store.search_text("_x")] == [3]
    assert [h.line_no for h in store.search_text("\\")] == [4]
    assert store.search_text("zz") == []
    hits = store.search_text("o", limit=2)
    assert len(hits) == 2
    assert all(h.snapshot_id == sid and "o" in h.text.lower() for h in hits)
    assert store.search_text("a=", hostname="r1")
    assert store.search_text("a=", hostname="nobody") == []


# --------------------------------------------------- 6. lines table, FTS rowids, ordering


def test_lines_table_serves_text_and_matches_split_lines(store: Store, src: Source) -> None:
    text = "one\n\n  three needle-q  \r\nfour\rfive"
    sid = add(store, text, src)
    assert store.get_lines(sid, 1, 5) == ["one", "", "  three needle-q  ", "four", "five"]
    assert store.get_lines(sid, 0, 2) == ["one", ""]
    assert store.get_lines(sid, 4, 99) == ["four", "five"]
    assert store.get_lines(sid, 9, 12) == []
    [hit] = store.search_text("needle-q", literal=True)
    assert (hit.line_no, hit.text) == (3, "  three needle-q  ")
    # blank lines are stored but not indexed
    assert store._conn.execute("SELECT count(*) FROM lines").fetchone()[0] == 5
    assert store._conn.execute("SELECT count(*) FROM lines_fts_docsize").fetchone()[0] == 4


def test_fts_rowids_are_line_ids_and_never_collide(store: Store, src: Source) -> None:
    for i in range(5):
        add(store, f"alpha {i}\nbeta {i}\n\ngamma {i}\n", src, host=f"h{i}")
    ids = [r[0] for r in store._conn.execute("SELECT id FROM lines ORDER BY id")]
    assert ids == sorted(set(ids))
    indexed = {r[0] for r in store._conn.execute("SELECT rowid FROM lines_fts")}
    assert indexed <= set(ids)
    assert len(store.search_text("gamma 3", literal=True)) == 1
    assert len(store.search_text("beta", limit=50)) == 5


def test_search_does_not_issue_per_hit_queries(store: Store, src: Source) -> None:
    for i in range(30):
        add(store, f"needle line {i}\nother\n", src, host=f"h{i}")
    statements: list[str] = []
    store._conn.set_trace_callback(statements.append)
    try:
        assert len(store.search_text("needle", limit=100)) == 30
        assert len(store.search_text("needle", limit=5)) == 5
    finally:
        store._conn.set_trace_callback(None)
    top_level = [q for q in statements if not q.startswith("-- ")]
    assert len(top_level) <= 3


def test_find_results_ordered_by_recency_then_line(store: Store, src: Source) -> None:
    # content hashes are unrelated to recency; ids chosen so hash order would differ
    old = add(store, "ip route 192.0.2.5\nip route 192.0.2.6\n", src, T0, host="a")
    new = add(store, "x\nip route 192.0.2.7\n! 192.0.2.8\n", src, T0 + timedelta(days=1), host="b")
    mid = add(store, "ip route 192.0.2.9\n", src, T0 + timedelta(hours=1), host="c")
    got = [(h.snapshot_id, h.line_no) for h in store.find_prefix("192.0.2.0/24")]
    assert got == [(new, 2), (new, 3), (mid, 1), (old, 1), (old, 2)]


# ------------------------------------------------- 7. observation uniqueness, history("")


def test_observation_uniqueness_includes_vendor(store: Store, src: Source) -> None:
    sid = add(store, "x\n", src, vendor="cisco_ios")
    add(store, "x\n", src, vendor="huawei_vrp")
    add(store, "x\n", src, vendor="huawei_vrp")  # exact duplicate: ignored
    add(store, "x\n", src, vendor=None)
    add(store, "x\n", src, vendor=None)  # NULL-vendor duplicates are ignored too
    obs = store.observations(sid)
    assert sorted(o.vendor or "" for o in obs) == ["", "cisco_ios", "huawei_vrp"]


def test_history_rejects_empty_hostname(store: Store) -> None:
    for bad in ("", "   "):
        with pytest.raises(InvalidInputError):
            store.history(bad)
        with pytest.raises(InvalidInputError):
            store.snapshot_at(bad, T0)


# --------------------------------------------------------------------------- 8. threads


def test_store_is_usable_from_many_threads(tmp_path: Path, src: Source, redactor: Redactor) -> None:
    errors: list[BaseException] = []
    with Store.open(tmp_path / "t.db", redactor=redactor) as store:

        def work(n: int) -> None:
            try:
                for i in range(10):
                    sid = add(store, f"thread {n} line {i}\n", src, host=f"h{n}")
                    assert store.get_content(sid) is not None
                    store.search_text("thread", limit=5)
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        assert store._conn.execute("SELECT count(*) FROM contents").fetchone()[0] == 80
        assert store.schema_version >= 1


# ------------------------------------------------------- 9. hit metadata and filters


def test_hits_carry_latest_observation(store: Store, src: Source) -> None:
    text = "hostname r1\nip route 192.0.2.1\n"
    add(store, text, src, T0, host="r1")
    add(store, text, src, T0 + timedelta(days=2), host="r2", kind="command_output", command="sh r")
    for hits in (store.search_text("192.0.2.1", literal=True), store.find_prefix("192.0.2.1")):
        [h] = hits
        assert h.hostname == "r2"
        assert h.captured_at == T0 + timedelta(days=2)
        assert h.kind == "command_output"
        assert h.command == "sh r"
    [h] = store.search_text("192.0.2.1", literal=True, hostname="R1")
    assert (h.hostname, h.kind, h.command, h.captured_at) == ("r1", "config", None, T0)
    [h] = store.find_prefix("192.0.2.1", kind="config")
    assert h.hostname == "r1"
    assert store.search_text("192.0.2.1", literal=True, kind="session") == []
    assert store.find_prefix("192.0.2.1", hostname="zz") == []


def test_latest_only_filters_superseded_contents(store: Store, src: Source) -> None:
    v1 = "ip route 192.0.2.1\nrouter bgp 64496\n set a=1\n set b=1\n"
    v2 = "ip route 192.0.2.1\nrouter bgp 64497\n set a=2\n set b=2\n"
    add(store, v1, src, T0, host="r1")
    add(store, v2, src, T0 + timedelta(days=1), host="r1")
    add(store, v1, src, T0, host="r2")  # r2 still on v1: v1 is its latest
    add(store, "ip route 192.0.2.1 anon-1\n", src, T0, host=None)  # unknown host never superseded
    add(store, "ip route 192.0.2.1 anon-2\n", src, T0 + timedelta(days=3), host=None)
    everything = store.find_prefix("192.0.2.1")
    latest = store.find_prefix("192.0.2.1", latest_only=True)
    assert len(everything) == 4
    assert len(latest) == 4  # v1 (via r2), v2 (via r1), both anonymous
    only_r1 = store.find_prefix("192.0.2.1", hostname="r1", latest_only=True)
    assert [h.text for h in only_r1] == ["ip route 192.0.2.1"]
    assert {h.captured_at for h in only_r1} == {T0 + timedelta(days=1)}
    only = store.search_text("router bgp 6449", latest_only=True, hostname="r1")
    assert [h.text for h in only] == ["router bgp 64497"]
    assert store.search_text("router bgp 64496", hostname="r1", latest_only=True) == []
    assert [h.text for h in store.search_text("router bgp 64496", hostname="r1")] == [
        "router bgp 64496"
    ]
    assert store.find_asn(64496, hostname="r1", latest_only=True) == []
    assert len(store.find_asn(64496, hostname="r1")) == 1
    assert store.find_community("no-export", latest_only=True) == []
    assert store.find_mac("00:00:5e:00:53:01", latest_only=True) == []
    assert store.find_interface("Gi0/1", latest_only=True) == []


def test_latest_only_is_per_command(store: Store, src: Source) -> None:
    add(store, "a 192.0.2.1\n", src, T0, kind="command_output", command="show a")
    add(
        store,
        "b 192.0.2.1\n",
        src,
        T0 + timedelta(hours=1),
        kind="command_output",
        command="show b",
    )
    assert len(store.find_prefix("192.0.2.1", latest_only=True)) == 2
    add(
        store,
        "a2 192.0.2.1\n",
        src,
        T0 + timedelta(hours=2),
        kind="command_output",
        command="show a",
    )
    texts = sorted(h.text for h in store.find_prefix("192.0.2.1", latest_only=True))
    assert texts == ["a2 192.0.2.1", "b 192.0.2.1"]
