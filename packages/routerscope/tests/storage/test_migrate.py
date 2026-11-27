from __future__ import annotations

import importlib
import sqlite3
from pathlib import Path

import pytest
from routerscope.storage import (
    FtsUnavailableError,
    Migration,
    MigrationError,
    Redactor,
    SchemaTooNewError,
    Store,
    latest_version,
    load_migrations,
    migrate,
)
from routerscope.storage.migrate import check_sequence, schema_version
from routerscope.storage.store import check_fts5

MOD = importlib.import_module("routerscope.storage.migrate")


def _conn() -> sqlite3.Connection:
    return sqlite3.connect(":memory:", isolation_level=None)


def test_packaged_migrations_are_contiguous() -> None:
    migrations = load_migrations()
    assert migrations
    assert latest_version() == len(migrations)


def test_fresh_db_gets_latest_and_is_idempotent() -> None:
    conn = _conn()
    assert migrate(conn) == latest_version()
    assert migrate(conn) == latest_version()
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    assert {"sources", "contents", "observations", "snapshots", "lines_fts", "parsed"} <= names


V1 = Migration(1, "one", "CREATE TABLE t (id INTEGER PRIMARY KEY, a TEXT);")
V2 = Migration(2, "two", "ALTER TABLE t ADD COLUMN b TEXT DEFAULT 'x';\n-- comment\n")
V3 = Migration(
    3,
    "three",
    "CREATE TABLE u (n INTEGER);\n"
    "CREATE TRIGGER tg AFTER INSERT ON u BEGIN UPDATE u SET n = n + 1; END;\n",
)


@pytest.mark.parametrize("start", [0, 1, 2])
def test_each_older_version_upgrades_and_keeps_data(start: int) -> None:
    conn = _conn()
    if start >= 1:
        migrate(conn, [V1])
        conn.execute("INSERT INTO t (a) VALUES ('kept')")
    if start >= 2:
        migrate(conn, [V1, V2])
    assert schema_version(conn) == start
    assert migrate(conn, [V1, V2, V3]) == 3
    if start >= 1:
        assert conn.execute("SELECT a FROM t").fetchone()[0] == "kept"
    assert conn.execute("SELECT b FROM t").fetchall() in ([], [("x",)])


def test_real_v1_database_is_upgraded_by_later_migration(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path, isolation_level=None)
    migrate(conn)
    version = schema_version(conn)
    conn.execute("INSERT INTO sources (kind, uri, importer) VALUES ('paste', 'u', 'i')")
    later = Migration(version + 1, "extra", "CREATE TABLE extra (x INTEGER);")
    assert migrate(conn, [*load_migrations(), later]) == version + 1
    assert conn.execute("SELECT uri FROM sources").fetchone()[0] == "u"


def test_newer_database_is_refused(tmp_path: Path, redactor: Redactor) -> None:
    path = tmp_path / "new.db"
    conn = sqlite3.connect(path)
    conn.execute(f"PRAGMA user_version = {latest_version() + 5}")
    conn.close()
    with pytest.raises(SchemaTooNewError, match="newer"):
        Store.open(path, redactor=redactor)


def test_failed_migration_rolls_back() -> None:
    conn = _conn()
    bad = Migration(1, "bad", "CREATE TABLE ok (x);\nCREATE TABLE ok (x);")
    with pytest.raises(MigrationError):
        migrate(conn, [bad])
    assert schema_version(conn) == 0
    assert conn.execute("SELECT count(*) FROM sqlite_master").fetchone()[0] == 0
    assert not conn.in_transaction


def test_unterminated_statement_and_gaps_are_errors() -> None:
    with pytest.raises(MigrationError, match="unterminated"):
        migrate(_conn(), [Migration(1, "x", "CREATE TABLE t (a)")])
    with pytest.raises(MigrationError, match="contiguous"):
        check_sequence([Migration(2, "x", "")])


def test_non_sql_error_inside_migration_rolls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _conn()

    def boom(sql: str) -> list[str]:
        raise KeyboardInterrupt

    monkeypatch.setattr(MOD, "_statements", boom)
    with pytest.raises(KeyboardInterrupt):
        migrate(conn, [V1])
    assert not conn.in_transaction


def test_newer_version_seen_after_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _conn()
    calls = iter([0, 9])
    monkeypatch.setattr(MOD, "schema_version", lambda c: next(calls))
    with pytest.raises(SchemaTooNewError):
        migrate(conn, [V1])
    assert not conn.in_transaction


def test_missing_fts5_gives_clear_error() -> None:
    class Fake:
        def execute(self, sql: str) -> None:
            raise sqlite3.OperationalError("no such module: fts5")

    with pytest.raises(FtsUnavailableError, match="FTS5"):
        check_fts5(Fake())  # type: ignore[arg-type]


def test_open_sets_pragmas(tmp_path: Path, redactor: Redactor) -> None:
    with Store.open(tmp_path / "p.db", redactor=redactor) as store:
        assert store.schema_version == latest_version()
        conn = store._conn
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
