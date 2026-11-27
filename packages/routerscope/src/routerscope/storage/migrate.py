"""Schema migrations driven by ``PRAGMA user_version``.

Migrations are SQL files named ``NNNN_name.sql`` in ``storage/migrations/`` (shipped as package
data). Version numbers start at 1 and must be contiguous. :func:`migrate` applies every
migration above the database's ``user_version`` inside one ``BEGIN IMMEDIATE`` transaction
(SQLite DDL is transactional), so a failed upgrade leaves the database untouched. It is
idempotent and safe against two processes upgrading at once (the version is re-read after the
lock is taken). A database whose version is above the latest known one is refused.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from importlib import resources

from routerscope.storage.errors import MigrationError, SchemaTooNewError

_NAME_RE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")


@dataclass(frozen=True, slots=True)
class Migration:
    """One schema step: applying it moves ``user_version`` to ``version``."""

    version: int
    name: str
    sql: str


def load_migrations() -> tuple[Migration, ...]:
    """Load the packaged migrations, ordered, checking versions are 1..N without gaps."""
    found: list[Migration] = []
    folder = resources.files("routerscope.storage") / "migrations"
    for entry in folder.iterdir():
        match = _NAME_RE.match(entry.name)
        if match is None:
            continue
        found.append(Migration(int(match[1]), match[2], entry.read_text(encoding="utf-8")))
    found.sort(key=lambda m: m.version)
    check_sequence(found)
    return tuple(found)


def check_sequence(migrations: Sequence[Migration]) -> None:
    """Raise :class:`MigrationError` unless versions are exactly 1..N in order."""
    for expected, migration in enumerate(migrations, start=1):
        if migration.version != expected:
            raise MigrationError(
                f"migration versions must be contiguous from 1: expected {expected}, "
                f"found {migration.version} ({migration.name})"
            )


def latest_version(migrations: Sequence[Migration] | None = None) -> int:
    """Highest schema version known to this build."""
    return len(load_migrations() if migrations is None else migrations)


def schema_version(conn: sqlite3.Connection) -> int:
    """Current ``user_version`` of the connection's database."""
    row = conn.execute("PRAGMA user_version").fetchone()
    return int(row[0])


def _statements(sql: str) -> Iterator[str]:
    buf = ""
    for line in sql.splitlines(keepends=True):
        buf += line
        if sqlite3.complete_statement(buf):
            yield buf.strip()
            buf = ""
    if any(ln.strip() and not ln.strip().startswith("--") for ln in buf.splitlines()):
        raise MigrationError("migration ends with an unterminated statement")


def _too_new(current: int, latest: int) -> SchemaTooNewError:
    return SchemaTooNewError(
        f"database schema version {current} is newer than this routerscope supports "
        f"({latest}); upgrade routerscope"
    )


def migrate(conn: sqlite3.Connection, migrations: Sequence[Migration] | None = None) -> int:
    """Bring the database up to the latest schema and return the resulting version.

    ``conn`` must be in autocommit mode (``isolation_level=None``). ``migrations`` defaults to
    the packaged ones; tests pass their own chain.
    """
    chain = load_migrations() if migrations is None else tuple(migrations)
    check_sequence(chain)
    latest = len(chain)
    current = schema_version(conn)
    if current > latest:
        raise _too_new(current, latest)
    if current == latest:
        return current
    conn.execute("BEGIN IMMEDIATE")
    try:
        current = schema_version(conn)  # re-read under the write lock
        if current > latest:
            raise _too_new(current, latest)
        for migration in chain[current:]:
            for statement in _statements(migration.sql):
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version = {int(migration.version)}")
        conn.execute("COMMIT")
    except sqlite3.Error as exc:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise MigrationError(f"migration failed: {exc}") from exc
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    return schema_version(conn)
