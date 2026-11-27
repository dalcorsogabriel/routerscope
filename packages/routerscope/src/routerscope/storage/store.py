"""SQLite store: versioned snapshots, full-text index, typed side tables, parsed objects.

Raw, unredacted content is never persisted: ``add_snapshot`` runs the (required) redactor first
and everything stored or indexed, including the snapshot id, derives from the redacted text.

Text handling: every ``str`` handed to the store is encoded as UTF-8 with
``errors="replace"`` (a lone surrogate such as ``"\\ud800"`` becomes ``"?"``) before it is
hashed, stored, indexed or searched, so such input never crashes and is treated the same
everywhere. Bytes content is decoded the same way (undecodable bytes become U+FFFD).

Thread safety: the connection is shared (``check_same_thread=False``) and every public
operation holds one re-entrant lock, so a :class:`Store` may be used from several threads;
operations are serialized, not parallel.
"""

from __future__ import annotations

import functools
import re
import sqlite3
import threading
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Concatenate, Literal, Self, get_args
from urllib.parse import urlsplit

from netaddr_search import (
    normalize_interface,
    normalize_mac,
    parse_network,
    query_params,
    sql_fragments,
)
from netaddr_search.ip import Network, bounds
from pydantic import ValidationError

from routerscope.model import (
    ParsedConfig,
    ParseResult,
    Snapshot,
    SnapshotKind,
    Source,
    make_snapshot,
    split_lines,
)
from routerscope.model._base import VENDOR_ID_PATTERN
from routerscope.storage.errors import (
    DatabaseBusyError,
    FtsUnavailableError,
    InvalidInputError,
    QuerySyntaxError,
    UnknownSnapshotError,
    UnredactedDataError,
)
from routerscope.storage.extract import extract_rows
from routerscope.storage.migrate import migrate, schema_version

Redactor = Callable[[str, str | None], str]
"""``redactor(text, vendor) -> text`` with secrets removed. Must be deterministic."""

PrefixRelation = Literal["inside", "covering", "overlaps", "exact"]

_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*")
_HOSTNAME = re.compile(r"[A-Za-z0-9_.:/@-]{1,255}")
_VENDOR = re.compile(VENDOR_ID_PATTERN)
_KINDS: tuple[str, ...] = get_args(SnapshotKind)
_FTS_ERRORS = (
    "fts5:",
    "syntax error",
    "unterminated string",
    "no such column",
    "unknown special query",
    "malformed match",
)
_MIN_FTS_CHARS = 3  # trigram tokenizer minimum; shorter queries use the LIKE fallback


@dataclass(frozen=True, slots=True)
class Hit:
    """One matching line, with the latest observation of its content.

    ``snapshot_id`` is the content hash, ``line_no`` is 1-based. ``hostname``, ``captured_at``,
    ``kind`` and ``command`` come from the newest observation of that content that satisfies
    the search filters (``hostname`` is None when unknown, ``command`` None when absent).
    """

    snapshot_id: str
    line_no: int
    text: str
    hostname: str | None
    captured_at: datetime
    kind: SnapshotKind
    command: str | None
    matched: str | None = None


@dataclass(frozen=True, slots=True)
class DeviceSummary:
    """A hostname seen in observations."""

    hostname: str
    vendor: str | None
    observations: int
    first_seen: datetime
    last_seen: datetime


def _clean(text: str) -> str:
    """Make ``text`` encodable as UTF-8 (lone surrogates become ``?``)."""
    return text.encode("utf-8", errors="replace").decode("utf-8")


def _fmt_ts(value: datetime) -> str:
    if value.tzinfo is None:
        raise InvalidInputError("datetime must be timezone-aware")
    return value.astimezone(UTC).strftime(_TS_FORMAT)


def _parse_ts(value: str) -> datetime:
    return datetime.strptime(value, _TS_FORMAT).replace(tzinfo=UTC)


def _hostname(value: str) -> str:
    """Trimmed, validated hostname (letters, digits and ``-_.:/@``; at most 255 chars)."""
    host = value.strip()
    if not host:
        raise InvalidInputError("hostname must not be empty")
    if not _HOSTNAME.fullmatch(host):
        raise InvalidInputError(
            "invalid hostname: use letters, digits and '-_.:/@' only (max 255 characters)"
        )
    return host


def _vendor_id(value: str, what: str) -> str:
    if not _VENDOR.fullmatch(value):
        raise InvalidInputError(f"invalid {what} id: must match {VENDOR_ID_PATTERN}")
    return value


def _kind(value: str) -> str:
    if value not in _KINDS:
        raise InvalidInputError(f"invalid kind {value!r}; expected one of {_KINDS}")
    return value


def _strip_uri_credentials(uri: str) -> str:
    r"""Drop userinfo, query and fragment from ``scheme://...`` URIs; keep anything else as is.

    Userinfo may contain unescaped ``@`` and ``/``. When the authority looks like userinfo
    (it has an ``@``, or ``name:text`` that is not ``host:port``) and an ``@`` occurs anywhere
    after the scheme, everything up to the *last* ``@`` is dropped: secrecy wins over keeping a
    path that happens to contain ``@``. Windows paths (``C:\logs\a.txt``) and other non-URL
    strings are returned unchanged.
    """
    scheme, sep, rest = uri.partition("://")
    if not sep or not _SCHEME.fullmatch(scheme):
        return uri
    netloc = re.split(r"[/?#]", rest, maxsplit=1)[0]
    looks_like_userinfo = "@" in netloc or (
        not netloc.startswith("[") and ":" in netloc and not netloc.rpartition(":")[2].isdigit()
    )
    if looks_like_userinfo and "@" in rest:
        rest = rest[rest.rindex("@") + 1 :]
    try:
        parts = urlsplit(f"{scheme}://{rest}")
    except ValueError:
        return f"{scheme}://{re.split(r'[?#]', rest, maxsplit=1)[0]}"
    return f"{scheme}://{parts.netloc.rpartition('@')[2]}{parts.path}"


def _is_busy(exc: sqlite3.OperationalError) -> bool:
    # sqlite_errorcode exists since Python 3.11; the low byte is the primary result code.
    return (exc.sqlite_errorcode & 0xFF) in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)


def _serialized[S, **P, R](fn: Callable[Concatenate[S, P], R]) -> Callable[Concatenate[S, P], R]:
    """Run a Store method under the store lock; map busy/locked errors to DatabaseBusyError."""

    @functools.wraps(fn)
    def wrapper(self: S, *args: P.args, **kwargs: P.kwargs) -> R:
        with self._lock:  # type: ignore[attr-defined]
            try:
                return fn(self, *args, **kwargs)
            except sqlite3.OperationalError as exc:
                if _is_busy(exc):
                    raise DatabaseBusyError(f"database is busy: {exc}") from exc
                raise

    return wrapper  # type: ignore[return-value]


def check_fts5(conn: sqlite3.Connection) -> None:
    """Raise :class:`FtsUnavailableError` unless FTS5 with the trigram tokenizer works."""
    try:
        conn.execute("CREATE VIRTUAL TABLE temp.rs_fts_probe USING fts5(x, tokenize='trigram')")
    except sqlite3.OperationalError as exc:
        raise FtsUnavailableError(
            f"this SQLite build (version {sqlite3.sqlite_version}) lacks FTS5 with the trigram "
            f"tokenizer ({exc}); install Python with SQLite >= 3.34 compiled with FTS5"
        ) from exc
    conn.execute("DROP TABLE temp.rs_fts_probe")


def quote_fts_literal(text: str) -> str:
    """Quote ``text`` as one FTS5 phrase (so ``route-policy`` or ``0/0/1`` are not syntax)."""
    return '"' + text.replace('"', '""') + '"'


_FTS_OPERATORS = re.compile(r'["()*^:]|\b(?:AND|OR|NOT|NEAR)\b')


def _balanced(text: str) -> bool:
    """Quotes pair up and parentheses outside quotes nest properly."""
    depth, quoted = 0, False
    for char in text:
        if char == '"':
            quoted = not quoted
        elif not quoted and char == "(":
            depth += 1
        elif not quoted and char == ")":
            depth -= 1
            if depth < 0:
                return False
    return not quoted and depth == 0


def auto_fts_query(text: str) -> str:
    """Plain words (no FTS operators) become literal terms, ANDed.

    ``route-policy PASS`` searches for both terms as written; a ``-`` or ``/`` is never read as
    FTS syntax. Queries with quotes, parentheses, ``*``, ``^``, ``:`` or the upper-case
    operators ``AND``/``OR``/``NOT``/``NEAR`` are passed to FTS5 unchanged.
    """
    if _FTS_OPERATORS.search(text):
        return text
    return " ".join(quote_fts_literal(word) for word in text.split())


def _strings(value: object) -> Iterator[str]:
    """Every string inside a JSON-like structure (dict keys included)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(key)
            yield from _strings(item)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from _strings(item)


def _like_pattern(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


class _Filter:
    """Observation filters shared by every search: which observation represents a content."""

    def __init__(self, hostname: str | None, kind: str | None, latest_only: bool) -> None:
        self.params: dict[str, object] = {}
        sql = ""
        if hostname is not None:
            sql += " AND o2.hostname = :f_host"
            self.params["f_host"] = _hostname(hostname)
        if kind is not None:
            sql += " AND o2.kind = :f_kind"
            self.params["f_kind"] = _kind(kind)
        if latest_only:
            # Newest observation per (hostname, kind, command). Observations without a
            # hostname cannot be grouped, so they are never treated as superseded.
            sql += (
                " AND (o2.hostname = '' OR NOT EXISTS (SELECT 1 FROM observations n"
                " WHERE n.hostname = o2.hostname AND n.kind = o2.kind"
                " AND n.command = o2.command AND (n.captured_at > o2.captured_at"
                " OR (n.captured_at = o2.captured_at AND n.id > o2.id))))"
            )
        self._sql = sql

    def pick(self, content_id: str) -> str:
        """SQL expression: id of the newest qualifying observation of ``content_id``."""
        return (
            "(SELECT o2.id FROM observations o2 WHERE o2.content_id = "
            f"{content_id}{self._sql} ORDER BY o2.captured_at DESC, o2.id DESC LIMIT 1)"
        )


_HIT_COLUMNS = "l.text, o.hostname, o.captured_at, o.kind, o.command"


class Store:
    """A routerscope database. Use :meth:`open`. Thread-safe: operations are serialized."""

    def __init__(self, conn: sqlite3.Connection, redactor: Redactor) -> None:
        self._conn = conn
        self._redactor = redactor
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ lifecycle

    @classmethod
    def open(cls, path: str | Path, *, redactor: Redactor, timeout: float = 30.0) -> Self:
        """Open (creating and migrating if needed) the database at ``path``.

        ``redactor`` is required: there is deliberately no default, so nothing can be stored
        unredacted by omission. ``":memory:"`` gives a throwaway database. ``timeout`` is how
        long to wait for another connection's lock before :class:`DatabaseBusyError`.
        """
        conn = sqlite3.connect(
            str(path), isolation_level=None, timeout=timeout, check_same_thread=False
        )
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            check_fts5(conn)
            migrate(conn)
        except BaseException as exc:
            conn.close()
            if isinstance(exc, sqlite3.OperationalError) and _is_busy(exc):
                raise DatabaseBusyError(f"database is busy: {exc}") from exc
            raise
        return cls(conn, redactor)

    def close(self) -> None:
        """Close the connection (idempotent)."""
        with self._lock:
            self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    @property
    @_serialized
    def schema_version(self) -> int:
        """The ``user_version`` of the open database."""
        return schema_version(self._conn)

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            # SQLite may already have rolled back (e.g. after some errors); never let a
            # failing ROLLBACK hide the original exception.
            if conn.in_transaction:
                with suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
            raise

    # ------------------------------------------------------------------ writing

    def _clean_source(self, source: Source) -> Source:
        return source.model_copy(
            update={
                "uri": self._redactor(_strip_uri_credentials(_clean(source.uri)), None),
                "importer": self._redactor(_clean(source.importer), None),
                "git_commit": (
                    None
                    if source.git_commit is None
                    else self._redactor(_clean(source.git_commit), None)
                ),
            }
        )

    @_serialized
    def add_snapshot(
        self,
        content: str | bytes,
        *,
        source: Source,
        kind: SnapshotKind,
        captured_at: datetime,
        hostname: str | None = None,
        vendor: str | None = None,
        command: str | None = None,
    ) -> Snapshot:
        """Redact, store and index ``content``; return the resulting :class:`Snapshot`.

        The snapshot id is the sha256 of the *redacted* text. Identical redacted content is
        stored and indexed once; seeing it again (other host, time, vendor or source) only adds
        an observation, and re-adding the very same observation is a no-op. ``hostname`` is
        trimmed (blank means unknown) and validated (letters, digits, ``-_.:/@``, at most 255
        characters) and ``vendor`` must be a vendor id (``^[a-z][a-z0-9_]*$``), otherwise
        :class:`InvalidInputError` is raised. Credentials embedded in ``source.uri``
        (``scheme://user:pass@host``) are dropped with the query and fragment; the URI,
        ``source.importer``, ``source.git_commit`` and ``command`` also go through the
        redactor. Everything happens in one transaction.
        """
        host = _hostname(hostname) if hostname is not None and hostname.strip() else None
        vendor_id = None if vendor is None else _vendor_id(vendor, "vendor")
        raw = _clean(content) if isinstance(content, str) else content.decode("utf-8", "replace")
        text = _clean(self._redactor(raw, vendor_id))
        del raw
        clean_command = _clean(self._redactor(_clean(command), vendor_id)) if command else None
        clean_source = self._clean_source(source)
        _fmt_ts(captured_at)
        try:
            snapshot = make_snapshot(
                text,
                source=clean_source,
                kind=kind,
                captured_at=captured_at,
                hostname=host,
                vendor=vendor_id,
                command=clean_command,
            )
        except ValidationError as exc:
            raise InvalidInputError(f"invalid snapshot metadata: {exc}") from exc
        with self._tx() as conn:
            source_id = self._source_id(conn, clean_source)
            if not conn.execute("SELECT 1 FROM contents WHERE id = ?", (snapshot.id,)).fetchone():
                self._insert_content(conn, snapshot, text, vendor_id)
            conn.execute(
                "INSERT OR IGNORE INTO observations"
                " (content_id, hostname, vendor, kind, command, captured_at, source_id)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    snapshot.id,
                    host or "",
                    vendor_id or "",
                    kind,
                    clean_command or "",
                    _fmt_ts(snapshot.captured_at),
                    source_id,
                ),
            )
        return snapshot

    @staticmethod
    def _source_id(conn: sqlite3.Connection, source: Source) -> int:
        key = (source.kind, source.uri, source.importer, source.git_commit or "")
        conn.execute(
            "INSERT OR IGNORE INTO sources (kind, uri, importer, git_commit) VALUES (?, ?, ?, ?)",
            key,
        )
        row = conn.execute(
            "SELECT id FROM sources WHERE kind = ? AND uri = ? AND importer = ? AND git_commit = ?",
            key,
        ).fetchone()
        return int(row[0])

    @staticmethod
    def _insert_content(
        conn: sqlite3.Connection, snapshot: Snapshot, text: str, vendor: str | None
    ) -> None:
        lines = split_lines(text)
        cid = snapshot.id
        conn.execute(
            "INSERT INTO contents (id, text, size, line_count) VALUES (?, ?, ?, ?)",
            (cid, text, snapshot.size, snapshot.line_count),
        )
        conn.executemany(
            "INSERT INTO lines (content_id, line_no, text) VALUES (?, ?, ?)",
            ((cid, n, line) for n, line in enumerate(lines, 1)),
        )
        # External-content FTS5: index the rows just inserted (rowid = lines.id, never reused).
        conn.execute(
            "INSERT INTO lines_fts (rowid, text) SELECT id, text FROM lines"
            " WHERE content_id = ? AND trim(text, char(9, 10, 13, 32)) <> ''",
            (cid,),
        )
        rows = extract_rows(lines, vendor)
        conn.executemany(
            'INSERT INTO ip_addrs (content_id, line_no, version, start, "end", address,'
            " network, kind) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ((cid, *r) for r in rows.ips),
        )
        conn.executemany(
            "INSERT INTO macs (content_id, line_no, mac) VALUES (?, ?, ?)",
            ((cid, *r) for r in rows.macs),
        )
        conn.executemany(
            "INSERT INTO asns (content_id, line_no, asn, context) VALUES (?, ?, ?, ?)",
            ((cid, *r) for r in rows.asns),
        )
        conn.executemany(
            "INSERT INTO communities (content_id, line_no, community, kind) VALUES (?, ?, ?, ?)",
            ((cid, *r) for r in rows.communities),
        )
        conn.executemany(
            "INSERT INTO interfaces (content_id, line_no, raw, normalized, norm_key)"
            " VALUES (?, ?, ?, ?, ?)",
            ((cid, ln, raw, norm, norm.lower()) for ln, raw, norm in rows.interfaces),
        )

    @_serialized
    def add_parsed(self, parsed: ParsedConfig | ParseResult, *, plugin: str) -> None:
        """Store (or replace) parser output for a stored snapshot and plugin id.

        ``plugin`` must be a vendor-style id (``^[a-z][a-z0-9_]*$``). Parsers must run on the
        stored (redacted) text from :meth:`get_content`. As a second line of defence every
        string value (line by line) goes through the redactor, and the data is refused with
        :class:`UnredactedDataError` if the redactor would change any of them.
        """
        _vendor_id(plugin, "plugin")
        if not self._has_content(parsed.snapshot_id):
            raise UnknownSnapshotError(f"snapshot {parsed.snapshot_id[:12]} is not stored")
        data = parsed.model_dump_json()
        # The redactor is line-oriented, so check every string value on its own rather than
        # the single-line JSON (where a value's tail would run into the next field).
        for value in _strings(parsed.model_dump(mode="json")):
            if any(self._redactor(line, parsed.vendor) != line for line in value.splitlines()):
                raise UnredactedDataError(
                    "parsed data still contains secrets; parse the redacted text from the store"
                )
        kind, command = (
            ("config", "")
            if isinstance(parsed, ParsedConfig)
            else (
                "result",
                parsed.command,
            )
        )
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO parsed (content_id, plugin, kind, command, data)"
                " VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT (content_id, plugin, kind, command)"
                " DO UPDATE SET data = excluded.data",
                (parsed.snapshot_id, plugin, kind, command, data),
            )

    # ------------------------------------------------------------------ reading

    def _has_content(self, snapshot_id: str) -> bool:
        return (
            self._conn.execute("SELECT 1 FROM contents WHERE id = ?", (snapshot_id,)).fetchone()
            is not None
        )

    @_serialized
    def get_parsed_config(self, snapshot_id: str, plugin: str) -> ParsedConfig | None:
        """Parsed config stored by ``plugin`` for the snapshot, if any."""
        row = self._conn.execute(
            "SELECT data FROM parsed WHERE content_id = ? AND plugin = ? AND kind = 'config'",
            (snapshot_id, plugin),
        ).fetchone()
        return None if row is None else ParsedConfig.model_validate_json(row[0])

    @_serialized
    def get_parse_result(self, snapshot_id: str, plugin: str, command: str) -> ParseResult | None:
        """Command parse result stored by ``plugin`` for the snapshot, if any."""
        row = self._conn.execute(
            "SELECT data FROM parsed WHERE content_id = ? AND plugin = ?"
            " AND kind = 'result' AND command = ?",
            (snapshot_id, plugin, command),
        ).fetchone()
        return None if row is None else ParseResult.model_validate_json(row[0])

    @_serialized
    def get_content(self, snapshot_id: str) -> str | None:
        """The stored (redacted) text of a snapshot, or None."""
        row = self._conn.execute(
            "SELECT text FROM contents WHERE id = ?", (snapshot_id,)
        ).fetchone()
        return None if row is None else str(row[0])

    @_serialized
    def get_lines(self, snapshot_id: str, first: int, last: int) -> list[str]:
        """Lines ``first``..``last`` (1-based, inclusive) of a snapshot; [] if unknown.

        Served from the ``lines`` table; the whole content is not loaded or re-split.
        """
        if first > last:
            return []
        rows = self._conn.execute(
            "SELECT text FROM lines WHERE content_id = ? AND line_no BETWEEN ? AND ?"
            " ORDER BY line_no",
            (snapshot_id, max(first, 1), last),
        ).fetchall()
        return [str(r[0]) for r in rows]

    _SNAPSHOT_SELECT = (
        "SELECT id, hostname, vendor, kind, command, captured_at, source_kind, source_uri,"
        " source_importer, source_git_commit, size, line_count FROM snapshots"
    )

    @staticmethod
    def _to_snapshot(row: Sequence[object]) -> Snapshot:
        return Snapshot(
            id=str(row[0]),
            hostname=str(row[1]) or None,
            vendor=str(row[2]) or None,
            kind=row[3],  # type: ignore[arg-type]
            command=str(row[4]) or None,
            captured_at=_parse_ts(str(row[5])),
            source=Source(
                kind=row[6],  # type: ignore[arg-type]
                uri=str(row[7]),
                importer=str(row[8]),
                git_commit=str(row[9]) or None,
            ),
            size=int(row[10]),  # type: ignore[call-overload]
            line_count=int(row[11]),  # type: ignore[call-overload]
        )

    @_serialized
    def get_snapshot(self, snapshot_id: str) -> Snapshot | None:
        """The most recent observation of a snapshot id, or None."""
        row = self._conn.execute(
            f"{self._SNAPSHOT_SELECT} WHERE id = ? ORDER BY captured_at DESC, observation_id DESC"
            " LIMIT 1",
            (snapshot_id,),
        ).fetchone()
        return None if row is None else self._to_snapshot(row)

    @_serialized
    def observations(self, snapshot_id: str) -> list[Snapshot]:
        """Every observation of a snapshot id, oldest first."""
        rows = self._conn.execute(
            f"{self._SNAPSHOT_SELECT} WHERE id = ? ORDER BY captured_at, observation_id",
            (snapshot_id,),
        ).fetchall()
        return [self._to_snapshot(r) for r in rows]

    @staticmethod
    def _history_filter(
        hostname: str, kind: SnapshotKind | None, command: str | None
    ) -> tuple[str, list[object]]:
        sql = " WHERE hostname = ?"
        params: list[object] = [_hostname(hostname)]
        if kind is not None:
            sql += " AND kind = ?"
            params.append(_kind(kind))
        if command is not None:
            sql += " AND command = ?"
            params.append(_clean(command))
        return sql, params

    @_serialized
    def history(
        self, hostname: str, kind: SnapshotKind | None = None, command: str | None = None
    ) -> list[Snapshot]:
        """Observations of a device ordered by capture time (oldest first).

        ``hostname`` is trimmed and matches case-insensitively (an empty one raises
        :class:`InvalidInputError`); ``kind`` and ``command`` filter when given.
        """
        where, params = self._history_filter(hostname, kind, command)
        rows = self._conn.execute(
            f"{self._SNAPSHOT_SELECT}{where} ORDER BY captured_at, observation_id", params
        ).fetchall()
        return [self._to_snapshot(r) for r in rows]

    @_serialized
    def snapshot_at(
        self,
        hostname: str,
        at: datetime,
        kind: SnapshotKind | None = None,
        command: str | None = None,
    ) -> Snapshot | None:
        """Time travel: the latest observation captured at or before ``at``, or None."""
        where, params = self._history_filter(hostname, kind, command)
        row = self._conn.execute(
            f"{self._SNAPSHOT_SELECT}{where} AND captured_at <= ?"
            " ORDER BY captured_at DESC, observation_id DESC LIMIT 1",
            [*params, _fmt_ts(at)],
        ).fetchone()
        return None if row is None else self._to_snapshot(row)

    @_serialized
    def devices(self) -> list[DeviceSummary]:
        """Every hostname seen, with its latest known vendor and observation span."""
        rows = self._conn.execute(
            "SELECT hostname, COUNT(*), MIN(captured_at), MAX(captured_at),"
            " (SELECT s2.vendor FROM snapshots s2 WHERE s2.hostname = s.hostname"
            "  AND s2.vendor <> '' ORDER BY s2.captured_at DESC LIMIT 1)"
            " FROM snapshots s WHERE hostname <> '' GROUP BY hostname ORDER BY hostname"
        ).fetchall()
        return [
            DeviceSummary(
                hostname=str(r[0]),
                vendor=None if r[4] is None else str(r[4]),
                observations=int(r[1]),
                first_seen=_parse_ts(str(r[2])),
                last_seen=_parse_ts(str(r[3])),
            )
            for r in rows
        ]

    # ------------------------------------------------------------------ queries

    @staticmethod
    def _check_limit(limit: int) -> None:
        if limit < 1:
            raise InvalidInputError("limit must be >= 1")

    @staticmethod
    def _to_hits(rows: Sequence[Sequence[object]]) -> list[Hit]:
        """Rows are ``(content_id, line_no, matched, text, hostname, captured_at, kind, cmd)``."""
        return [
            Hit(
                snapshot_id=str(r[0]),
                line_no=int(r[1]),  # type: ignore[call-overload]
                text=str(r[3]),
                hostname=str(r[4]) or None,
                captured_at=_parse_ts(str(r[5])),
                kind=r[6],  # type: ignore[arg-type]
                command=str(r[7]) or None,
                matched=None if r[2] is None else str(r[2]),
            )
            for r in rows
        ]

    @_serialized
    def search_text(
        self,
        query: str,
        *,
        limit: int = 100,
        literal: bool = False,
        hostname: str | None = None,
        kind: SnapshotKind | None = None,
        latest_only: bool = False,
    ) -> list[Hit]:
        """Full-text search over lines, best matches first.

        ``query`` is FTS5 syntax (``AND``/``OR``/``NOT``, ``"phrases"``); with ``literal=True``
        it is searched as one phrase (use this for pasted text such as ``route-policy`` or
        ``GigabitEthernet0/0/1``). The trigram tokenizer needs 3+ characters, so a query of
        fewer than 3 characters (after trimming) is searched as a plain, case-insensitive
        (ASCII) substring with ``LIKE`` over the line text instead: it scans lines newest
        ingested first and stops at ``limit``, so it is bounded but not index-assisted, and it
        ignores FTS syntax and ``literal``.

        ``hostname`` and ``kind`` keep only contents with a matching observation;
        ``latest_only`` keeps only contents that are the newest observation of their
        ``(hostname, kind, command)``. Observations without a hostname are never superseded.
        Each hit reports the newest observation satisfying the filters.

        Raises :class:`QuerySyntaxError` for an empty or malformed FTS query; any other
        database error propagates unchanged.
        """
        self._check_limit(limit)
        text = _clean(query).strip()
        if not text:
            raise QuerySyntaxError("empty search query")
        flt = _Filter(hostname, kind, latest_only)
        params: dict[str, object] = {**flt.params, "limit": limit}
        if len(text) < _MIN_FTS_CHARS:
            params["q"] = _like_pattern(text)
            sql = (
                f"SELECT l.content_id, l.line_no, NULL, {_HIT_COLUMNS} FROM lines l"
                f" JOIN observations o ON o.id = {flt.pick('l.content_id')}"
                " WHERE l.text LIKE :q ESCAPE '\\' ORDER BY l.id DESC LIMIT :limit"
            )
        else:
            if not literal and not _balanced(text):
                # Older SQLite builds accept an unterminated phrase or group; reject it everywhere.
                raise QuerySyntaxError("unbalanced quotes or parentheses in search query")
            params["q"] = quote_fts_literal(text) if literal else auto_fts_query(text)
            sql = (
                f"SELECT l.content_id, l.line_no, NULL, {_HIT_COLUMNS} FROM lines_fts f"
                " JOIN lines l ON l.id = f.rowid"
                f" JOIN observations o ON o.id = {flt.pick('l.content_id')}"
                " WHERE lines_fts MATCH :q ORDER BY f.rank LIMIT :limit"
            )
        try:
            rows = self._conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError as exc:
            message = str(exc).lower()
            if any(marker in message for marker in _FTS_ERRORS):
                raise QuerySyntaxError(f"invalid search query {query!r}: {exc}") from exc
            raise
        return self._to_hits(rows)

    def _typed(
        self,
        table: str,
        matched: str,
        where: str,
        params: dict[str, Any],
        limit: int,
        flt: _Filter,
    ) -> list[Hit]:
        """Hits from a side table, most recent observation first, then line number."""
        sql = (
            f"SELECT x.content_id, x.line_no, x.{matched}, {_HIT_COLUMNS} FROM {table} x"
            f" JOIN observations o ON o.id = {flt.pick('x.content_id')}"
            " JOIN lines l ON l.content_id = x.content_id AND l.line_no = x.line_no"
            f" WHERE {where} ORDER BY o.captured_at DESC, o.id DESC, x.line_no LIMIT :limit"
        )
        rows = self._conn.execute(sql, {**params, **flt.params, "limit": limit}).fetchall()
        return self._to_hits(rows)

    @_serialized
    def find_prefix(
        self,
        prefix: str | Network,
        relation: PrefixRelation = "inside",
        *,
        limit: int = 1000,
        hostname: str | None = None,
        kind: SnapshotKind | None = None,
        latest_only: bool = False,
    ) -> list[Hit]:
        """Lines mentioning an address or prefix related to ``prefix``.

        ``inside``: rows within ``prefix`` (equal included); ``covering``: rows that contain
        it (``0.0.0.0/0`` included); ``overlaps``: either; ``exact``: the same range.
        A bare address is a /32 or /128. ``matched`` is the row's network. Results are ordered
        by most recent observation, then line number; see :meth:`search_text` for the filters.
        """
        self._check_limit(limit)
        flt = _Filter(hostname, kind, latest_only)
        net = parse_network(prefix) if isinstance(prefix, str) else prefix
        if net is None:
            raise InvalidInputError(f"not an IP address or prefix: {prefix!r}")
        if relation == "exact":
            version, start, end = bounds(net)
            where = 'x."version" = :version AND x."start" = :start AND x."end" = :end'
            params: dict[str, object] = {"version": version, "start": start, "end": end}
        else:
            fragments = sql_fragments("")
            if relation not in fragments:
                raise InvalidInputError(f"unknown relation: {relation!r}")
            where = fragments[relation]
            params = query_params(net)
        return self._typed("ip_addrs", "network", where, params, limit, flt)

    @_serialized
    def find_mac(
        self,
        mac: str,
        *,
        limit: int = 1000,
        hostname: str | None = None,
        kind: SnapshotKind | None = None,
        latest_only: bool = False,
    ) -> list[Hit]:
        """Lines mentioning a MAC address, in any notation (``aabb.cc00.1122``, ``aa-bb-...``)."""
        self._check_limit(limit)
        flt = _Filter(hostname, kind, latest_only)
        norm = normalize_mac(mac)
        if norm is None:
            raise InvalidInputError(f"not a MAC address: {mac!r}")
        return self._typed("macs", "mac", "x.mac = :value", {"value": norm}, limit, flt)

    @_serialized
    def find_asn(
        self,
        asn: int | str,
        *,
        limit: int = 1000,
        hostname: str | None = None,
        kind: SnapshotKind | None = None,
        latest_only: bool = False,
    ) -> list[Hit]:
        """Lines where an AS number appears in a BGP context (``AS65536`` or ``65536``)."""
        self._check_limit(limit)
        flt = _Filter(hostname, kind, latest_only)
        text = str(asn).strip()
        if text[:2].upper() == "AS":
            text = text[2:]
        if not text.isdigit() or not 1 <= int(text) <= 4294967295:
            raise InvalidInputError(f"not an AS number: {asn!r}")
        return self._typed("asns", "context", "x.asn = :value", {"value": int(text)}, limit, flt)

    @_serialized
    def find_community(
        self,
        community: str,
        *,
        limit: int = 1000,
        hostname: str | None = None,
        kind: SnapshotKind | None = None,
        latest_only: bool = False,
    ) -> list[Hit]:
        """Lines with a BGP community (``64496:100``, ``64496:1:2`` or ``no-export``)."""
        self._check_limit(limit)
        flt = _Filter(hostname, kind, latest_only)
        value = _clean(community).strip().lower()
        return self._typed(
            "communities", "community", "x.community = :value", {"value": value}, limit, flt
        )

    @_serialized
    def find_interface(
        self,
        name: str,
        vendor: str | None = None,
        *,
        limit: int = 1000,
        hostname: str | None = None,
        kind: SnapshotKind | None = None,
        latest_only: bool = False,
    ) -> list[Hit]:
        """Lines naming an interface, matching short/long forms (``Gi0/0/1`` finds
        ``GigabitEthernet0/0/1``) within the vendor family and ignoring case."""
        self._check_limit(limit)
        flt = _Filter(hostname, kind, latest_only)
        clean_name = _clean(name).strip()
        if not clean_name:
            raise InvalidInputError("interface name must not be empty")
        try:
            norm = normalize_interface(clean_name, vendor)
        except ValueError:  # vendor id unknown to netaddr-search (third-party plugin)
            norm = normalize_interface(clean_name)
        return self._typed(
            "interfaces",
            "normalized",
            "x.norm_key = :value",
            {"value": norm.lower()},
            limit,
            flt,
        )
