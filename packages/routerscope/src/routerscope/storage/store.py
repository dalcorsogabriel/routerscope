"""SQLite store: versioned snapshots, full-text index, typed side tables, parsed objects.

Raw, unredacted content is never persisted: ``add_snapshot`` runs the (required) redactor first
and everything stored or indexed, including the snapshot id, derives from the redacted text.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Literal, Self

from netaddr_search import normalize_interface, parse_network, query_params, sql_fragments
from netaddr_search.ip import Network, bounds

from routerscope.model import (
    ParsedConfig,
    ParseResult,
    Snapshot,
    SnapshotKind,
    Source,
    make_snapshot,
    split_lines,
)
from routerscope.storage.errors import (
    FtsUnavailableError,
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
_URI_CREDENTIALS = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]*@")


@dataclass(frozen=True, slots=True)
class Hit:
    """One matching line: ``snapshot_id`` is the content hash, ``line_no`` is 1-based."""

    snapshot_id: str
    line_no: int
    text: str
    matched: str | None = None


@dataclass(frozen=True, slots=True)
class DeviceSummary:
    """A hostname seen in observations."""

    hostname: str
    vendor: str | None
    observations: int
    first_seen: datetime
    last_seen: datetime


def _fmt_ts(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(UTC).strftime(_TS_FORMAT)


def _parse_ts(value: str) -> datetime:
    return datetime.strptime(value, _TS_FORMAT).replace(tzinfo=UTC)


def _strip_uri_credentials(uri: str) -> str:
    return _URI_CREDENTIALS.sub(r"\1", uri)


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


class Store:
    """A routerscope database. Use :meth:`open`; not thread-safe (one connection)."""

    def __init__(self, conn: sqlite3.Connection, redactor: Redactor) -> None:
        self._conn = conn
        self._redactor = redactor

    # ------------------------------------------------------------------ lifecycle

    @classmethod
    def open(cls, path: str | Path, *, redactor: Redactor) -> Self:
        """Open (creating and migrating if needed) the database at ``path``.

        ``redactor`` is required: there is deliberately no default, so nothing can be stored
        unredacted by omission. ``":memory:"`` gives a throwaway database.
        """
        conn = sqlite3.connect(str(path), isolation_level=None, timeout=30.0)
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            check_fts5(conn)
            migrate(conn)
        except BaseException:
            conn.close()
            raise
        return cls(conn, redactor)

    def close(self) -> None:
        """Close the connection (idempotent)."""
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
    def schema_version(self) -> int:
        """The ``user_version`` of the open database."""
        return schema_version(self._conn)

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield self._conn
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")

    # ------------------------------------------------------------------ writing

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
        stored and indexed once; seeing it again (other host, time or source) only adds an
        observation, and re-adding the very same observation is a no-op. Credentials embedded
        in ``source.uri`` (``scheme://user:pass@host``) are dropped and ``command`` goes
        through the redactor too. Everything happens in one transaction.
        """
        raw = content if isinstance(content, str) else content.decode("utf-8", errors="replace")
        text = self._redactor(raw, vendor)
        del raw
        clean_command = self._redactor(command, vendor) if command else None
        clean_source = source.model_copy(update={"uri": _strip_uri_credentials(source.uri)})
        snapshot = make_snapshot(
            text,
            source=clean_source,
            kind=kind,
            captured_at=captured_at,
            hostname=hostname,
            vendor=vendor,
            command=clean_command,
        )
        with self._tx() as conn:
            source_id = self._source_id(conn, clean_source)
            if conn.execute("SELECT 1 FROM contents WHERE id = ?", (snapshot.id,)).fetchone():
                pass
            else:
                self._insert_content(conn, snapshot, text, vendor)
            conn.execute(
                "INSERT OR IGNORE INTO observations"
                " (content_id, hostname, vendor, kind, command, captured_at, source_id)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    snapshot.id,
                    hostname or "",
                    vendor,
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
        base = conn.execute(
            "SELECT COALESCE(MAX(line_base + line_count), 1) FROM contents"
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO contents (id, text, size, line_count, line_base) VALUES (?, ?, ?, ?, ?)",
            (snapshot.id, text, snapshot.size, snapshot.line_count, base),
        )
        conn.executemany(
            "INSERT INTO lines_fts (rowid, text) VALUES (?, ?)",
            ((base + n, line) for n, line in enumerate(lines) if line.strip()),
        )
        rows = extract_rows(lines, vendor)
        cid = snapshot.id
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

    def add_parsed(self, parsed: ParsedConfig | ParseResult, *, plugin: str) -> None:
        """Store (or replace) parser output for a stored snapshot and plugin id.

        Parsers must run on the stored (redacted) text from :meth:`get_content`. As a second
        line of defence the JSON is passed through the redactor and refused with
        :class:`UnredactedDataError` if the redactor would change it.
        """
        if not self._has_content(parsed.snapshot_id):
            raise UnknownSnapshotError(f"snapshot {parsed.snapshot_id[:12]} is not stored")
        data = parsed.model_dump_json()
        if self._redactor(data, parsed.vendor) != data:
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

    def get_parsed_config(self, snapshot_id: str, plugin: str) -> ParsedConfig | None:
        """Parsed config stored by ``plugin`` for the snapshot, if any."""
        row = self._conn.execute(
            "SELECT data FROM parsed WHERE content_id = ? AND plugin = ? AND kind = 'config'",
            (snapshot_id, plugin),
        ).fetchone()
        return None if row is None else ParsedConfig.model_validate_json(row[0])

    def get_parse_result(self, snapshot_id: str, plugin: str, command: str) -> ParseResult | None:
        """Command parse result stored by ``plugin`` for the snapshot, if any."""
        row = self._conn.execute(
            "SELECT data FROM parsed WHERE content_id = ? AND plugin = ?"
            " AND kind = 'result' AND command = ?",
            (snapshot_id, plugin, command),
        ).fetchone()
        return None if row is None else ParseResult.model_validate_json(row[0])

    def get_content(self, snapshot_id: str) -> str | None:
        """The stored (redacted) text of a snapshot, or None."""
        row = self._conn.execute(
            "SELECT text FROM contents WHERE id = ?", (snapshot_id,)
        ).fetchone()
        return None if row is None else str(row[0])

    def get_lines(self, snapshot_id: str, first: int, last: int) -> list[str]:
        """Lines ``first``..``last`` (1-based, inclusive) of a snapshot; [] if unknown."""
        text = self.get_content(snapshot_id)
        if text is None or first > last:
            return []
        return split_lines(text)[max(first, 1) - 1 : last]

    _SNAPSHOT_SELECT = (
        "SELECT id, hostname, vendor, kind, command, captured_at, source_kind, source_uri,"
        " source_importer, source_git_commit, size, line_count FROM snapshots"
    )

    @staticmethod
    def _to_snapshot(row: Sequence[object]) -> Snapshot:
        return Snapshot(
            id=str(row[0]),
            hostname=str(row[1]) or None,
            vendor=None if row[2] is None else str(row[2]),
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

    def get_snapshot(self, snapshot_id: str) -> Snapshot | None:
        """The most recent observation of a snapshot id, or None."""
        row = self._conn.execute(
            f"{self._SNAPSHOT_SELECT} WHERE id = ? ORDER BY captured_at DESC, observation_id DESC"
            " LIMIT 1",
            (snapshot_id,),
        ).fetchone()
        return None if row is None else self._to_snapshot(row)

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
        params: list[object] = [hostname]
        if kind is not None:
            sql += " AND kind = ?"
            params.append(kind)
        if command is not None:
            sql += " AND command = ?"
            params.append(command)
        return sql, params

    def history(
        self, hostname: str, kind: SnapshotKind | None = None, command: str | None = None
    ) -> list[Snapshot]:
        """Observations of a device ordered by capture time (oldest first).

        ``hostname`` matches case-insensitively; ``kind`` and ``command`` filter when given.
        """
        where, params = self._history_filter(hostname, kind, command)
        rows = self._conn.execute(
            f"{self._SNAPSHOT_SELECT}{where} ORDER BY captured_at, observation_id", params
        ).fetchall()
        return [self._to_snapshot(r) for r in rows]

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

    def devices(self) -> list[DeviceSummary]:
        """Every hostname seen, with its latest known vendor and observation span."""
        rows = self._conn.execute(
            "SELECT hostname, COUNT(*), MIN(captured_at), MAX(captured_at),"
            " (SELECT s2.vendor FROM snapshots s2 WHERE s2.hostname = s.hostname"
            "  AND s2.vendor IS NOT NULL ORDER BY s2.captured_at DESC LIMIT 1)"
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
            raise ValueError("limit must be >= 1")

    def _hits(self, rows: Sequence[Sequence[object]]) -> list[Hit]:
        """Attach line text to ``(content_id, line_no, matched)`` rows."""
        cache: dict[str, list[str]] = {}
        out: list[Hit] = []
        for content_id, line_no, matched in rows:
            cid = str(content_id)
            if cid not in cache:
                cache[cid] = split_lines(self.get_content(cid) or "")
            lines = cache[cid]
            n = int(line_no)  # type: ignore[call-overload]
            out.append(
                Hit(
                    cid,
                    n,
                    lines[n - 1] if 0 < n <= len(lines) else "",
                    None if matched is None else str(matched),
                )
            )
        return out

    def search_text(self, query: str, *, limit: int = 100, literal: bool = False) -> list[Hit]:
        """Full-text search over lines, best matches first.

        ``query`` is FTS5 syntax (``AND``/``OR``/``NOT``, ``"phrases"``); with ``literal=True``
        it is searched as one phrase (use this for pasted text such as ``route-policy`` or
        ``GigabitEthernet0/0/1``). The trigram tokenizer needs terms of 3+ characters.
        Raises :class:`QuerySyntaxError` for an empty or malformed query.
        """
        self._check_limit(limit)
        if not query.strip():
            raise QuerySyntaxError("empty search query")
        match = quote_fts_literal(query) if literal else query
        try:
            rows = self._conn.execute(
                "SELECT (SELECT c.id FROM contents c WHERE c.line_count > 0"
                "   AND c.line_base <= f.rowid ORDER BY c.line_base DESC LIMIT 1),"
                " f.rowid, NULL FROM lines_fts f WHERE lines_fts MATCH ? ORDER BY f.rank LIMIT ?",
                (match, limit),
            ).fetchall()
        except sqlite3.OperationalError as exc:
            raise QuerySyntaxError(f"invalid search query {query!r}: {exc}") from exc
        resolved: list[tuple[str, int, None]] = []
        for content_id, rowid, _ in rows:
            base = self._conn.execute(
                "SELECT line_base FROM contents WHERE id = ?", (content_id,)
            ).fetchone()[0]
            resolved.append((content_id, rowid - base + 1, None))
        return self._hits(resolved)

    def find_prefix(
        self, prefix: str | Network, relation: PrefixRelation = "inside", *, limit: int = 1000
    ) -> list[Hit]:
        """Lines mentioning an address or prefix related to ``prefix``.

        ``inside``: rows within ``prefix`` (equal included); ``covering``: rows that contain
        it (``0.0.0.0/0`` included); ``overlaps``: either; ``exact``: the same range.
        A bare address is a /32 or /128. ``matched`` is the row's network.
        """
        self._check_limit(limit)
        net = parse_network(prefix) if isinstance(prefix, str) else prefix
        if net is None:
            raise ValueError(f"not an IP address or prefix: {prefix!r}")
        if relation == "exact":
            version, start, end = bounds(net)
            where = '"version" = :version AND "start" = :start AND "end" = :end'
            params: dict[str, object] = {"version": version, "start": start, "end": end}
        else:
            fragments = sql_fragments("")
            if relation not in fragments:
                raise ValueError(f"unknown relation: {relation!r}")
            where = fragments[relation]
            params = query_params(net)
        params["limit"] = limit
        rows = self._conn.execute(
            f"SELECT content_id, line_no, network FROM ip_addrs WHERE {where}"
            " ORDER BY content_id, line_no LIMIT :limit",
            params,
        ).fetchall()
        return self._hits(rows)

    def _simple(self, sql: str, param: object, limit: int) -> list[Hit]:
        self._check_limit(limit)
        return self._hits(self._conn.execute(sql, (param, limit)).fetchall())

    def find_mac(self, mac: str, *, limit: int = 1000) -> list[Hit]:
        """Lines mentioning a MAC address, in any notation (``aabb.cc00.1122``, ``aa-bb-...``)."""
        from netaddr_search import normalize_mac

        norm = normalize_mac(mac)
        if norm is None:
            raise ValueError(f"not a MAC address: {mac!r}")
        return self._simple(
            "SELECT content_id, line_no, mac FROM macs WHERE mac = ?"
            " ORDER BY content_id, line_no LIMIT ?",
            norm,
            limit,
        )

    def find_asn(self, asn: int | str, *, limit: int = 1000) -> list[Hit]:
        """Lines where an AS number appears in a BGP context (``AS65536`` or ``65536``)."""
        text = str(asn).strip()
        if text[:2].upper() == "AS":
            text = text[2:]
        if not text.isdigit() or not 1 <= int(text) <= 4294967295:
            raise ValueError(f"not an AS number: {asn!r}")
        return self._simple(
            "SELECT content_id, line_no, context FROM asns WHERE asn = ?"
            " ORDER BY content_id, line_no LIMIT ?",
            int(text),
            limit,
        )

    def find_community(self, community: str, *, limit: int = 1000) -> list[Hit]:
        """Lines with a BGP community (``64496:100``, ``64496:1:2`` or ``no-export``)."""
        return self._simple(
            "SELECT content_id, line_no, community FROM communities WHERE community = ?"
            " ORDER BY content_id, line_no LIMIT ?",
            community.strip().lower(),
            limit,
        )

    def find_interface(
        self, name: str, vendor: str | None = None, *, limit: int = 1000
    ) -> list[Hit]:
        """Lines naming an interface, matching short/long forms (``Gi0/0/1`` finds
        ``GigabitEthernet0/0/1``) within the vendor family and ignoring case."""
        try:
            norm = normalize_interface(name, vendor)
        except ValueError:  # vendor id unknown to netaddr-search (third-party plugin)
            norm = normalize_interface(name)
        return self._simple(
            "SELECT content_id, line_no, normalized FROM interfaces WHERE norm_key = ?"
            " ORDER BY content_id, line_no LIMIT ?",
            norm.lower(),
            limit,
        )
