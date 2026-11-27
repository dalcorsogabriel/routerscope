# Storage

> Status: implemented in `routerscope.storage` (schema version 1).

One SQLite file (stdlib `sqlite3`, WAL, foreign keys on, explicit transactions). FTS5 with the `trigram` tokenizer is required and checked when the database is opened.

## Secrets never reach the database

`Store.open(path, *, redactor)` takes a **required** redactor, `Callable[[str, str | None], str]` (text, vendor to text). `add_snapshot` redacts first; the stored text, the FTS index, every side table, the snapshot id (sha256 of the *redacted* text), the command and the parsed JSON all derive from the redacted text. Raw, unredacted content is never persisted. `source.uri`, `source.importer`, `source.git_commit` and `command` go through the redactor too, and credentials in `source.uri` (`scheme://user:pass@host`, including unescaped `@` and `/` in the password), the query string and the fragment are dropped. When the authority looks like userinfo the URI is cut at the last `@` (secrecy wins over a path that contains `@`); non-URL strings such as Windows paths are only redacted. `add_parsed` passes the JSON through the redactor and refuses data it would change.

## Tables

| Table | Purpose and key columns |
|---|---|
| `sources` | `kind, uri, importer, git_commit` (unique) |
| `contents` | one row per distinct redacted text: `id` (sha256), `text`, `size`, `line_count` |
| `lines` | every line of every content: `id` (AUTOINCREMENT, the FTS rowid), `content_id`, `line_no`, `text` (redacted, blank lines included). Hit text and `get_lines` are served from here, so a search never loads or re-splits a whole content. |
| `observations` | one row per time a content was seen: `content_id, hostname, vendor, kind, command, captured_at (UTC ISO), source_id`, unique over all of them (the empty string means none/unknown, so `NULL` can never defeat the constraint). Seeing identical content again adds a row here, not a new copy. |
| `snapshots` (view) | observations joined with contents and sources; mirrors the `Snapshot` model |
| `lines_fts` | external-content FTS5 over `lines.text` (`content='lines'`, rowid = `lines.id`; blank lines are not indexed) |
| `ip_addrs` | `content_id, line_no, version, start, end, address, network, kind`; `start`/`end` are fixed-width big-endian BLOBs from `netaddr_search.bounds`, so containment works for IPv6 above 2**63 |
| `macs` | `content_id, line_no, mac` (normalized `aa:bb:cc:dd:ee:ff`) |
| `asns` | `content_id, line_no, asn, context` |
| `communities` | `content_id, line_no, community, kind` (`standard`, `large`, `well_known`) |
| `interfaces` | `content_id, line_no, raw, normalized, norm_key` |
| `parsed` | `ParsedConfig` / `ParseResult` JSON per `content_id`, `plugin`, `kind`, `command` |

Line numbers are 1-based and follow `routerscope.model.split_lines` (LF, CR and CRLF only), the same rule as `Snapshot.line_count` and `SourceRef`. Empty `hostname`, `vendor`, `command` and `git_commit` mean "none".

**Identifiers.** `hostname` is trimmed (blank means unknown) and must match `[A-Za-z0-9_.:/@-]{1,255}`; `vendor` and the `plugin` of `add_parsed` must match the vendor id pattern `^[a-z][a-z0-9_]*$`. Anything else raises `InvalidInputError`, so free text such as `host password 7 ABC` can never land in a column.

**Why an external-content index.** Rowids come from `lines.id` (collision-free by construction, no counter query), the FTS index holds only tokens (the text is stored once in `lines`), and a hit is one indexed join instead of splitting the whole content. **Contents are never deleted** (there is no delete API); if one is ever added it must delete the `lines` and FTS rows together, and ids are never reused (`AUTOINCREMENT`). Disk cost: text is kept in `contents.text` (byte-faithful, CRLF preserved) and in `lines.text`.

**Text encoding.** Every `str` is encoded as UTF-8 with `errors="replace"` before it is hashed, stored or searched: a lone surrogate becomes `?`, in content, commands and queries alike. Bytes content is decoded the same way.

**Concurrency.** One connection opened with `check_same_thread=False` and one `threading.RLock` serialize every public operation, so a `Store` can be shared between threads (serialized, not parallel). Writes use `BEGIN IMMEDIATE`; `COMMIT` is inside the guarded block, a failure rolls back only if a transaction is still open and never hides the original exception. A lock held by another connection longer than `Store.open(..., timeout=30)` raises `DatabaseBusyError`.

**Errors.** All derive from `StorageError`; bad input raises `InvalidInputError(StorageError, ValueError)`.

## Tokenizer

`trigram case_sensitive 0`: case-insensitive substring search, so `GigabitEthernet0/0/1`, `0/0/1`, `ether1`, `route-policy`, `policy`, `192.0.2.1` and `AS65536` all hit without special tokenizer rules. Terms need 3 or more characters: a query shorter than that (after trimming) falls back to a case-insensitive (ASCII) `LIKE` substring scan over `lines.text`, newest ingested first and stopped at `limit` (bounded, not indexed; it ignores FTS syntax and `literal`). Use `search_text(q, literal=True)` for pasted text; without it, plain words are literal terms combined with AND (`route-policy PASS` never trips over `-`), and a query with FTS5 operators (quotes, parentheses, `*`, `^`, `:`, upper-case `AND`/`OR`/`NOT`/`NEAR`) is FTS5 syntax; a malformed one (including unbalanced quotes, on every SQLite version) raises `QuerySyntaxError`. Only FTS syntax errors are mapped to it (`fts5: syntax error`, `unterminated string`, `no such column`, `unknown special query`); every other database error propagates. Exact IP/MAC/ASN questions should use the typed tables.

## Typed extraction (conservative)

- **ASN**: after `router bgp`, `remote-as`, `peer-as`, `local-as`, `as-number`, `autonomous-system`, a Huawei/OcNOS line `bgp N`, RouterOS `as=`/`remote.as=`/`local.as=`, `remote AS N`, `local AS number N` and the token `AS64496`. asdot (`1.1`) is converted.
- **Communities**: only on lines containing `communit`; `N:M` (16-bit), `N:M:K` (large), and well-known names (`no-export`, `no-advertise`, ...).
- **Interfaces**: known type prefixes per vendor family, `interface <name>` statements, SR OS `port x/y/z`; normalized with `netaddr-search`. Unknown (third-party) vendor ids fall back to inferred normalization.

## Migrations

`PRAGMA user_version` holds the schema version. Migrations are SQL files `storage/migrations/NNNN_name.sql` shipped as package data, contiguous from 1. `migrate()` applies pending ones inside one `BEGIN IMMEDIATE` transaction (failed upgrades roll back), is idempotent, and a database from a newer routerscope raises `SchemaTooNewError`. To change the schema add the next numbered file; never edit an applied one.

## API (`routerscope.storage`)

`Store.open`, `close` / context manager, `add_snapshot` (dedupe, returns `Snapshot`), `add_parsed`, `get_parsed_config`, `get_parse_result`, `get_snapshot`, `observations`, `get_content`, `get_lines`, `history`, `snapshot_at` (time travel), `devices`, and query helpers returning `Hit`: `search_text`, `find_prefix(relation="inside"|"covering"|"overlaps"|"exact")`, `find_mac`, `find_asn`, `find_community`, `find_interface`. All SQL is parameterized.

`Hit(snapshot_id, line_no, text, hostname, captured_at, kind, command, matched)` carries the newest observation of its content that satisfies the filters. Every search method accepts keyword filters:

- `hostname=`: only contents with an observation for that host (trimmed, case-insensitive);
- `kind=`: only contents with an observation of that kind;
- `latest_only=True`: only contents that are the newest observation of their `(hostname, kind, command)`, so superseded configs disappear. Observations without a hostname cannot be grouped and are never treated as superseded.

`find_*` results are ordered by most recent observation, then line number; `search_text` by FTS rank. The filters use the `(content_id, captured_at)` and `(hostname, kind, command, captured_at)` indexes.
