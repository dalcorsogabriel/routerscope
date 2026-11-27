# Storage

> Status: implemented in `routerscope.storage` (schema version 1).

One SQLite file (stdlib `sqlite3`, WAL, foreign keys on, explicit transactions). FTS5 with the `trigram` tokenizer is required and checked when the database is opened.

## Secrets never reach the database

`Store.open(path, *, redactor)` takes a **required** redactor, `Callable[[str, str | None], str]` (text, vendor to text). `add_snapshot` redacts first; the stored text, the FTS index, every side table, the snapshot id (sha256 of the *redacted* text), the command and the parsed JSON all derive from the redacted text. Raw, unredacted content is never persisted. Credentials in `source.uri` (`scheme://user:pass@host`) are dropped. `add_parsed` passes the JSON through the redactor and refuses data it would change.

## Tables

| Table | Purpose and key columns |
|---|---|
| `sources` | `kind, uri, importer, git_commit` (unique) |
| `contents` | one row per distinct redacted text: `id` (sha256), `text`, `size`, `line_count`, `line_base` |
| `observations` | one row per time a content was seen: `content_id, hostname, vendor, kind, command, captured_at (UTC ISO), source_id`. Seeing identical content again adds a row here, not a new copy. |
| `snapshots` (view) | observations joined with contents and sources; mirrors the `Snapshot` model |
| `lines_fts` | contentless FTS5 over lines. rowid = `contents.line_base + line_no - 1` (blank lines skipped) |
| `ip_addrs` | `content_id, line_no, version, start, end, address, network, kind`; `start`/`end` are fixed-width big-endian BLOBs from `netaddr_search.bounds`, so containment works for IPv6 above 2**63 |
| `macs` | `content_id, line_no, mac` (normalized `aa:bb:cc:dd:ee:ff`) |
| `asns` | `content_id, line_no, asn, context` |
| `communities` | `content_id, line_no, community, kind` (`standard`, `large`, `well_known`) |
| `interfaces` | `content_id, line_no, raw, normalized, norm_key` |
| `parsed` | `ParsedConfig` / `ParseResult` JSON per `content_id`, `plugin`, `kind`, `command` |

Line numbers are 1-based and follow `routerscope.model.split_lines` (LF, CR and CRLF only), the same rule as `Snapshot.line_count` and `SourceRef`. Empty `hostname`, `command` and `git_commit` mean "none".

## Tokenizer

`trigram case_sensitive 0`: case-insensitive substring search, so `GigabitEthernet0/0/1`, `0/0/1`, `ether1`, `route-policy`, `policy`, `192.0.2.1` and `AS65536` all hit without special tokenizer rules. Terms need 3 or more characters. Use `search_text(q, literal=True)` for pasted text; without it `q` is FTS5 syntax (`remote AND 65536`) and a malformed query raises `QuerySyntaxError`. Exact IP/MAC/ASN questions should use the typed tables.

## Typed extraction (conservative)

- **ASN**: after `router bgp`, `remote-as`, `peer-as`, `local-as`, `as-number`, `autonomous-system`, a Huawei/OcNOS line `bgp N`, RouterOS `as=`/`remote.as=`/`local.as=`, `remote AS N`, `local AS number N` and the token `AS64496`. asdot (`1.1`) is converted.
- **Communities**: only on lines containing `communit`; `N:M` (16-bit), `N:M:K` (large), and well-known names (`no-export`, `no-advertise`, ...).
- **Interfaces**: known type prefixes per vendor family, `interface <name>` statements, SR OS `port x/y/z`; normalized with `netaddr-search`. Unknown (third-party) vendor ids fall back to inferred normalization.

## Migrations

`PRAGMA user_version` holds the schema version. Migrations are SQL files `storage/migrations/NNNN_name.sql` shipped as package data, contiguous from 1. `migrate()` applies pending ones inside one `BEGIN IMMEDIATE` transaction (failed upgrades roll back), is idempotent, and a database from a newer routerscope raises `SchemaTooNewError`. To change the schema add the next numbered file; never edit an applied one.

## API (`routerscope.storage`)

`Store.open`, `close` / context manager, `add_snapshot` (dedupe, returns `Snapshot`), `add_parsed`, `get_parsed_config`, `get_parse_result`, `get_snapshot`, `observations`, `get_content`, `get_lines`, `history`, `snapshot_at` (time travel), `devices`, and query helpers returning `Hit(snapshot_id, line_no, text, matched)`: `search_text`, `find_prefix(relation="inside"|"covering"|"overlaps"|"exact")`, `find_mac`, `find_asn`, `find_community`, `find_interface`. All SQL is parameterized.
