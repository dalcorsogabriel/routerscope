-- routerscope storage schema, version 1. See docs/storage.md.
-- Every text column is derived from REDACTED text; raw content is never written.

CREATE TABLE sources (
    id         INTEGER PRIMARY KEY,
    kind       TEXT NOT NULL,
    uri        TEXT NOT NULL,
    importer   TEXT NOT NULL,
    git_commit TEXT NOT NULL DEFAULT ''        -- '' means "none"
);
CREATE UNIQUE INDEX ux_sources ON sources (kind, uri, importer, git_commit);

-- One row per distinct (redacted) text. id is its sha256, which is the Snapshot id.
CREATE TABLE contents (
    id         TEXT PRIMARY KEY CHECK (length(id) = 64),
    text       TEXT NOT NULL,
    size       INTEGER NOT NULL,
    line_count INTEGER NOT NULL
);

-- Every line of every content (redacted), numbered like routerscope.model.split_lines.
-- id is the FTS rowid. AUTOINCREMENT guarantees an id is never reused, even if rows were ever
-- deleted (contents are never deleted today, see docs/storage.md).
CREATE TABLE lines (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    content_id TEXT NOT NULL REFERENCES contents (id),
    line_no    INTEGER NOT NULL,
    text       TEXT NOT NULL,
    UNIQUE (content_id, line_no)
);

-- One row per time the content was seen. Identical content seen again adds a row here only.
CREATE TABLE observations (
    id          INTEGER PRIMARY KEY,
    content_id  TEXT NOT NULL REFERENCES contents (id),
    hostname    TEXT NOT NULL DEFAULT '' COLLATE NOCASE,   -- '' means "unknown"
    vendor      TEXT NOT NULL DEFAULT '',                  -- '' means "unknown"
    kind        TEXT NOT NULL CHECK (kind IN ('config', 'command_output', 'session')),
    command     TEXT NOT NULL DEFAULT '',                  -- '' means "none"
    captured_at TEXT NOT NULL,                             -- UTC, fixed-width ISO 8601
    source_id   INTEGER NOT NULL REFERENCES sources (id)
);
CREATE UNIQUE INDEX ux_observations
    ON observations (content_id, hostname, vendor, kind, command, captured_at, source_id);
CREATE INDEX ix_observations_content ON observations (content_id, captured_at);
CREATE INDEX ix_observations_history ON observations (hostname, kind, command, captured_at);

-- Mirrors the Snapshot model: one row per observation.
CREATE VIEW snapshots AS
SELECT o.id AS observation_id, c.id AS id, o.hostname, o.vendor, o.kind, o.command,
       o.captured_at, s.kind AS source_kind, s.uri AS source_uri,
       s.importer AS source_importer, s.git_commit AS source_git_commit,
       c.size, c.line_count
FROM observations o
JOIN contents c ON c.id = o.content_id
JOIN sources s ON s.id = o.source_id;

-- External-content FTS5 over lines.text (rowid = lines.id). Blank lines are not indexed.
-- Trigram tokenizer: case-insensitive substring search for any term of 3+ characters.
CREATE VIRTUAL TABLE lines_fts USING fts5 (
    text, content = 'lines', content_rowid = 'id', tokenize = 'trigram case_sensitive 0'
);

CREATE TABLE ip_addrs (
    content_id TEXT NOT NULL REFERENCES contents (id),
    line_no    INTEGER NOT NULL,
    version    INTEGER NOT NULL,
    start      BLOB NOT NULL,                  -- fixed-width big-endian (4 or 16 bytes)
    "end"      BLOB NOT NULL,
    address    TEXT NOT NULL,                  -- address as written
    network    TEXT NOT NULL,                  -- enclosing network (/32 or /128 for hosts)
    kind       TEXT NOT NULL                   -- address | prefix | mask | wildcard
);
CREATE INDEX ix_ip_range ON ip_addrs (version, start, "end");
CREATE INDEX ix_ip_content ON ip_addrs (content_id, line_no);

CREATE TABLE macs (
    content_id TEXT NOT NULL REFERENCES contents (id),
    line_no    INTEGER NOT NULL,
    mac        TEXT NOT NULL                   -- aa:bb:cc:dd:ee:ff
);
CREATE INDEX ix_macs ON macs (mac);

CREATE TABLE asns (
    content_id TEXT NOT NULL REFERENCES contents (id),
    line_no    INTEGER NOT NULL,
    asn        INTEGER NOT NULL,
    context    TEXT NOT NULL                   -- keyword that introduced it, lowercase
);
CREATE INDEX ix_asns ON asns (asn);

CREATE TABLE communities (
    content_id TEXT NOT NULL REFERENCES contents (id),
    line_no    INTEGER NOT NULL,
    community  TEXT NOT NULL,                  -- N:M, N:M:K or lowercase well-known name
    kind       TEXT NOT NULL CHECK (kind IN ('standard', 'large', 'well_known'))
);
CREATE INDEX ix_communities ON communities (community);

CREATE TABLE interfaces (
    content_id TEXT NOT NULL REFERENCES contents (id),
    line_no    INTEGER NOT NULL,
    raw        TEXT NOT NULL,
    normalized TEXT NOT NULL,
    norm_key   TEXT NOT NULL                   -- lower(normalized)
);
CREATE INDEX ix_interfaces ON interfaces (norm_key);

-- JSON of ParsedConfig / ParseResult per snapshot and plugin.
CREATE TABLE parsed (
    id         INTEGER PRIMARY KEY,
    content_id TEXT NOT NULL REFERENCES contents (id),
    plugin     TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('config', 'result')),
    command    TEXT NOT NULL DEFAULT '',
    data       TEXT NOT NULL,
    UNIQUE (content_id, plugin, kind, command)
);
