"""SQLite storage: versioned snapshots, FTS5 line index, typed side tables, parsed objects."""

from routerscope.storage.errors import (
    DatabaseBusyError,
    FtsUnavailableError,
    InvalidInputError,
    MigrationError,
    QuerySyntaxError,
    SchemaTooNewError,
    StorageError,
    UnknownSnapshotError,
    UnredactedDataError,
)
from routerscope.storage.migrate import Migration, latest_version, load_migrations, migrate
from routerscope.storage.store import (
    DeviceSummary,
    Hit,
    PrefixRelation,
    Redactor,
    Store,
    quote_fts_literal,
)

__all__ = [
    "DatabaseBusyError",
    "DeviceSummary",
    "FtsUnavailableError",
    "Hit",
    "InvalidInputError",
    "Migration",
    "MigrationError",
    "PrefixRelation",
    "QuerySyntaxError",
    "Redactor",
    "SchemaTooNewError",
    "StorageError",
    "Store",
    "UnknownSnapshotError",
    "UnredactedDataError",
    "latest_version",
    "load_migrations",
    "migrate",
    "quote_fts_literal",
]
