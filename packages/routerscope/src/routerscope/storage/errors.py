"""Exceptions raised by the storage layer."""

from __future__ import annotations


class StorageError(Exception):
    """Base class of every storage error."""


class FtsUnavailableError(StorageError):
    """The SQLite build lacks FTS5 or its trigram tokenizer (needs SQLite >= 3.34 with FTS5)."""


class SchemaTooNewError(StorageError):
    """The database was created by a newer routerscope than the one running."""


class MigrationError(StorageError):
    """A migration could not be loaded or applied."""


class QuerySyntaxError(StorageError):
    """An FTS5 query string was rejected by SQLite (or was empty)."""


class UnknownSnapshotError(StorageError):
    """A referenced snapshot id is not stored."""


class UnredactedDataError(StorageError):
    """Data handed to the store still contains something the redactor would remove."""


class InvalidInputError(StorageError, ValueError):
    """A caller-supplied value is unusable (bad hostname, vendor id, limit, filter, ...).

    Also a :class:`ValueError`, so callers may catch either.
    """


class DatabaseBusyError(StorageError):
    """The database stayed locked by another connection longer than the busy timeout."""
