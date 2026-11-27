"""Store imported items and run the vendor parsers on them.

The pipeline for each :class:`~routerscope.capture.importers.base.ImportItem`:

1. Detect the vendor when the item does not say (vendor plugins, then netprompt).
2. Store it with :meth:`Store.add_snapshot` (the store redacts secrets before writing).
3. Parse the *stored, redacted* text with the vendor plugin (``parse_config`` for configs,
   ``parse_command`` for command outputs) and keep the result with :meth:`Store.add_parsed`.

A failing plugin never stops an import: the error is recorded in the report and the raw
snapshot stays searchable.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field

from routerscope.capture.importers.base import ImportItem
from routerscope.model import ParsedConfig, ParseResult
from routerscope.storage import Store
from routerscope.vendors.registry import VendorRegistry, default_registry

__all__ = ["IngestReport", "ingest"]

logger = logging.getLogger(__name__)


@dataclass
class IngestReport:
    """What an ingestion did."""

    stored: int = 0
    parsed: int = 0
    snapshot_ids: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    """Human-readable problems (plugin failures, rejected items); never contains content."""


def _detect(item: ImportItem, registry: VendorRegistry) -> str | None:
    if item.vendor:
        return item.vendor
    text = item.content if isinstance(item.content, str) else ""
    return registry.detect_vendor(text) if text else None


def ingest(
    store: Store,
    items: Iterable[ImportItem],
    *,
    registry: VendorRegistry | None = None,
    parse: bool = True,
) -> IngestReport:
    """Store ``items`` and parse them; returns an :class:`IngestReport`."""
    reg = registry if registry is not None else default_registry()
    report = IngestReport()
    for number, item in enumerate(items, 1):
        vendor = _detect(item, reg)
        try:
            snapshot = store.add_snapshot(
                item.content,
                source=item.source,
                kind=item.kind,
                captured_at=item.captured_at,
                hostname=item.hostname,
                vendor=vendor,
                command=item.command,
            )
        except ValueError as exc:
            report.errors.append(f"item {number}: rejected: {exc}")
            continue
        report.stored += 1
        report.snapshot_ids.append(snapshot.id)
        plugin = reg.get(vendor) if (parse and vendor) else None
        if plugin is None or item.kind == "session":
            continue
        text = store.get_content(snapshot.id) or ""
        try:
            parsed: ParsedConfig | ParseResult | None
            if item.kind == "config":
                parsed = plugin.parse_config(text, snapshot)
            else:
                parsed = plugin.parse_command(item.command or "", text, snapshot)
            if parsed is None:
                continue
            store.add_parsed(parsed, plugin=plugin.id)
        except Exception as exc:  # a plugin must never break an import
            logger.warning("vendor plugin %s failed on item %d: %r", plugin.id, number, exc)
            report.errors.append(f"item {number}: plugin {plugin.id} failed: {type(exc).__name__}")
            continue
        report.parsed += 1
    return report
