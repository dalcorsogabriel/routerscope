"""Paste importer: text copied from any terminal (Termius, a web console, an editor...).

Decision order for ``PasteImporter(text, ...)``, unless ``kind`` forces one:

1. **Session**: the text contains device prompts (:func:`netprompt.segment` finds commands).
   It is handled exactly like a terminal log (auto-detected timestamps, one ``session`` item
   plus one ``command_output`` item per command). ``hostname`` and ``vendor`` given by the
   caller override what was detected.
2. **Config**: no prompts and the text looks like a configuration
   (:func:`~routerscope.capture.importers._common.looks_like_config`: at least three
   configuration-looking lines, or one plus a vendor recognised by the plugin registry).
3. **Command output**: anything else, which needs ``command`` (``ImportError_`` otherwise).

Single items are stored normalized (ANSI and pagination removed). Their vendor is the given
one, else the plugin registry's ``detect_vendor``; a config's hostname is taken from its own
``hostname``/``sysname``/``set system host-name``/``/system identity`` statement when not
given. ``captured_at`` defaults to the current time; ``Source`` is
``Source(kind="paste", uri="paste", importer="paste")``.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, tzinfo
from typing import get_args

import netprompt

from routerscope.capture.importers._common import config_hostname, looks_like_config
from routerscope.capture.importers.base import ImportError_, ImportItem
from routerscope.capture.importers.session_log import parse_session_log, session_items
from routerscope.model import Source
from routerscope.model.provenance import SnapshotKind
from routerscope.vendors.registry import VendorRegistry, default_registry

__all__ = ["PasteImporter"]


class PasteImporter:
    """Turn pasted text into import items (see the module docstring)."""

    name = "paste"

    def __init__(
        self,
        text: str,
        *,
        hostname: str | None = None,
        vendor: str | None = None,
        kind: SnapshotKind | None = None,
        command: str | None = None,
        captured_at: datetime | None = None,
        tz: tzinfo | None = None,
        registry: VendorRegistry | None = None,
    ) -> None:
        if kind is not None and kind not in get_args(SnapshotKind):
            raise ValueError(f"unknown kind {kind!r}")
        if captured_at is not None and captured_at.tzinfo is None:
            raise ValueError("captured_at must be timezone-aware")
        self.text = text
        self.hostname = hostname
        self.vendor = vendor
        self.kind = kind
        self.command = command
        self.captured_at = captured_at
        self.tz = tz
        self.registry = registry if registry is not None else default_registry()

    def items(self) -> Iterator[ImportItem]:
        if not self.text.strip():
            raise ImportError_("nothing to import: the pasted text is empty")
        when = self.captured_at or datetime.now(UTC)
        source = Source(kind="paste", uri="paste", importer="paste")
        if self.kind in (None, "session"):
            parsed = parse_session_log(self.text, tz=self.tz, fallback=when)
            if parsed.segments or self.kind == "session":
                for item in session_items(parsed, source):
                    yield replace(
                        item,
                        hostname=self.hostname or item.hostname,
                        vendor=self.vendor or item.vendor,
                    )
                return
        content = netprompt.normalize(self.text)
        kind = self.kind or ("config" if looks_like_config(content, self.registry) else None)
        if kind is None and self.command:
            kind = "command_output"
        if kind is None or (kind == "command_output" and not self.command):
            raise ImportError_(
                "cannot tell what was pasted: it has no prompts and does not look like a "
                "config; pass command=... to store it as command output"
            )
        hostname = self.hostname or (config_hostname(content) if kind == "config" else None)
        yield ImportItem(
            content=content,
            kind=kind,
            captured_at=when,
            source=source,
            hostname=hostname,
            vendor=self.vendor or self.registry.detect_vendor(content),
            command=self.command if kind == "command_output" else None,
        )
