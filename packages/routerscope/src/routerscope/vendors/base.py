"""The vendor plugin interface and a base class with safe defaults."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

import netprompt
from pydantic import Field

from routerscope.model import ParsedConfig, ParseResult, Snapshot
from routerscope.model._base import Frozen


class SnippetIntent(Frozen):
    """A vendor-neutral request for a config snippet, e.g. ``action="shutdown_interface"``."""

    action: str = Field(min_length=1)
    target: str = Field(min_length=1)
    params: dict[str, str] = Field(default_factory=dict)


class Snippet(Frozen):
    """A rendered change and the text that undoes it. Never sent to a device by routerscope."""

    apply: str
    rollback: str
    notes: str | None = None


@runtime_checkable
class VendorPlugin(Protocol):
    """What routerscope needs from a vendor.

    Plugins are registered through the ``routerscope.vendors`` entry-point group. Subclass
    :class:`BaseVendorPlugin` rather than implementing everything by hand.
    """

    id: str
    name: str

    def detect(self, text: str) -> float:
        """Confidence (0..1) that ``text`` comes from this vendor."""
        ...

    def segment(self, text: str) -> list[netprompt.Segment]:
        """Split a terminal session into prompt/command/output segments."""
        ...

    def parse_config(self, text: str, snapshot: Snapshot) -> ParsedConfig:
        """Parse a configuration snapshot into neutral objects."""
        ...

    def parse_command(self, command: str, output: str, snapshot: Snapshot) -> ParseResult | None:
        """Parse one command's output; ``None`` if the command is not supported."""
        ...

    def readonly_commands(self) -> Sequence[str]:
        """Commands a read-only collector may send. Each must pass netcmd-safety."""
        ...

    def render_snippet(self, intent: SnippetIntent) -> Snippet | None:
        """Render an apply/rollback snippet for ``intent``; ``None`` if unsupported."""
        ...


class BaseVendorPlugin:
    """Defaults for :class:`VendorPlugin`: override only what the vendor supports.

    Subclasses must set ``id`` and ``name``. By default detection delegates to netprompt,
    segmentation delegates to netprompt, parsing returns empty results, no commands are
    declared and no snippets are rendered.
    """

    id: str = ""
    name: str = ""

    def detect(self, text: str) -> float:
        return 1.0 if netprompt.detect_vendor(text) == self.id else 0.0

    def segment(self, text: str) -> list[netprompt.Segment]:
        return netprompt.segment(text, vendor=self.id)

    def parse_config(self, text: str, snapshot: Snapshot) -> ParsedConfig:
        return ParsedConfig(snapshot_id=snapshot.id, vendor=self.id)

    def parse_command(self, command: str, output: str, snapshot: Snapshot) -> ParseResult | None:
        return None

    def readonly_commands(self) -> Sequence[str]:
        return ()

    def render_snippet(self, intent: SnippetIntent) -> Snippet | None:
        return None
