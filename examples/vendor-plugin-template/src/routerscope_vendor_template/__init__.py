"""Template vendor plugin for a fictional 'ExampleOS'. Copy it and replace the ExampleOS bits."""

from __future__ import annotations

import re
from collections.abc import Sequence

from routerscope.model import Device, Interface, ParsedConfig, Snapshot, SourceRef
from routerscope.vendors import BaseVendorPlugin, Snippet, SnippetIntent

_HOSTNAME = re.compile(r"^hostname (\S+)")
_INTERFACE = re.compile(r"^interface (\S+)")
_DESCRIPTION = re.compile(r"^\s+description (.+)$")


class ExamplePlugin(BaseVendorPlugin):
    """Parses ``hostname`` and ``interface`` blocks of an invented CLI."""

    id = "example_os"
    name = "ExampleOS"

    def detect(self, text: str) -> float:
        # Return a confidence between 0 and 1. Look for something only this vendor prints.
        return 1.0 if "ExampleOS" in text else 0.0

    def parse_config(self, text: str, snapshot: Snapshot) -> ParsedConfig:
        device: Device | None = None
        interfaces: list[Interface] = []
        lines = text.splitlines()
        for number, line in enumerate(lines, start=1):
            ref = SourceRef(snapshot_id=snapshot.id, line_start=number, line_end=number)
            if match := _HOSTNAME.match(line):
                device = Device(ref=ref, hostname=match.group(1))
            elif match := _INTERFACE.match(line):
                end = number
                description = None
                # An interface block runs while lines are indented.
                for follow in lines[number:]:
                    if not follow.startswith(" "):
                        break
                    end += 1
                    if desc := _DESCRIPTION.match(follow):
                        description = desc.group(1)
                interfaces.append(
                    Interface(
                        ref=SourceRef(snapshot_id=snapshot.id, line_start=number, line_end=end),
                        name=match.group(1),
                        description=description,
                    )
                )
        return ParsedConfig(
            snapshot_id=snapshot.id,
            vendor=self.id,
            device=device,
            interfaces=tuple(interfaces),
        )

    def readonly_commands(self) -> Sequence[str]:
        # Commands for vendors unknown to netcmd-safety are not used by collectors until the
        # vendor is added there. Known vendors must only list commands netcmd-safety accepts.
        return ("show version", "show running-config")

    def render_snippet(self, intent: SnippetIntent) -> Snippet | None:
        if intent.action == "shutdown_interface":
            return Snippet(
                apply=f"interface {intent.target}\n shutdown",
                rollback=f"interface {intent.target}\n no shutdown",
            )
        return None
