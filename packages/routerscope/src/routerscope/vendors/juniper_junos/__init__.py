"""Juniper Junos vendor plugin: detection, config parsing and state-command parsing."""

from __future__ import annotations

from collections.abc import Sequence

from routerscope.model import ParsedConfig, ParseResult, Snapshot
from routerscope.vendors._cmd import dispatch, readonly
from routerscope.vendors.base import BaseVendorPlugin
from routerscope.vendors.juniper_junos.commands import SPECS
from routerscope.vendors.juniper_junos.config import parse_junos


class Plugin(BaseVendorPlugin):
    """Detects Junos text through netprompt, parses configs and state commands."""

    id = "juniper_junos"
    name = "Juniper Junos"

    def parse_config(self, text: str, snapshot: Snapshot) -> ParsedConfig:
        return parse_junos(text, snapshot, self.id)

    def parse_command(self, command: str, output: str, snapshot: Snapshot) -> ParseResult | None:
        return dispatch(
            SPECS, command, output, snapshot, self.id, harmless_pipes=frozenset({"no-more"})
        )

    def readonly_commands(self) -> Sequence[str]:
        return readonly(SPECS)
