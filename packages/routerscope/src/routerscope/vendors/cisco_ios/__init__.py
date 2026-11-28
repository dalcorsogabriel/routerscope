"""Cisco IOS / IOS-XE vendor plugin: detection, config parsing and state-command parsing."""

from __future__ import annotations

from collections.abc import Sequence

from routerscope.model import ParsedConfig, ParseResult, Snapshot
from routerscope.vendors._cmd import dispatch, readonly
from routerscope.vendors.base import BaseVendorPlugin
from routerscope.vendors.cisco_ios.commands import SPECS
from routerscope.vendors.cisco_ios.config import parse_ios_like


class Plugin(BaseVendorPlugin):
    """Detects Cisco IOS / IOS-XE text through netprompt, parses configs and state commands."""

    id = "cisco_ios"
    name = "Cisco IOS / IOS-XE"

    def parse_config(self, text: str, snapshot: Snapshot) -> ParsedConfig:
        return parse_ios_like(text, snapshot, self.id)

    def parse_command(self, command: str, output: str, snapshot: Snapshot) -> ParseResult | None:
        return dispatch(SPECS, command, output, snapshot, self.id)

    def readonly_commands(self) -> Sequence[str]:
        return readonly(SPECS)
