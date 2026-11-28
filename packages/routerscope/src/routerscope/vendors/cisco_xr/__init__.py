"""Cisco IOS XR vendor plugin: detection, config parsing and state-command parsing."""

from __future__ import annotations

from collections.abc import Sequence

from routerscope.model import ParsedConfig, ParseResult, Snapshot
from routerscope.vendors._cmd import dispatch, readonly
from routerscope.vendors.base import BaseVendorPlugin
from routerscope.vendors.cisco_xr.commands import SPECS
from routerscope.vendors.cisco_xr.config import parse_xr


class Plugin(BaseVendorPlugin):
    """Detects Cisco IOS XR text through netprompt, parses configs and state commands."""

    id = "cisco_xr"
    name = "Cisco IOS XR"

    def parse_config(self, text: str, snapshot: Snapshot) -> ParsedConfig:
        return parse_xr(text, snapshot, self.id)

    def parse_command(self, command: str, output: str, snapshot: Snapshot) -> ParseResult | None:
        return dispatch(SPECS, command, output, snapshot, self.id)

    def readonly_commands(self) -> Sequence[str]:
        return readonly(SPECS)
