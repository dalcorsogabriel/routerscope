"""MikroTik RouterOS 7 vendor plugin: detection, config parsing and state-command parsing."""

from __future__ import annotations

from collections.abc import Sequence

from routerscope.model import ParsedConfig, ParseResult, Snapshot
from routerscope.vendors._cmd import dispatch, readonly
from routerscope.vendors.base import BaseVendorPlugin
from routerscope.vendors.mikrotik_ros7.commands import SPECS, normalize
from routerscope.vendors.mikrotik_ros7.config import parse_routeros_config


class Plugin(BaseVendorPlugin):
    """Detects MikroTik RouterOS text through netprompt, parses configs and state commands."""

    id = "mikrotik_ros7"
    name = "MikroTik RouterOS 7"

    def parse_config(self, text: str, snapshot: Snapshot) -> ParsedConfig:
        return parse_routeros_config(text, snapshot, self.id)

    def parse_command(self, command: str, output: str, snapshot: Snapshot) -> ParseResult | None:
        return dispatch(SPECS, command, output, snapshot, self.id, normalize=normalize)

    def readonly_commands(self) -> Sequence[str]:
        return readonly(SPECS)
