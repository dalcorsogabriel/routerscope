"""Nokia SR OS vendor plugin: detection, config parsing and state-command parsing."""

from __future__ import annotations

from collections.abc import Sequence

from routerscope.model import ParsedConfig, ParseResult, Snapshot
from routerscope.vendors._cmd import dispatch, readonly
from routerscope.vendors.base import BaseVendorPlugin
from routerscope.vendors.nokia_sros.commands import SPECS
from routerscope.vendors.nokia_sros.config import parse_sros


class Plugin(BaseVendorPlugin):
    """Detects Nokia SR OS text through netprompt, parses configs and state commands."""

    id = "nokia_sros"
    name = "Nokia SR OS"

    def parse_config(self, text: str, snapshot: Snapshot) -> ParsedConfig:
        return parse_sros(text, snapshot, self.id)

    def parse_command(self, command: str, output: str, snapshot: Snapshot) -> ParseResult | None:
        return dispatch(SPECS, command, output, snapshot, self.id)

    def readonly_commands(self) -> Sequence[str]:
        return readonly(SPECS)
