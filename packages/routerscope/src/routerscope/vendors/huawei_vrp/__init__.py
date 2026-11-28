"""Huawei VRP vendor plugin: detection, config parsing and state-command parsing."""

from __future__ import annotations

from collections.abc import Sequence

from routerscope.model import ParsedConfig, ParseResult, Snapshot
from routerscope.vendors._cmd import dispatch, readonly
from routerscope.vendors.base import BaseVendorPlugin
from routerscope.vendors.huawei_vrp.commands import SPECS
from routerscope.vendors.huawei_vrp.config import parse_vrp


class Plugin(BaseVendorPlugin):
    """Detects Huawei VRP text through netprompt, parses configs and state commands."""

    id = "huawei_vrp"
    name = "Huawei VRP"

    def parse_config(self, text: str, snapshot: Snapshot) -> ParsedConfig:
        return parse_vrp(text, snapshot, self.id)

    def parse_command(self, command: str, output: str, snapshot: Snapshot) -> ParseResult | None:
        return dispatch(SPECS, command, output, snapshot, self.id)

    def readonly_commands(self) -> Sequence[str]:
        return readonly(SPECS)
