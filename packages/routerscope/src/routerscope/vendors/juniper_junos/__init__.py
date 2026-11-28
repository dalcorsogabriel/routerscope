"""Juniper Junos vendor plugin: detection plus hierarchical and set-form config parsing."""

from __future__ import annotations

from routerscope.model import ParsedConfig, Snapshot
from routerscope.vendors.base import BaseVendorPlugin
from routerscope.vendors.juniper_junos.config import parse_junos


class Plugin(BaseVendorPlugin):
    """Detects Junos text through netprompt and parses its configuration."""

    id = "juniper_junos"
    name = "Juniper Junos"

    def parse_config(self, text: str, snapshot: Snapshot) -> ParsedConfig:
        return parse_junos(text, snapshot, self.id)
