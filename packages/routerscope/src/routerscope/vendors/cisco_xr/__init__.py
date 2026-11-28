"""Cisco IOS XR vendor plugin: detection plus hierarchical config parsing."""

from __future__ import annotations

from routerscope.model import ParsedConfig, Snapshot
from routerscope.vendors.base import BaseVendorPlugin
from routerscope.vendors.cisco_xr.config import parse_xr


class Plugin(BaseVendorPlugin):
    """Detects Cisco IOS XR text through netprompt and parses its configuration."""

    id = "cisco_xr"
    name = "Cisco IOS XR"

    def parse_config(self, text: str, snapshot: Snapshot) -> ParsedConfig:
        return parse_xr(text, snapshot, self.id)
