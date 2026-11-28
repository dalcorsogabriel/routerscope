"""Cisco IOS / IOS-XE vendor plugin: detection plus hierarchical config parsing."""

from __future__ import annotations

from routerscope.model import ParsedConfig, Snapshot
from routerscope.vendors.base import BaseVendorPlugin
from routerscope.vendors.cisco_ios.config import parse_ios_like


class Plugin(BaseVendorPlugin):
    """Detects Cisco IOS / IOS-XE text through netprompt and parses its configuration."""

    id = "cisco_ios"
    name = "Cisco IOS / IOS-XE"

    def parse_config(self, text: str, snapshot: Snapshot) -> ParsedConfig:
        return parse_ios_like(text, snapshot, self.id)
