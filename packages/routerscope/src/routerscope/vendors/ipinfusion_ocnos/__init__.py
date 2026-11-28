"""IP Infusion OcNOS vendor plugin: detection plus config parsing (IOS-like syntax)."""

from __future__ import annotations

from routerscope.model import ParsedConfig, Snapshot
from routerscope.vendors.base import BaseVendorPlugin
from routerscope.vendors.cisco_ios.config import parse_ios_like


class Plugin(BaseVendorPlugin):
    """Detects IP Infusion OcNOS text through netprompt and parses its configuration."""

    id = "ipinfusion_ocnos"
    name = "IP Infusion OcNOS"

    def parse_config(self, text: str, snapshot: Snapshot) -> ParsedConfig:
        return parse_ios_like(text, snapshot, self.id)
