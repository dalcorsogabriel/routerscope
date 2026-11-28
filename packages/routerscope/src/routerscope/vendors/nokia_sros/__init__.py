"""Nokia SR OS vendor plugin: detection plus classic and MD-CLI config parsing."""

from __future__ import annotations

from routerscope.model import ParsedConfig, Snapshot
from routerscope.vendors.base import BaseVendorPlugin
from routerscope.vendors.nokia_sros.config import parse_sros


class Plugin(BaseVendorPlugin):
    """Detects Nokia SR OS text through netprompt and parses its configuration."""

    id = "nokia_sros"
    name = "Nokia SR OS"

    def parse_config(self, text: str, snapshot: Snapshot) -> ParsedConfig:
        return parse_sros(text, snapshot, self.id)
