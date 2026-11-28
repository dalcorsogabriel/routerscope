"""MikroTik RouterOS 7 vendor plugin: detection plus ``/export`` config parsing."""

from __future__ import annotations

from routerscope.model import ParsedConfig, Snapshot
from routerscope.vendors.base import BaseVendorPlugin
from routerscope.vendors.mikrotik_ros7.config import parse_routeros_config


class Plugin(BaseVendorPlugin):
    """Detects MikroTik RouterOS text through netprompt and parses its configuration."""

    id = "mikrotik_ros7"
    name = "MikroTik RouterOS 7"

    def parse_config(self, text: str, snapshot: Snapshot) -> ParsedConfig:
        return parse_routeros_config(text, snapshot, self.id)
