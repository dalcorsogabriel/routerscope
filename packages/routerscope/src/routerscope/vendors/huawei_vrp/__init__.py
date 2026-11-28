"""Huawei VRP vendor plugin: detection plus hierarchical config parsing."""

from __future__ import annotations

from routerscope.model import ParsedConfig, Snapshot
from routerscope.vendors.base import BaseVendorPlugin
from routerscope.vendors.huawei_vrp.config import parse_vrp


class Plugin(BaseVendorPlugin):
    """Detects Huawei VRP text through netprompt and parses its configuration."""

    id = "huawei_vrp"
    name = "Huawei VRP"

    def parse_config(self, text: str, snapshot: Snapshot) -> ParsedConfig:
        return parse_vrp(text, snapshot, self.id)
