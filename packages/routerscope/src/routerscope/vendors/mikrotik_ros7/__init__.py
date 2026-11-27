"""MikroTik RouterOS 7 vendor plugin (stub: detection only for now)."""

from __future__ import annotations

from routerscope.vendors.base import BaseVendorPlugin


class Plugin(BaseVendorPlugin):
    """Detects MikroTik RouterOS 7 text through netprompt and parses nothing yet."""

    id = "mikrotik_ros7"
    name = "MikroTik RouterOS 7"
