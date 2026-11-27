"""Cisco IOS XR vendor plugin (stub: detection only; parsing arrives in a later milestone)."""

from __future__ import annotations

from routerscope.vendors.base import BaseVendorPlugin


class Plugin(BaseVendorPlugin):
    """Detects Cisco IOS XR text through netprompt and parses nothing yet."""

    id = "cisco_xr"
    name = "Cisco IOS XR"
