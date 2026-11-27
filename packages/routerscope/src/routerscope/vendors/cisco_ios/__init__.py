"""Cisco IOS / IOS-XE vendor plugin (stub: detection only; parsing arrives in a later milestone)."""

from __future__ import annotations

from routerscope.vendors.base import BaseVendorPlugin


class Plugin(BaseVendorPlugin):
    """Detects Cisco IOS / IOS-XE text through netprompt and parses nothing yet."""

    id = "cisco_ios"
    name = "Cisco IOS / IOS-XE"
