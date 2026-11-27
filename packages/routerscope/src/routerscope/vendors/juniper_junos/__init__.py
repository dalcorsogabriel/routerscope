"""Juniper Junos vendor plugin (stub: detection only; parsing arrives in a later milestone)."""

from __future__ import annotations

from routerscope.vendors.base import BaseVendorPlugin


class Plugin(BaseVendorPlugin):
    """Detects Juniper Junos text through netprompt and parses nothing yet."""

    id = "juniper_junos"
    name = "Juniper Junos"
