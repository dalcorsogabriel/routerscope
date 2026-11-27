"""Huawei VRP vendor plugin (stub: detection only; parsing arrives in a later milestone)."""

from __future__ import annotations

from routerscope.vendors.base import BaseVendorPlugin


class Plugin(BaseVendorPlugin):
    """Detects Huawei VRP text through netprompt and parses nothing yet."""

    id = "huawei_vrp"
    name = "Huawei VRP"
