"""Nokia SR OS vendor plugin (stub: detection only; parsing arrives in a later milestone)."""

from __future__ import annotations

from routerscope.vendors.base import BaseVendorPlugin


class Plugin(BaseVendorPlugin):
    """Detects Nokia SR OS text through netprompt and parses nothing yet."""

    id = "nokia_sros"
    name = "Nokia SR OS"
