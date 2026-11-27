"""IP Infusion OcNOS vendor plugin (stub: detection only; parsing arrives in a later milestone)."""

from __future__ import annotations

from routerscope.vendors.base import BaseVendorPlugin


class Plugin(BaseVendorPlugin):
    """Detects IP Infusion OcNOS text through netprompt and parses nothing yet."""

    id = "ipinfusion_ocnos"
    name = "IP Infusion OcNOS"
