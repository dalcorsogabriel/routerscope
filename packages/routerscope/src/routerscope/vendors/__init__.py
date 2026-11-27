"""Vendor plugins: the interface, the registry and the built-in vendors."""

from routerscope.vendors.base import BaseVendorPlugin, Snippet, SnippetIntent, VendorPlugin
from routerscope.vendors.registry import (
    ENTRY_POINT_GROUP,
    VendorRegistry,
    all_plugins,
    default_registry,
    detect_vendor,
    get,
)

__all__ = [
    "ENTRY_POINT_GROUP",
    "BaseVendorPlugin",
    "Snippet",
    "SnippetIntent",
    "VendorPlugin",
    "VendorRegistry",
    "all_plugins",
    "default_registry",
    "detect_vendor",
    "get",
]
