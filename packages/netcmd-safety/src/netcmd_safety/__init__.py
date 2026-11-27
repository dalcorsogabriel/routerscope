"""Classify network CLI commands as read, session, config or destructive, per vendor.

>>> from netcmd_safety import classify, Verdict
>>> classify("display bgp peer", "huawei_vrp").verdict is Verdict.READ
True
>>> classify("undo peer 192.0.2.1", "huawei_vrp").verdict
<Verdict.DESTRUCTIVE: 'destructive'>
"""

from ._api import classify, classify_lines, is_collector_safe, is_read
from ._model import (
    CISCO_IOS,
    CISCO_XR,
    HUAWEI_VRP,
    IPINFUSION_OCNOS,
    JUNIPER_JUNOS,
    MIKROTIK_ROS7,
    NOKIA_SROS,
    VENDORS,
    Classification,
    Mode,
    UnknownVendorError,
    Verdict,
    worst,
)

__version__ = "0.1.0"

__all__ = [
    "CISCO_IOS",
    "CISCO_XR",
    "HUAWEI_VRP",
    "IPINFUSION_OCNOS",
    "JUNIPER_JUNOS",
    "MIKROTIK_ROS7",
    "NOKIA_SROS",
    "VENDORS",
    "Classification",
    "Mode",
    "UnknownVendorError",
    "Verdict",
    "__version__",
    "classify",
    "classify_lines",
    "is_collector_safe",
    "is_read",
    "worst",
]
