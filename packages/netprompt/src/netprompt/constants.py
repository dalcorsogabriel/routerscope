"""Vendor identifiers used across netprompt."""

from __future__ import annotations

CISCO_IOS = "cisco_ios"
"""Cisco IOS and IOS-XE."""
CISCO_XR = "cisco_xr"
HUAWEI_VRP = "huawei_vrp"
MIKROTIK_ROS7 = "mikrotik_ros7"
JUNIPER_JUNOS = "juniper_junos"
NOKIA_SROS = "nokia_sros"
IPINFUSION_OCNOS = "ipinfusion_ocnos"

VENDORS: tuple[str, ...] = (
    CISCO_IOS,
    CISCO_XR,
    HUAWEI_VRP,
    MIKROTIK_ROS7,
    JUNIPER_JUNOS,
    NOKIA_SROS,
    IPINFUSION_OCNOS,
)
