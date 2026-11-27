"""Vendor registry."""

from __future__ import annotations

from .._engine import VendorSpec
from .._model import (
    CISCO_IOS,
    CISCO_XR,
    HUAWEI_VRP,
    IPINFUSION_OCNOS,
    JUNIPER_JUNOS,
    NOKIA_SROS,
)
from .cisco import IOS, OCNOS, XR
from .huawei import VRP
from .juniper import JUNOS
from .nokia import SROS

TREE_SPECS: dict[str, VendorSpec] = {
    CISCO_IOS: IOS,
    CISCO_XR: XR,
    IPINFUSION_OCNOS: OCNOS,
    HUAWEI_VRP: VRP,
    JUNIPER_JUNOS: JUNOS,
    NOKIA_SROS: SROS,
}
