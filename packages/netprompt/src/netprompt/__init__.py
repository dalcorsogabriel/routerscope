"""Prompt/vendor/mode detection and terminal session segmentation."""

from netprompt.constants import (
    CISCO_IOS,
    CISCO_XR,
    HUAWEI_VRP,
    IPINFUSION_OCNOS,
    JUNIPER_JUNOS,
    MIKROTIK_ROS7,
    NOKIA_SROS,
    VENDORS,
)
from netprompt.normalize import normalize
from netprompt.prompt import Mode, Prompt, detect_prompt, is_prompt_banner
from netprompt.segment import Segment, segment
from netprompt.vendor import detect_vendor

__version__ = "0.0.1"

__all__ = [
    "CISCO_IOS",
    "CISCO_XR",
    "HUAWEI_VRP",
    "IPINFUSION_OCNOS",
    "JUNIPER_JUNOS",
    "MIKROTIK_ROS7",
    "NOKIA_SROS",
    "VENDORS",
    "Mode",
    "Prompt",
    "Segment",
    "__version__",
    "detect_prompt",
    "detect_vendor",
    "is_prompt_banner",
    "normalize",
    "segment",
]
