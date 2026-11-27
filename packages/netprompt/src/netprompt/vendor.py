"""Vendor fingerprinting from output text and prompts."""

from __future__ import annotations

import re
from collections import Counter

from netprompt.constants import (
    CISCO_IOS,
    CISCO_XR,
    HUAWEI_VRP,
    IPINFUSION_OCNOS,
    JUNIPER_JUNOS,
    MIKROTIK_ROS7,
    NOKIA_SROS,
)
from netprompt.normalize import normalize
from netprompt.prompt import detect_prompt, parse_banner

_FINGERPRINTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"Huawei Versatile Routing Platform|\bVRP \(R\) software"), HUAWEI_VRP),
    (re.compile(r"Cisco IOS[ -]XR"), CISCO_XR),
    (re.compile(r"Cisco IOS Software|Cisco IOS[ -]XE|IOS-XE Software"), CISCO_IOS),
    (re.compile(r"\bJUNOS\b|\bJunos:"), JUNIPER_JUNOS),
    (re.compile(r"\bTiMOS\b"), NOKIA_SROS),
    (re.compile(r"RouterOS|MikroTik"), MIKROTIK_ROS7),
    (re.compile(r"OcNOS|IP Infusion"), IPINFUSION_OCNOS),
)

FINGERPRINT_WEIGHT = 10


def fingerprint_scores(normalized: str) -> Counter[str]:
    """Score vendors by text fingerprints only (each fingerprint counts once)."""
    scores: Counter[str] = Counter()
    for pattern, vendor in _FINGERPRINTS:
        if pattern.search(normalized):
            scores[vendor] += FINGERPRINT_WEIGHT
    return scores


def vendor_scores(normalized: str) -> Counter[str]:
    """Score vendors by fingerprints plus one vote per vendor-specific prompt or banner line."""
    scores = fingerprint_scores(normalized)
    for line in normalized.split("\n"):
        found = detect_prompt(line)
        if found is not None:
            if found[0].vendor is not None:
                scores[found[0].vendor] += 1
            continue
        banner = parse_banner(line)
        if banner is not None:
            scores[NOKIA_SROS if banner.kind == "mdcli" else JUNIPER_JUNOS] += 1
    return scores


def detect_vendor(text: str) -> str | None:
    """Fingerprint ``text`` (output and/or prompts) and return a vendor id.

    Returns ``None`` if nothing is conclusive, including ties between vendors.
    """
    scores = vendor_scores(normalize(text))
    if not scores:
        return None
    ranked = scores.most_common(2)
    if len(ranked) > 1 and ranked[0][1] == ranked[1][1]:
        return None
    return ranked[0][0]
