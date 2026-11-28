"""Helpers shared by the text-based importers: decoding and config heuristics."""

from __future__ import annotations

import logging
import re

from routerscope.vendors.registry import VendorRegistry, default_registry

__all__ = ["config_hostname", "decode_bytes", "looks_like_config"]

logger = logging.getLogger(__name__)

_BOMS: tuple[tuple[bytes, str], ...] = (
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe", "utf-16"),
    (b"\xfe\xff", "utf-16"),
)


def decode_bytes(data: bytes) -> str:
    """Decode a log file's bytes.

    Recognises a UTF-8 BOM, a UTF-16 BOM and BOM-less UTF-16 (detected by NUL bytes
    interleaved with text, as written by Windows PowerShell 5.1 redirection). Anything else is
    read as UTF-8; undecodable bytes become U+FFFD and a warning is logged.
    """
    for bom, codec in _BOMS:
        if data.startswith(bom):
            return data.decode(codec, errors="replace")
    sample = data[:400]
    if len(sample) >= 4 and sample.count(0) * 4 >= len(sample):
        even = sample[0::2].count(0)
        odd = sample[1::2].count(0)
        codec = "utf-16-le" if odd >= even else "utf-16-be"
        return data.decode(codec, errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        logger.warning("input is not valid UTF-8; undecodable bytes were replaced")
        return data.decode("utf-8", errors="replace")


_CONFIG_LINE = re.compile(
    r"^(?:hostname\s+\S+|sysname\s+\S+|interface\s+\S+|router\s+(?:bgp|ospf|isis|ospfv3)\b"
    r"|ip(?:v6)?\s+route\s|vlan\s+\d+|bgp\s+\d+|ospf\s+\d+|set\s+(?:system|interfaces|protocols"
    r"|routing-options|policy-options|firewall)\b|/(?:interface|ip|ipv6|system|routing|snmp)\b"
    r"|(?:system|interfaces|protocols|routing-options|policy-options)\s*\{"
    r"|#\s.*\bby RouterOS\b|!\s*$|return\s*$|configure\s*$|\s*exit all\s*$)",
    re.MULTILINE,
)
_HOSTNAME = (
    re.compile(r"^hostname\s+(\S+)", re.MULTILINE),
    re.compile(r"^sysname\s+(\S+)", re.MULTILINE),
    re.compile(r"^set system host-name\s+(\S+)", re.MULTILINE),
    re.compile(r"^\s*host-name\s+(\S+)", re.MULTILINE),
    re.compile(r"^/system identity\s*\n\s*set name=(\S+)", re.MULTILINE),
)


def looks_like_config(text: str, registry: VendorRegistry | None = None) -> bool:
    """Heuristic: is ``text`` a device configuration (and not command output)?

    True when at least three lines look like configuration statements (``hostname``,
    ``interface``, ``router bgp``, ``set system ...``, ``/interface ...``, ``system {``,
    bare ``!`` separators...), or when one does and a vendor plugin recognises the text.
    """
    count = len(_CONFIG_LINE.findall(text))
    if count >= 3:
        return True
    if count == 0:
        return False
    reg = registry if registry is not None else default_registry()
    return reg.detect_vendor(text) is not None


def config_hostname(text: str) -> str | None:
    """The hostname a configuration declares about itself, if a known statement is present."""
    for pattern in _HOSTNAME:
        match = pattern.search(text)
        if match:
            return match.group(1).strip("\";'") or None
    return None
