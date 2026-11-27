"""Interface-name normalization across vendor families.

Normalization is *within a vendor family*: ``Gi0/0/1`` and ``GigabitEthernet0/0/1`` are the same
Cisco interface. It never maps between vendors (``ether1`` stays ``ether1``).
"""

from __future__ import annotations

import re

__all__ = ["VENDORS", "interface_aliases", "normalize_interface", "same_interface"]

VENDORS = (
    "cisco_ios",
    "cisco_xr",
    "huawei_vrp",
    "mikrotik_ros7",
    "juniper_junos",
    "nokia_sros",
    "ipinfusion_ocnos",
)

# lowercase spelling -> canonical long form
_CISCO_COMMON = {
    "gi": "GigabitEthernet",
    "gigabitethernet": "GigabitEthernet",
    "twe": "TwentyFiveGigE",
    "twentyfivegige": "TwentyFiveGigE",
    "fo": "FortyGigE",
    "fortygige": "FortyGigE",
    "fortygigabitethernet": "FortyGigE",
    "hu": "HundredGigE",
    "hundredgige": "HundredGigE",
    "fa": "FastEthernet",
    "fastethernet": "FastEthernet",
    "eth": "Ethernet",
    "ethernet": "Ethernet",
    "po": "Port-channel",
    "port-channel": "Port-channel",
    "be": "Bundle-Ether",
    "bundle-ether": "Bundle-Ether",
    "lo": "Loopback",
    "loopback": "Loopback",
    "vl": "Vlan",
    "vlan": "Vlan",
    "tu": "Tunnel",
    "tunnel": "Tunnel",
    "mg": "MgmtEth",
    "mgmteth": "MgmtEth",
    "se": "Serial",
    "serial": "Serial",
    "bdi": "BDI",
}
_CISCO_IOS = {
    **_CISCO_COMMON,
    "te": "TenGigabitEthernet",
    "tengigabitethernet": "TenGigabitEthernet",
    "tengige": "TenGigabitEthernet",
}
_CISCO_XR = {
    **_CISCO_COMMON,
    "te": "TenGigE",
    "tengige": "TenGigE",
    "tengigabitethernet": "TenGigE",
}
# Family unknown (IOS vs XR): IOS spellings, except the XR-only long name TenGigE.
_CISCO_ANY = {**_CISCO_IOS, "tengige": "TenGigE"}

_HUAWEI = {
    "ge": "GigabitEthernet",
    "gigabitethernet": "GigabitEthernet",
    "xge": "XGigabitEthernet",
    "xgigabitethernet": "XGigabitEthernet",
    "10ge": "10GE",
    "25ge": "25GE",
    "40ge": "40GE",
    "100ge": "100GE",
    "eth-trunk": "Eth-Trunk",
    "loopback": "LoopBack",
    "vlanif": "Vlanif",
    "null": "NULL",
    "meth": "MEth",
    "ethernet": "Ethernet",
    "tunnel": "Tunnel",
}

_SHORT = {
    "GigabitEthernet": "Gi",
    "TenGigabitEthernet": "Te",
    "TenGigE": "Te",
    "TwentyFiveGigE": "Twe",
    "FortyGigE": "Fo",
    "HundredGigE": "Hu",
    "FastEthernet": "Fa",
    "Ethernet": "Eth",
    "Port-channel": "Po",
    "Bundle-Ether": "BE",
    "Loopback": "Lo",
    "Vlan": "Vl",
    "Tunnel": "Tu",
    "MgmtEth": "Mg",
    "Serial": "Se",
}
_HUAWEI_SHORT = {"GigabitEthernet": "GE", "XGigabitEthernet": "XGE"}

_NAME_RE = re.compile(r"(?P<type>\d+GE|[A-Za-z][A-Za-z-]*)\s*(?P<num>\d[\w/.:]*)?", re.IGNORECASE)

_JUNOS_RE = re.compile(
    r"(?:(?:ge|xe|et|fe|xle|so|em|fxp|vme|me)-\d[\w/.:]*|(?:ae|reth)\d+(?:\.\d+)?|irb(?:\.\d+)?)",
    re.IGNORECASE,
)
_ROS_RE = re.compile(
    r"(?:ether|sfp-sfpplus|sfpplus|sfp|qsfp\w*|wlan|wifi|bridge|bonding|bond|vrrp|lte|combo"
    r"|pppoe-out|pppoe-in|l2tp-out)\d*(?:\.\d+)?",
    re.IGNORECASE,
)
_SROS_RE = re.compile(r"(?:\d+/\d+/(?:c\d+/)?\d+|esat-\d\S*|lag-\d+|system)", re.IGNORECASE)
_OCNOS_RE = re.compile(r"(?:(?:xe|ge)\d+(?:\.\d+)?|lo)", re.IGNORECASE)


def _split(name: str) -> tuple[str, str] | None:
    m = _NAME_RE.fullmatch(name)
    if m is None:
        return None
    return m.group("type"), m.group("num") or ""


def _infer(name: str) -> str | None:
    """Best-effort vendor family for ``name``; None when unknown."""
    parts = _split(name)
    if parts is not None:
        t, num = parts[0].lower(), parts[1]
        if t in {"xge", "xgigabitethernet", "eth-trunk", "vlanif", "meth", "null"} or re.fullmatch(
            r"\d+ge", t
        ):
            return "huawei_vrp"
        if t == "ge" and "/" in num:
            return "huawei_vrp"
    if _JUNOS_RE.fullmatch(name):
        return "juniper_junos"
    if _ROS_RE.fullmatch(name):
        return "mikrotik_ros7"
    if _SROS_RE.fullmatch(name):
        return "nokia_sros"
    if _OCNOS_RE.fullmatch(name):
        return "ipinfusion_ocnos"
    if parts is not None and parts[0].lower() in _CISCO_ANY:
        return "cisco_ios"
    return None


def _table(vendor: str, inferred: bool) -> dict[str, str] | None:
    if vendor == "cisco_ios":
        return _CISCO_ANY if inferred else _CISCO_IOS
    if vendor == "cisco_xr":
        return _CISCO_XR
    if vendor == "huawei_vrp":
        return _HUAWEI
    return None


def _resolve(name: str, vendor: str | None) -> tuple[str, str | None]:
    name = name.strip()
    if vendor is not None and vendor not in VENDORS:
        raise ValueError(f"unknown vendor: {vendor!r}")
    return name, vendor if vendor is not None else _infer(name)


def normalize_interface(name: str, vendor: str | None = None) -> str:
    """Return the canonical long form of an interface name within its vendor family.

    ``vendor`` is one of :data:`VENDORS`; when ``None`` the family is inferred from the name
    where unambiguous (``Gi0/0/1`` -> Cisco, ``GE0/0/1`` -> Huawei). Unknown names are returned
    stripped but otherwise unchanged. Junos and OcNOS names are lowercased; RouterOS and SR OS
    names are kept as written.
    """
    name, fam = _resolve(name, vendor)
    if fam is None:
        return name
    if fam in ("juniper_junos", "ipinfusion_ocnos"):
        return name.lower()
    table = _table(fam, vendor is None)
    if table is None:
        return name
    parts = _split(name)
    if parts is None:
        return name
    canon = table.get(parts[0].lower())
    if canon is None:
        return name
    return canon + parts[1]


def interface_aliases(name: str, vendor: str | None = None) -> frozenset[str]:
    """Return the spellings that refer to the same interface within its vendor family.

    For Cisco and Huawei this is the canonical long form and every known short/long type
    spelling, each as written, lowercased, uppercased and capitalized, followed by the
    port/sub-interface number. For other families it is the canonical name and its lowercase
    form. Matching of arbitrary casing is done by :func:`same_interface`.
    """
    canon = normalize_interface(name, vendor)
    _, fam = _resolve(name, vendor)
    table = _table(fam, vendor is None) if fam else None
    parts = _split(canon)
    if table is None or parts is None or parts[0] not in set(table.values()):
        return frozenset({canon, canon.lower()})
    ctype, num = parts
    short = (_HUAWEI_SHORT if fam == "huawei_vrp" else _SHORT).get(ctype)
    spellings = {ctype, *(k for k, v in table.items() if v == ctype)}
    if short:
        spellings.add(short)
    out: set[str] = set()
    for s in spellings:
        for variant in (s, s.lower(), s.upper(), s.capitalize()):
            out.add(variant + num)
    return frozenset(out)


def same_interface(a: str, b: str, vendor: str | None = None) -> bool:
    """True when ``a`` and ``b`` name the same interface (case-insensitive, short/long forms)."""
    return normalize_interface(a, vendor).casefold() == normalize_interface(b, vendor).casefold()
