from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from netaddr_search import (
    VENDORS,
    interface_aliases,
    normalize_interface,
    same_interface,
)


@pytest.mark.parametrize(
    ("name", "vendor", "expected"),
    [
        ("Gi0/0/1", "cisco_ios", "GigabitEthernet0/0/1"),
        ("gi0/0/1", "cisco_ios", "GigabitEthernet0/0/1"),
        ("GIGABITETHERNET0/0/1", "cisco_ios", "GigabitEthernet0/0/1"),
        ("Gi0/0/1.100", "cisco_ios", "GigabitEthernet0/0/1.100"),
        ("Gi 0/0/1", "cisco_ios", "GigabitEthernet0/0/1"),
        ("Te1/0/1", "cisco_ios", "TenGigabitEthernet1/0/1"),
        ("Te0/0/0/1", "cisco_xr", "TenGigE0/0/0/1"),
        ("TenGigE0/0/0/1", "cisco_xr", "TenGigE0/0/0/1"),
        ("Twe1/0/1", "cisco_ios", "TwentyFiveGigE1/0/1"),
        ("Fo1/0/1", "cisco_ios", "FortyGigE1/0/1"),
        ("Hu0/0/0/0", "cisco_xr", "HundredGigE0/0/0/0"),
        ("Fa0/1", "cisco_ios", "FastEthernet0/1"),
        ("Eth1/1", "cisco_ios", "Ethernet1/1"),
        ("Po10", "cisco_ios", "Port-channel10"),
        ("BE100", "cisco_xr", "Bundle-Ether100"),
        ("Lo0", "cisco_ios", "Loopback0"),
        ("Vl100", "cisco_ios", "Vlan100"),
        ("Tu1", "cisco_ios", "Tunnel1"),
        ("Mg0/RP0/CPU0/0", "cisco_xr", "MgmtEth0/RP0/CPU0/0"),
        ("Se0/0/0", "cisco_ios", "Serial0/0/0"),
        ("bdi10", "cisco_ios", "BDI10"),
        ("GE0/0/1", "huawei_vrp", "GigabitEthernet0/0/1"),
        ("XGE0/0/1", "huawei_vrp", "XGigabitEthernet0/0/1"),
        ("25GE0/0/1", "huawei_vrp", "25GE0/0/1"),
        ("100ge0/0/1", "huawei_vrp", "100GE0/0/1"),
        ("40GE0/0/1", "huawei_vrp", "40GE0/0/1"),
        ("eth-trunk1", "huawei_vrp", "Eth-Trunk1"),
        ("loopback0", "huawei_vrp", "LoopBack0"),
        ("vlanif100", "huawei_vrp", "Vlanif100"),
        ("null0", "huawei_vrp", "NULL0"),
        ("meth0/0/1", "huawei_vrp", "MEth0/0/1"),
        ("GE0/0/1.10", "huawei_vrp", "GigabitEthernet0/0/1.10"),
        ("GE-0/0/0.0", "juniper_junos", "ge-0/0/0.0"),
        ("xe-0/0/0", "juniper_junos", "xe-0/0/0"),
        ("et-0/0/0", "juniper_junos", "et-0/0/0"),
        ("AE0", "juniper_junos", "ae0"),
        ("lo0.0", "juniper_junos", "lo0.0"),
        ("irb.10", "juniper_junos", "irb.10"),
        ("ether1", "mikrotik_ros7", "ether1"),
        ("sfp-sfpplus1", "mikrotik_ros7", "sfp-sfpplus1"),
        ("bridge", "mikrotik_ros7", "bridge"),
        ("vlan100", "mikrotik_ros7", "vlan100"),
        ("1/1/1", "nokia_sros", "1/1/1"),
        ("1/1/c1/1", "nokia_sros", "1/1/c1/1"),
        ("esat-1/1/1", "nokia_sros", "esat-1/1/1"),
        ("lag-1", "nokia_sros", "lag-1"),
        ("system", "nokia_sros", "system"),
        ("XE1", "ipinfusion_ocnos", "xe1"),
        ("ge1", "ipinfusion_ocnos", "ge1"),
        ("PO1", "ipinfusion_ocnos", "po1"),
        ("lo", "ipinfusion_ocnos", "lo"),
        # inference
        ("Gi0/0/1", None, "GigabitEthernet0/0/1"),
        ("GE0/0/1", None, "GigabitEthernet0/0/1"),
        ("TenGigE0/0/0/1", None, "TenGigE0/0/0/1"),
        ("Te1/0/1", None, "TenGigabitEthernet1/0/1"),
        ("XGE0/0/1", None, "XGigabitEthernet0/0/1"),
        ("100GE0/0/1", None, "100GE0/0/1"),
        ("Eth-Trunk1", None, "Eth-Trunk1"),
        ("Vlanif10", None, "Vlanif10"),
        ("ge-0/0/0", None, "ge-0/0/0"),
        ("ae1", None, "ae1"),
        ("ether1", None, "ether1"),
        ("1/1/c1/1", None, "1/1/c1/1"),
        ("lag-1", None, "lag-1"),
        ("xe1", None, "xe1"),
        ("po1", None, "Port-channel1"),
        ("  Lo0  ", None, "Loopback0"),
        ("weird-name", None, "weird-name"),
        ("", None, ""),
        # unknown type for explicit vendor, or unparsable
        ("foo1", "cisco_ios", "foo1"),
        ("Gi0/0/1 extra", "cisco_ios", "Gi0/0/1 extra"),
    ],
)
def test_normalize(name: str, vendor: str | None, expected: str) -> None:
    assert normalize_interface(name, vendor) == expected


def test_unknown_vendor() -> None:
    with pytest.raises(ValueError, match="unknown vendor"):
        normalize_interface("Gi0", "acme")


def test_aliases_cisco() -> None:
    al = interface_aliases("Gi0/0/1", "cisco_ios")
    assert {"Gi0/0/1", "GigabitEthernet0/0/1", "gi0/0/1", "gigabitethernet0/0/1"} <= al
    assert all(same_interface(x, "Gi0/0/1", "cisco_ios") for x in al)
    xr = interface_aliases("TenGigE0/0/0/1", "cisco_xr")
    assert {"Te0/0/0/1", "TenGigE0/0/0/1"} <= xr


def test_aliases_huawei_and_others() -> None:
    assert {"GE0/0/1", "GigabitEthernet0/0/1", "ge0/0/1"} <= interface_aliases("GE0/0/1")
    assert interface_aliases("ether1", "mikrotik_ros7") == {"ether1"}
    assert interface_aliases("Ether1", "mikrotik_ros7") == {"Ether1", "ether1"}
    assert interface_aliases("weird") == {"weird"}
    assert interface_aliases("Eth-Trunk1", "huawei_vrp") >= {"Eth-Trunk1", "eth-trunk1"}


def test_same_interface() -> None:
    assert same_interface("Gi0/0/1", "gigabitethernet0/0/1")
    assert same_interface("GE0/0/1", "GigabitEthernet0/0/1", "huawei_vrp")
    assert not same_interface("Gi0/0/1", "Gi0/0/2")
    assert same_interface("ETHER1", "ether1")


_numbers = st.from_regex(r"\d{1,2}(/\d{1,2}){0,3}(\.\d{1,3})?", fullmatch=True)
_prefixes = st.sampled_from(
    [
        "Gi", "GigabitEthernet", "Te", "TenGigE", "Twe", "Fo", "Hu", "Fa", "Eth", "Po", "BE",
        "Lo", "Vl", "Tu", "Mg", "Se", "BDI", "GE", "XGE", "25GE", "40GE", "100GE", "Eth-Trunk",
        "LoopBack", "Vlanif", "NULL", "MEth", "ge-", "xe-", "et-", "ae", "lo", "irb", "ether",
        "sfp-sfpplus", "bridge", "vlan", "lag-", "esat-", "xe", "po", "",
    ]
)  # fmt: skip
_names = st.builds(lambda p, n: p + n, _prefixes, _numbers)
_vendors = st.sampled_from([None, *VENDORS])


@given(_names, _vendors)
def test_normalize_idempotent(name: str, vendor: str | None) -> None:
    once = normalize_interface(name, vendor)
    assert normalize_interface(once, vendor) == once


@given(st.text(max_size=20), _vendors)
def test_normalize_idempotent_text(name: str, vendor: str | None) -> None:
    once = normalize_interface(name, vendor)
    assert normalize_interface(once, vendor) == once


@given(_names, _names, _vendors)
def test_same_interface_symmetric(a: str, b: str, vendor: str | None) -> None:
    assert same_interface(a, b, vendor) == same_interface(b, a, vendor)
    assert same_interface(a, a, vendor)


@given(_names, _vendors)
def test_aliases_are_same_interface(name: str, vendor: str | None) -> None:
    for alias in interface_aliases(name, vendor):
        assert same_interface(alias, name, vendor)
