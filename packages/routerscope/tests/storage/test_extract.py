from __future__ import annotations

import pytest
from routerscope.storage.extract import (
    extract_asns,
    extract_communities,
    extract_interfaces,
    extract_rows,
)


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("router bgp 64496", [(64496, "router bgp")]),
        (" neighbor 192.0.2.2 remote-as 64497", [(64497, "remote-as")]),
        (" neighbor 192.0.2.2 remote-as external", []),
        (" neighbor 192.0.2.2 local-as 64500 no-prepend", [(64500, "local-as")]),
        ("bgp 65536", [(65536, "bgp")]),
        (" peer 192.0.2.2 as-number 64497", [(64497, "as-number")]),
        ("set routing-options autonomous-system 64496;", [(64496, "autonomous-system")]),
        ("set protocols bgp group x peer-as 64498;", [(64498, "peer-as")]),
        ("autonomous-system 65540", [(65540, "autonomous-system")]),
        ("/routing bgp template set default as=65536", [(65536, "as")]),
        ("add name=p remote.as=64499 local.role=ebgp", [(64499, "remote.as")]),
        ("BGP neighbor is 192.0.2.2, remote AS 64497, external link", [(64497, "remote as")]),
        ("local AS number 64496", [(64496, "local as number")]),
        ("peer AS64500 is down", [(64500, "as")]),
        ("router bgp 1.1", [(65537, "router bgp")]),
        ("router bgp 70000.1", []),
        ("router bgp 0", []),
        ("remote-as 4294967296", []),
        ("has=65536 ip 10 as 5", []),
        ("remote-as 64497.", []),
    ],
)
def test_asn(line: str, expected: list[tuple[int, str]]) -> None:
    assert extract_asns(line) == expected


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (" set community 64496:100 additive", [("64496:100", "standard")]),
        ("ip community-list 1 permit 64496:100", [("64496:100", "standard")]),
        (" set large-community 64496:1:2", [("64496:1:2", "large")]),
        ("set community no-export", [("no-export", "well_known")]),
        (
            "community X members [ 64496:100 no-advertise ]",
            [
                ("64496:100", "standard"),
                ("no-advertise", "well_known"),
            ],
        ),
        ("set bgp-communities=64496:200", [("64496:200", "standard")]),
        ("set community 70000:1", []),
        ("set large-community 4294967296:1:2", []),
        ("Community: 64496:100 64496:100", [("64496:100", "standard")]),
        ("no-export on a line without the keyword 64496:100", []),
        ("community 12:30:45 text", [("12:30:45", "large")]),
        ("community 2001:db8::1", []),
    ],
)
def test_communities(line: str, expected: list[tuple[str, str]]) -> None:
    assert extract_communities(line) == expected


@pytest.mark.parametrize(
    ("line", "vendor", "expected"),
    [
        ("interface GigabitEthernet0/0/1", "cisco_ios", ["GigabitEthernet0/0/1"]),
        (" shutdown Gi0/0/1 and gi0/0/1", "cisco_ios", ["GigabitEthernet0/0/1"]),
        ("interface GE0/0/1.100", "huawei_vrp", ["GigabitEthernet0/0/1.100"]),
        ("set interfaces xe-0/0/0 unit 0", "juniper_junos", ["xe-0/0/0"]),
        ("/interface bridge port add interface=ether1 bridge=bridge1", None, ["ether1", "bridge1"]),
        ("show port 1/1/c1/1", "nokia_sros", ["1/1/c1/1"]),
        ("port 1/1/3 admin-state enable", "nokia_sros", ["1/1/3"]),
        ('interface "to-r2"', "nokia_sros", ["to-r2"]),
        ("lag-5 up", None, ["lag-5"]),
        ("interface xe1", "ipinfusion_ocnos", ["xe1"]),
        ("date 1/2/24 and 192.0.2.1/24", None, []),
        ("interface Gi0/1", "some_third_party_vendor", ["GigabitEthernet0/1"]),
    ],
)
def test_interfaces(line: str, vendor: str | None, expected: list[str]) -> None:
    assert [n for _, n in extract_interfaces(line, vendor)] == expected


def test_extract_rows_line_numbers_and_blank_lines() -> None:
    rows = extract_rows(
        ["", "ip address 192.0.2.1 255.255.255.0", "", "mac 00-00-5E-00-53-01"], None
    )
    assert [r[0] for r in rows.ips] == [2]
    assert rows.macs == [(4, "00:00:5e:00:53:01")]
