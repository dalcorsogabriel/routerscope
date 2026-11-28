"""State-command table for IOS / IOS-XE (also the base of the OcNOS table)."""

from __future__ import annotations

from routerscope.vendors import _cisco_like as c
from routerscope.vendors._cmd import Spec, spec

SPECS: tuple[Spec, ...] = (
    spec(
        ("show ip bgp summary", "show bgp all summary"),
        c.bgp_summary,
        "show:2 ip:2 bgp:2 [all:2] summary:3",
        "show:2 ip:2 bgp:2 vpnv4:3/vpnv6:3 [unicast:3] all:2 summary:3",
        "show:2 ip:2 bgp:2 vpnv4:3/vpnv6:3 [unicast:3] vrf:2 <vrf> summary:3",
        "show:2 ip:2 bgp:2 ipv4:3/ipv6:3 [unicast:3] summary:3",
        "show:2 bgp:2 summary:3",
        "show:2 bgp:2 all:2 summary:3",
        "show:2 bgp:2 ipv4:3/ipv6:3 unicast:3 summary:3",
        "show:2 bgp:2 vpnv4:3/vpnv6:3 unicast:3 all:2 summary:3",
        "show:2 bgp:2 vpnv4:3/vpnv6:3 unicast:3 vrf:2 <vrf> summary:3",
    ),
    spec(
        "show ip interface brief",
        c.interface_brief,
        "show:2 ip:2 interface:3 brief:1 [vrf:2 <vrf>]",
    ),
    spec(
        "show interfaces description",
        c.interface_description,
        "show:2 interfaces:3 description:1",
    ),
    spec(
        "show ip arp",
        c.arp_table,
        "show:2 ip:2 arp:2 [vrf:2 <vrf>]",
        "show:2 arp:2 [vrf:2 <vrf>]",
    ),
    spec(
        "show mac address-table",
        c.mac_table,
        "show:2 mac:3 address-table:3",
        "show:2 mac-address-table:5",
    ),
    spec("show version", c.show_version, "show:2 version:3"),
)
