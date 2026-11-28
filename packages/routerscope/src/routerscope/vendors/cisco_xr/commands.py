"""State-command table for Cisco IOS-XR."""

from __future__ import annotations

from routerscope.vendors import _cisco_like as c
from routerscope.vendors._cmd import Spec, spec

SPECS: tuple[Spec, ...] = (
    spec(
        ("show bgp summary", "show bgp vrf all summary", "show bgp all all summary"),
        c.bgp_summary,
        "show:2 bgp:2 summary:3",
        "show:2 bgp:2 all:2 all:2 summary:3",
        "show:2 bgp:2 ipv4:3/ipv6:3/vpnv4:3/vpnv6:3 unicast:3 summary:3",
        "show:2 bgp:2 vrf:2 all:2 summary:3",
        "show:2 bgp:2 vrf:2 all:2 ipv4:3/ipv6:3 unicast:3 summary:3",
        "show:2 bgp:2 vrf:2 <vrf> summary:3",
        "show:2 bgp:2 vrf:2 <vrf> ipv4:3/ipv6:3 unicast:3 summary:3",
    ),
    spec(
        "show ipv4 interface brief",
        c.interface_brief,
        "show:2 ipv4:3/ip:2 interface:3 brief:1",
        "show:2 ipv4:3/ip:2 interface:3 brief:1 vrf:2 <vrf>",
    ),
    spec("show interfaces brief", c.xr_interfaces_brief, "show:2 interfaces:3 brief:1"),
    spec(
        "show interfaces description", c.interface_description, "show:2 interfaces:3 description:1"
    ),
    spec(
        "show arp",
        c.arp_table,
        "show:2 arp:2",
        "show:2 arp:2 vrf:2 <vrf>",
        "show:2 ipv4:3 arp:2",
    ),
    spec(
        "show l2vpn forwarding bridge-domain mac-address",
        c.mac_table,
        "show:2 l2vpn:2 forwarding:3 bridge-domain:3 mac-address:3",
        "show:2 l2vpn:2 forwarding:3 bridge-domain:3 mac-address:3 location:3 <location>",
    ),
    spec("show version", c.show_version, "show:2 version:3"),
)
