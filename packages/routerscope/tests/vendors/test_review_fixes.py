"""Regression tests for issues found in review of the config parsers."""

from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest
from routerscope.model import ParsedConfig, Snapshot, Source, split_lines
from routerscope.vendors import all_plugins, get
from routerscope.vendors._tree import (
    parse_brace,
    parse_indented,
    parse_routeros,
    parse_set,
)

VENDORS = [p.id for p in all_plugins()]


def parse(vendor: str, text: str) -> ParsedConfig:
    snapshot = Snapshot(
        id="0" * 63 + "1",
        vendor=vendor,
        kind="config",
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
        source=Source(kind="paste", uri="memory://t", importer="test"),
        size=len(text.encode()),
        line_count=len(split_lines(text)),
    )
    plugin = get(vendor)
    assert plugin is not None
    return plugin.parse_config(text, snapshot)


# 1. SR OS: same interface name in Base and several VPRNs ---------------------------------


def test_sros_classic_same_interface_name_in_base_and_vprns() -> None:
    text = (
        "    router Base\n"
        '        interface "loopback"\n            address 192.0.2.1/32\n        exit\n'
        "    exit\n"
        '    vprn 1 name "A" customer 1 create\n'
        '        interface "loopback" create\n            address 198.51.100.1/32\n        exit\n'
        "    exit\n"
        '    vprn 2 name "B" customer 1 create\n'
        '        interface "loopback" create\n            address 203.0.113.1/32\n        exit\n'
        "    exit\n"
    )
    parsed = parse("nokia_sros", text)
    assert [(i.name, i.vrf) for i in parsed.interfaces] == [
        ("loopback", None),
        ("loopback", "A"),
        ("loopback", "B"),
    ]
    assert [(str(a.address), a.vrf) for a in parsed.ip_addresses] == [
        ("192.0.2.1/32", None),
        ("198.51.100.1/32", "A"),
        ("203.0.113.1/32", "B"),
    ]
    assert {v.name: v.interfaces for v in parsed.vrfs} == {"A": ("loopback",), "B": ("loopback",)}


def test_sros_mdcli_same_interface_name_in_base_and_vprns() -> None:
    text = """configure {
    router "Base" {
        interface "loopback" {
            ipv4 { primary { address 192.0.2.1
                prefix-length 32 } }
        }
    }
    service {
        vprn "A" {
            interface "loopback" {
                ipv4 { primary { address 198.51.100.1
                    prefix-length 32 } }
            }
        }
        vprn "B" {
            interface "loopback" {
                ipv4 { primary { address 203.0.113.1
                    prefix-length 32 } }
            }
        }
    }
}
"""
    parsed = parse("nokia_sros", text)
    assert [(i.name, i.vrf) for i in parsed.interfaces] == [
        ("loopback", None),
        ("loopback", "A"),
        ("loopback", "B"),
    ]
    assert [a.vrf for a in parsed.ip_addresses] == [None, "A", "B"]
    assert {v.name: v.interfaces for v in parsed.vrfs} == {"A": ("loopback",), "B": ("loopback",)}


# 2. performance on very large prefix lists -------------------------------------------------

N = 50_000


def _prefix(i: int) -> str:
    return (
        f"10.{(i >> 8) & 255}.{i & 255}.0/24"
        if i < 65536
        else f"11.{(i >> 8) & 255}.{i & 255}.0/24"
    )


def _big_texts() -> dict[str, tuple[str, str]]:
    ps = [_prefix(i) for i in range(N)]
    junos_brace = (
        "policy-options {\n prefix-list BIG {\n" + "".join(f"  {p};\n" for p in ps) + " }\n}\n"
    )
    junos_set = "".join(f"set policy-options prefix-list BIG {p}\n" for p in ps)
    classic = (
        '    policy-options\n        prefix-list "BIG"\n'
        + "".join(f"            prefix {p} exact\n" for p in ps)
        + "        exit\n    exit\n"
    )
    mdcli = (
        'configure {\n policy-options {\n  prefix-list "BIG" {\n'
        + "".join(f"   prefix {p} type exact {{\n   }}\n" for p in ps)
        + "  }\n }\n}\n"
    )
    ios = "".join(f"ip prefix-list BIG seq {i + 1} permit {p}\n" for i, p in enumerate(ps))
    return {
        "junos-brace": ("juniper_junos", junos_brace),
        "junos-set": ("juniper_junos", junos_set),
        "sros-classic": ("nokia_sros", classic),
        "sros-mdcli": ("nokia_sros", mdcli),
        "ios": ("cisco_ios", ios),
    }


@pytest.mark.parametrize("case", ["junos-brace", "junos-set", "sros-classic", "sros-mdcli", "ios"])
def test_huge_prefix_list_is_not_quadratic(case: str) -> None:
    vendor, text = _big_texts()[case]
    start = time.perf_counter()
    parsed = parse(vendor, text)
    assert time.perf_counter() - start < 30
    assert len(parsed.prefix_lists) == 1
    assert len(parsed.prefix_lists[0].entries) == N


# 3. interface names do not include mode keywords -------------------------------------------


@pytest.mark.parametrize(
    ("vendor", "text", "name"),
    [
        ("cisco_ios", "interface Serial0/0.1 point-to-point\n description x\n", "Serial0/0.1"),
        ("cisco_ios", "interface Tunnel0 point-to-point\n", "Tunnel0"),
        ("ipinfusion_ocnos", "interface xe1 point-to-point\n", "xe1"),
        ("cisco_xr", "interface Bundle-Ether1.100 l2transport\n", "Bundle-Ether1.100"),
        ("huawei_vrp", "interface GigabitEthernet0/0/1.100 mode l2\n", "GigabitEthernet0/0/1.100"),
    ],
)
def test_interface_name_is_first_word(vendor: str, text: str, name: str) -> None:
    assert [i.name for i in parse(vendor, text).interfaces] == [name]


# 4. deep nesting never raises ---------------------------------------------------------------

DEPTH = 10_000
DEEP = {
    "indent": "\n".join(" " * min(i, 300) + "x" for i in range(DEPTH)),
    "brace-lines": "a {\n" * DEPTH + "}\n" * DEPTH,
    "brace-one-line": "a { " * DEPTH,
    "mdcli": "configure {\n" + "a {\n" * DEPTH,
    "set": "set " + " ".join("unit 1 family" for _ in range(DEPTH // 3)),
    "ros": "/ip address\n" + "add " * DEPTH,
}


@pytest.mark.parametrize("name", list(DEEP))
def test_deep_text_every_tree_parser(name: str) -> None:
    text = DEEP[name]
    for dialect in ("ios", "xr", "vrp", "sros"):
        parse_indented(text, dialect)  # type: ignore[arg-type]
    for brace in ("junos", "mdcli"):
        parse_brace(text, brace)  # type: ignore[arg-type]
        parse_set(text, brace)  # type: ignore[arg-type]
    parse_routeros(text)


@pytest.mark.parametrize("vendor", VENDORS)
@pytest.mark.parametrize("name", list(DEEP))
def test_deep_text_every_plugin(vendor: str, name: str) -> None:
    parse(vendor, DEEP[name])


def test_deep_tree_walk_and_flat_words_are_iterative() -> None:
    root = parse_brace("a {\n" * 5000 + "b;\n" + "}\n" * 5000)
    nodes = list(root.walk())
    assert len(nodes) >= 5000
    assert nodes[-1].flat_words  # does not recurse


# 5. SR OS static route ref includes the prefix line ----------------------------------------


def test_sros_static_route_ref_starts_at_prefix() -> None:
    classic = (
        "    router Base\n"
        "        static-route-entry 192.0.2.0/24\n"
        "            next-hop 198.51.100.1\n"
        "                no shutdown\n"
        "            exit\n"
        "        exit\n"
        "    exit\n"
    )
    route = parse("nokia_sros", classic).static_routes[0]
    assert (route.ref.line_start, route.ref.line_end) == (2, 6)
    md = (
        'configure {\n router "Base" {\n  static-routes {\n'
        "   route 192.0.2.0/24 route-type unicast {\n"
        '    next-hop "198.51.100.1" {\n     preference 5\n    }\n   }\n  }\n }\n}\n'
    )
    route = parse("nokia_sros", md).static_routes[0]
    assert route.ref.line_start == 4 and route.ref.line_end >= 7


# 6/7. RouterOS -----------------------------------------------------------------------------

ROS = """/ip address
add address=192.0.2.1/30 disabled=yes interface=ether1
add address=192.0.2.5/30 interface=ether1
/routing bgp connection
add disabled=yes name=off remote.address=192.0.2.2 remote.as=64497
add name=on remote.address=192.0.2.6 remote.as=64498 comment=real
add name=plain remote.address=192.0.2.10 remote.as=64499
/ip route
add disabled=yes dst-address=10.0.0.0/8 gateway=192.0.2.2
add dst-address=10.1.0.0/16 gateway=192.0.2.2,192.0.2.3
add dst-address=10.2.0.0/16 gateway=192.0.2.2%vlan100
add dst-address=10.3.0.0/16 gateway=ether1,ether2
"""


def test_routeros_disabled_entries_are_skipped() -> None:
    parsed = parse("mikrotik_ros7", ROS)
    assert [str(a.address) for a in parsed.ip_addresses] == ["192.0.2.5/30"]
    assert [str(p.peer) for p in parsed.bgp_peers] == ["192.0.2.6", "192.0.2.10"]
    assert [str(r.prefix) for r in parsed.static_routes] == [
        "10.1.0.0/16",
        "10.2.0.0/16",
        "10.3.0.0/16",
    ]


def test_routeros_gateway_lists_and_scopes() -> None:
    routes = {str(r.prefix): r for r in parse("mikrotik_ros7", ROS).static_routes}
    assert str(routes["10.1.0.0/16"].next_hop) == "192.0.2.2"
    assert routes["10.1.0.0/16"].interface is None
    assert str(routes["10.2.0.0/16"].next_hop) == "192.0.2.2"
    assert routes["10.2.0.0/16"].interface == "vlan100"
    assert routes["10.3.0.0/16"].next_hop is None and routes["10.3.0.0/16"].interface == "ether1"


def test_routeros_bgp_description_is_only_the_comment() -> None:
    peers = {str(p.peer): p for p in parse("mikrotik_ros7", ROS).bgp_peers}
    assert peers["192.0.2.6"].description == "real"
    assert peers["192.0.2.10"].description is None


def test_routeros_local_as_from_template() -> None:
    text = (
        "/routing bgp template\nset default as=64496\nadd as=64511 name=other\n"
        "/routing bgp connection\n"
        "add name=a remote.address=192.0.2.2 remote.as=64497 templates=default\n"
        "add name=b remote.address=192.0.2.3 remote.as=64498 templates=other\n"
        "add name=c remote.address=192.0.2.4 remote.as=64499\n"
    )
    assert [p.local_as for p in parse("mikrotik_ros7", text).bgp_peers] == [64496, 64511, 64496]


# 8. Junos reserved keywords and unit leaf ---------------------------------------------------


def test_junos_reserved_interface_keywords_and_unit_leaf() -> None:
    text = (
        "interfaces {\n  apply-groups GL;\n  apply-groups-except X;\n  traceoptions {\n"
        "    flag all;\n  }\n  interface-range IR {\n    member ge-0/0/0;\n  }\n"
        "  ge-0/0/1 {\n    unit 0;\n  }\n}\n"
    )
    parsed = parse("juniper_junos", text)
    assert [i.name for i in parsed.interfaces] == ["ge-0/0/1", "ge-0/0/1.0"]
    flat = parse(
        "juniper_junos", "set interfaces apply-groups GL\nset interfaces ge-0/0/1 unit 0\n"
    )
    assert [i.name for i in flat.interfaces] == ["ge-0/0/1", "ge-0/0/1.0"]


# 9. eui-64 --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("vendor", "head"),
    [("cisco_xr", "interface Gi0\n ipv6 address"), ("huawei_vrp", "interface Gi0\n ipv6 address")],
)
def test_ipv6_eui64_is_skipped(vendor: str, head: str) -> None:
    parsed = parse(
        vendor, f"{head} 2001:db8:5::/64 eui-64\n{head[head.index(' ipv6') :]} 2001:db8:6::1/64\n"
    )
    assert [str(a.address) for a in parsed.ip_addresses] == ["2001:db8:6::1/64"]


# 10. local_as from the BGP process ---------------------------------------------------------


@pytest.mark.parametrize(
    ("vendor", "text"),
    [
        ("cisco_ios", "router bgp 64496\n neighbor 192.0.2.2 remote-as 64497\n"),
        ("ipinfusion_ocnos", "router bgp 64496\n neighbor 192.0.2.2 remote-as 64497\n"),
        ("cisco_xr", "router bgp 64496\n neighbor 192.0.2.2\n  remote-as 64497\n"),
        ("huawei_vrp", "bgp 64496\n peer 192.0.2.2 as-number 64497\n"),
    ],
)
def test_bgp_peer_local_as_defaults_to_process_as(vendor: str, text: str) -> None:
    peers = parse(vendor, text).bgp_peers
    assert peers[0].remote_as == 64497 and peers[0].local_as == 64496


def test_explicit_local_as_wins() -> None:
    text = (
        "router bgp 64496\n neighbor 192.0.2.2 remote-as 64497\n"
        " neighbor 192.0.2.2 local-as 64500\n"
    )
    assert parse("cisco_ios", text).bgp_peers[0].local_as == 64500


# 11. SR OS MD-CLI and classic extras --------------------------------------------------------


def test_sros_mdcli_secondary_ports_vrf_target_blackhole() -> None:
    text = """configure {
    port 1/1/c1/1 {
        admin-state enable
        description "to CE"
    }
    router "Base" {
        interface "x" {
            ipv4 {
                primary { address 192.0.2.1
                    prefix-length 30 }
                secondary 192.0.2.5 {
                    prefix-length 30
                }
            }
        }
        static-routes {
            route 10.0.0.0/8 route-type unicast {
                blackhole {
                }
            }
        }
    }
    service {
        vprn "C" {
            route-distinguisher "64496:1"
            vrf-target {
                import-community "target:64496:1"
                export-community "target:64496:2"
            }
        }
    }
}
"""
    parsed = parse("nokia_sros", text)
    assert [
        (i.name, i.enabled, i.description) for i in parsed.interfaces if i.name.startswith("1/")
    ] == [("1/1/c1/1", True, "to CE")]
    assert [(str(a.address), a.secondary) for a in parsed.ip_addresses] == [
        ("192.0.2.1/30", False),
        ("192.0.2.5/30", True),
    ]
    assert parsed.static_routes[0].blackhole
    vrf = parsed.vrfs[0]
    assert vrf.import_targets == ("target:64496:1",) and vrf.export_targets == ("target:64496:2",)


def test_sros_classic_blackhole_and_secondary_statement() -> None:
    text = (
        "    router Base\n"
        '        interface "x"\n            address 192.0.2.1/30\n'
        "            secondary 192.0.2.5/30\n"
        "        exit\n"
        "        static-route-entry 10.0.0.0/8\n"
        "            blackhole\n            exit\n        exit\n"
        "    exit\n"
    )
    parsed = parse("nokia_sros", text)
    assert [a.secondary for a in parsed.ip_addresses] == [False, True]
    assert parsed.static_routes[0].blackhole


# 12. CR-only line endings -------------------------------------------------------------------


def test_sros_mdcli_detected_with_cr_only_endings() -> None:
    text = 'configure {\r router "Base" {\r  interface "a" {\r   description "d"\r  }\r }\r}\r'
    parsed = parse("nokia_sros", text)
    assert [i.description for i in parsed.interfaces] == ["d"]


# 13. repeated interface blocks are merged ---------------------------------------------------


@pytest.mark.parametrize(
    ("vendor", "text"),
    [
        ("cisco_ios", "interface Gi0\n description a\n!\ninterface Gi0\n mtu 1500\n"),
        ("cisco_xr", "interface Gi0\n description a\n!\ninterface Gi0\n mtu 1500\n"),
        ("huawei_vrp", "interface Gi0\n description a\n#\ninterface Gi0\n mtu 1500\n"),
    ],
)
def test_reentered_interface_blocks_merge(vendor: str, text: str) -> None:
    ifaces = parse(vendor, text).interfaces
    assert len(ifaces) == 1
    assert (ifaces[0].description, ifaces[0].mtu) == ("a", 1500)
    assert (ifaces[0].ref.line_start, ifaces[0].ref.line_end) == (1, 5)


def test_vrp_display_header_lines_are_comments() -> None:
    from routerscope.vendors._tree import parse_indented

    text = (
        "!Software Version V800R021C10SPC100\n"
        "!Last configuration was updated at 2026-01-05 10:00:00+00:00\n"
        "#\n"
        " sysname PE1\n"
        "#\n"
        "interface GigabitEthernet0/0/1\n"
        " ip address 192.0.2.1 255.255.255.0\n"
        "#\n"
        "return\n"
    )
    root = parse_indented(text, "vrp")
    assert [(n.text, n.depth, n.line_start) for n in root.children][:2] == [
        ("sysname PE1", 1, 4),
        ("interface GigabitEthernet0/0/1", 1, 6),
    ]
