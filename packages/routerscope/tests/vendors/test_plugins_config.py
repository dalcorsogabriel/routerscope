"""Behavioural tests for the vendor config extractors beyond the golden files."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from routerscope.model import ParsedConfig, Snapshot, Source, split_lines
from routerscope.vendors import all_plugins, get

DATA = Path(__file__).resolve().parent.parent / "data" / "configs"
FIXED_ID = "0" * 63 + "1"


def snap(text: str, vendor: str) -> Snapshot:
    return Snapshot(
        id=FIXED_ID,
        vendor=vendor,
        kind="config",
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
        source=Source(kind="paste", uri="memory://t", importer="test"),
        size=len(text.encode()),
        line_count=len(split_lines(text)),
    )


def parse(vendor: str, text: str) -> ParsedConfig:
    plugin = get(vendor)
    assert plugin is not None
    return plugin.parse_config(text, snap(text, vendor))


def check_refs(parsed: ParsedConfig, text: str) -> None:
    total = len(split_lines(text))
    for obj in parsed.iter_objects():
        assert 1 <= obj.ref.line_start <= obj.ref.line_end <= max(total, 1)


VENDORS = [p.id for p in all_plugins()]


def test_all_seven_builtin_vendors_have_config_parsers() -> None:
    assert sorted(VENDORS) == sorted(p.name for p in DATA.iterdir() if p.is_dir())


@pytest.mark.parametrize("vendor", VENDORS)
def test_empty_and_garbage(vendor: str) -> None:
    for text in ("", "\n\n", "{{{{", "}}}}", "interface\n", "neighbor\n", "/\n", "\x00\x01"):
        check_refs(parse(vendor, text), text)


@pytest.mark.parametrize("vendor", VENDORS)
def test_readonly_commands_are_declared(vendor: str) -> None:
    plugin = get(vendor)
    assert plugin is not None
    assert len(tuple(plugin.readonly_commands())) >= 5


@pytest.mark.parametrize("vendor", VENDORS)
def test_golden_files_with_crlf_give_same_objects(vendor: str) -> None:
    for path in sorted((DATA / vendor).glob("*.cfg")):
        text = path.read_bytes().decode()
        crlf = text.replace("\n", "\r\n")
        assert parse(vendor, text).model_dump() == parse(vendor, crlf).model_dump()


ALPHABET = st.sampled_from(
    [
        "interface ",
        "neighbor ",
        "peer ",
        "remote-as ",
        "as-number ",
        "address ",
        "ip address ",
        "route ",
        "ip route ",
        "prefix-list ",
        "set ",
        "add ",
        "/ip ",
        "{",
        "}",
        ";",
        "\n",
        " ",
        "192.0.2.1",
        "192.0.2.0/24",
        "255.255.255.0",
        "64496",
        "2001:db8::1",
        '"',
        "[",
        "]",
        "=",
        "bgp ",
        "vrf ",
        "configure ",
        "/configure ",
    ]
)


@settings(max_examples=120, deadline=None)
@given(st.lists(ALPHABET, max_size=60).map("".join))
def test_plugins_never_raise_on_noise(text: str) -> None:
    for vendor in VENDORS:
        check_refs(parse(vendor, text), text)


def test_junos_brace_and_set_forms_agree() -> None:
    brace = parse("juniper_junos", (DATA / "juniper_junos" / "mx1.cfg").read_text())
    flat = parse("juniper_junos", (DATA / "juniper_junos" / "mx1-set.cfg").read_text())
    # the set file deactivates ge-0/0/3 and omits some statements: compare shared objects
    names = {i.name for i in flat.interfaces}
    assert names <= {i.name for i in brace.interfaces}
    assert {(p.peer, p.remote_as, p.vrf) for p in flat.bgp_peers} <= {
        (p.peer, p.remote_as, p.vrf) for p in brace.bgp_peers
    }
    assert {a.address for a in flat.ip_addresses} <= {a.address for a in brace.ip_addresses}


def test_junos_inactive_statements_are_ignored() -> None:
    parsed = parse(
        "juniper_junos",
        "interfaces {\n inactive: ge-0/0/0 {\n  unit 0 {\n   family inet {\n"
        "    address 192.0.2.1/24;\n   }\n  }\n }\n}\n",
    )
    assert parsed.interfaces == () and parsed.ip_addresses == ()


def test_ios_peer_group_and_invalid_values_are_skipped() -> None:
    text = (
        "router bgp 64496\n neighbor 192.0.2.9 remote-as notanumber\n"
        " neighbor 192.0.2.10 remote-as 0\n neighbor 192.0.2.11 peer-group MISSING\n"
        "ip route 192.0.2.0 255.255.255.0\nip route 999.1.1.1 255.255.255.0 192.0.2.1\n"
        "ip prefix-list X seq 5 permit 192.0.2.0/24 ge 20\n"
        "interface Gi0\n ip address 192.0.2.1 999.0.0.0\n ip address dhcp\n"
        " ipv6 address 2001:db8::1/64 eui-64\n mtu 0\n"
    )
    parsed = parse("cisco_ios", text)
    assert parsed.bgp_peers == () and parsed.static_routes == ()
    assert parsed.prefix_lists == () and parsed.ip_addresses == ()
    assert [i.name for i in parsed.interfaces] == ["Gi0"]
    assert parsed.interfaces[0].mtu is None


def test_ios_asdot_remote_as() -> None:
    parsed = parse("cisco_ios", "router bgp 1.10\n neighbor 192.0.2.1 remote-as 1.10\n")
    assert parsed.bgp_peers[0].remote_as == 65546


def test_xr_prefix_set_mixed_families_split() -> None:
    parsed = parse(
        "cisco_xr",
        "prefix-set P\n  192.0.2.0/24,\n  2001:db8::/32 le 48\nend-set\n",
    )
    assert sorted(p.afi for p in parsed.prefix_lists) == ["ipv4", "ipv6"]


def test_routeros_one_line_forms_and_ipv6_scope() -> None:
    parsed = parse(
        "mikrotik_ros7",
        "/ip address add address=192.0.2.1/24 interface=ether1\n"
        "/ip route add dst-address=0.0.0.0/0 gateway=fe80::1%ether1\n"
        "/routing bgp peer\nadd remote-address=192.0.2.2 remote-as=64497\n"
        "/interface vlan add name=v1 vlan-id=5000 interface=ether1\n",
    )
    assert len(parsed.ip_addresses) == 1
    assert len(parsed.bgp_peers) == 1
    assert parsed.vlans == ()


def test_sros_classic_without_wrapper_and_mdcli_detection() -> None:
    classic = parse(
        "nokia_sros",
        'router\n    interface "a"\n        address 192.0.2.1/31\n    exit\nexit all\n',
    )
    assert classic.ip_addresses[0].interface == "a"
    mdcli = parse("nokia_sros", 'configure {\n router "Base" {\n  interface "a" {\n  }\n }\n}\n')
    assert [i.name for i in mdcli.interfaces] == ["a"]


def test_vrp_vlan_batch_ranges() -> None:
    parsed = parse("huawei_vrp", "vlan batch 10 to 12 20\nvlan batch 5000\n")
    assert [v.vlan_id for v in parsed.vlans] == [10, 11, 12, 20]
