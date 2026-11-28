"""Command recognition, safety and robustness of the state-command parsers."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import netcmd_safety
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from routerscope.model import ARPEntry, BGPPeer, ParseResult, Snapshot, Source, split_lines
from routerscope.vendors import all_plugins, get
from routerscope.vendors._cmd import compile_pattern, match_pattern, split_command

DATA = Path(__file__).resolve().parent.parent / "data" / "commands"
VENDORS = [p.id for p in all_plugins()]
ID = "0" * 63 + "1"


def snap(text: str, vendor: str) -> Snapshot:
    return Snapshot(
        id=ID,
        vendor=vendor,
        kind="command_output",
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
        source=Source(kind="paste", uri="memory://t", importer="test"),
        size=len(text.encode()),
        line_count=len(split_lines(text)),
    )


def run(vendor: str, command: str, name: str) -> ParseResult | None:
    text = (DATA / vendor / f"{name}.txt").read_text(encoding="utf-8")
    plugin = get(vendor)
    assert plugin is not None
    return plugin.parse_command(command, text, snap(text, vendor))


@pytest.mark.parametrize("vendor", VENDORS)
def test_readonly_commands_are_collector_safe(vendor: str) -> None:
    plugin = get(vendor)
    assert plugin is not None
    commands = list(plugin.readonly_commands())
    assert len(commands) == len(set(commands)) >= 5
    for cmd in commands:
        assert netcmd_safety.is_collector_safe(cmd, vendor), cmd


@pytest.mark.parametrize("vendor", VENDORS)
def test_every_readonly_command_is_recognised(vendor: str) -> None:
    """A declared command reaches its handler: no table in the text means ``None``."""
    plugin = get(vendor)
    assert plugin is not None
    for cmd in plugin.readonly_commands():
        assert plugin.parse_command(cmd, "no table here\n", snap("x", vendor)) is None


@pytest.mark.parametrize(
    ("vendor", "command", "name", "count"),
    [
        ("cisco_ios", "sh ip bgp sum", "bgp_summary", 6),
        ("cisco_ios", "show bgp all summary", "bgp_all_summary", 2),
        ("cisco_ios", "sh ip arp", "arp", 3),
        ("cisco_ios", "sh arp", "arp", 3),
        ("cisco_ios", "show mac-address-table", "mac_table", 4),
        ("cisco_xr", "sh bgp summ", "bgp_summary", 4),
        ("cisco_xr", "show bgp vrf all summary", "bgp_vrf_all", 2),
        ("huawei_vrp", "dis bgp peer", "bgp_peer", 3),
        ("huawei_vrp", "disp arp", "arp", 3),
        ("juniper_junos", "show bgp summary | no-more", "bgp_summary", 4),
        ("juniper_junos", "sh bgp sum", "bgp_summary", 4),
        ("nokia_sros", 'show router "Base" bgp summary', "bgp_summary", 3),
        ("nokia_sros", "sh rou bgp summ", "bgp_summary", 3),
        ("mikrotik_ros7", "/routing/bgp/session/print", "bgp_session_table", 2),
        ("mikrotik_ros7", "routing bgp session print without-paging", "bgp_session_table", 2),
        ("mikrotik_ros7", "/ro bg se pr", "bgp_session_table", 2),
        ("mikrotik_ros7", "/ip arp print", "arp", 2),
    ],
)
def test_abbreviations(vendor: str, command: str, name: str, count: int) -> None:
    result = run(vendor, command, name)
    assert result is not None
    assert len(result.objects) == count
    assert result.command == command


@pytest.mark.parametrize(
    ("vendor", "command", "name"),
    [
        ("cisco_ios", "show ip bgp summary | include 192.0.2", "bgp_summary"),
        ("cisco_ios", "show ip arp 192.0.2.1", "arp"),
        ("cisco_ios", "show ip bgp neighbors", "bgp_summary"),
        ("cisco_ios", "", "bgp_summary"),
        ("cisco_ios", "s ip bgp summary", "bgp_summary"),
        ("huawei_vrp", "display bgp peer | include 192", "bgp_peer"),
        ("juniper_junos", "show bgp summary | match Establ", "bgp_summary"),
        ("juniper_junos", "show bgp summary | display xml", "bgp_summary"),
        ("nokia_sros", "show router bgp summary | match 192", "bgp_summary"),
        ("mikrotik_ros7", "/ip arp print where interface=ether1", "arp"),
        ("mikrotik_ros7", "/ip arp print count-only", "arp"),
        ("mikrotik_ros7", ":put [/ip arp print]", "arp"),
        ("mikrotik_ros7", "/ip arp print | foo", "arp"),
        ("mikrotik_ros7", "/ip arp set 0 disabled=yes", "arp"),
    ],
)
def test_filtered_or_unknown_commands_are_not_parsed(vendor: str, command: str, name: str) -> None:
    assert run(vendor, command, name) is None


def test_vrf_variants_set_vrf() -> None:
    res = run("cisco_ios", "show ip arp vrf CUST9", "arp")
    assert res is not None
    assert all(isinstance(o, ARPEntry) and o.vrf == "CUST9" for o in res.objects)
    res = run("cisco_ios", "show ip bgp vpnv4 vrf CUST9 summary", "bgp_vpnv4_vrf")
    assert res is not None
    assert all(isinstance(o, BGPPeer) and o.vrf == "CUST9" for o in res.objects)
    res = run("juniper_junos", "show bgp summary instance X", "bgp_summary")
    assert res is not None
    assert [o.vrf for o in res.objects if isinstance(o, BGPPeer)][:2] == ["X", "X"]
    res = run("huawei_vrp", "display arp vpn-instance CUST1", "arp_vpn")
    assert res is not None
    assert [o.vrf for o in res.objects if isinstance(o, ARPEntry)] == ["CUST1"]


def test_empty_or_blank_output_is_none() -> None:
    plugin = get("cisco_ios")
    assert plugin is not None
    assert plugin.parse_command("show ip arp", "", snap("", "cisco_ios")) is None
    assert plugin.parse_command("show ip arp", "\n \n", snap("\n", "cisco_ios")) is None


def test_pattern_language() -> None:
    pat = "show:2 ip:2 [vrf:2 <vrf>] arp"
    assert match_pattern(pat, ["sh", "ip", "vrf", "A", "arp"]) == {"vrf": "A"}
    assert match_pattern(pat, ["sh", "ip", "arp"]) == {}
    assert match_pattern(pat, ["sh", "ip", "vrf"]) is None
    assert match_pattern("show:2", ["s"]) is None
    assert match_pattern("a/bcd:2", ["b"]) is None
    assert match_pattern("a/bcd:2", ["bc"]) == {}
    assert match_pattern("show", ["show", "extra"]) is None
    assert compile_pattern("a [b <x>]") == compile_pattern("a [b <x>]")
    assert split_command('show router "VPRN 1" arp', frozenset()) == [
        "show",
        "router",
        "VPRN 1",
        "arp",
    ]
    assert split_command("show a | no-more", frozenset({"no-more"})) == ["show", "a"]
    assert split_command("show a | count", frozenset({"no-more"})) is None


def _outputs(vendor: str) -> list[str]:
    return [p.read_text(encoding="utf-8") for p in sorted((DATA / vendor).glob("*.txt"))]


def _check(vendor: str, text: str) -> None:
    plugin = get(vendor)
    assert plugin is not None
    total = max(len(split_lines(text)), 1)
    for cmd in plugin.readonly_commands():
        result = plugin.parse_command(cmd, text, snap(text, vendor))
        if result is not None:
            assert all(1 <= o.ref.line_start <= o.ref.line_end <= total for o in result.objects)


@pytest.mark.parametrize("vendor", VENDORS)
@settings(max_examples=60, deadline=None)
@given(text=st.text(max_size=400))
def test_fuzz_random_text_never_raises(vendor: str, text: str) -> None:
    _check(vendor, text)


@pytest.mark.parametrize("vendor", VENDORS)
@settings(max_examples=40, deadline=None)
@given(data=st.data())
def test_fuzz_mutated_real_outputs_never_raise(vendor: str, data: st.DataObject) -> None:
    lines = split_lines(data.draw(st.sampled_from(_outputs(vendor))))
    kept = [ln for ln in lines if data.draw(st.booleans())]
    cut = [ln[: data.draw(st.integers(0, 90))] for ln in kept]
    _check(vendor, "\n".join(cut))
