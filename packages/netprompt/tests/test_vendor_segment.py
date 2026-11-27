from __future__ import annotations

import pytest
from netprompt import (
    CISCO_IOS,
    CISCO_XR,
    HUAWEI_VRP,
    IPINFUSION_OCNOS,
    JUNIPER_JUNOS,
    MIKROTIK_ROS7,
    NOKIA_SROS,
    Mode,
    detect_vendor,
    segment,
)


@pytest.mark.parametrize(
    ("text", "vendor"),
    [
        ("Huawei Versatile Routing Platform Software", HUAWEI_VRP),
        ("Cisco IOS XR Software, Version 7.5.2", CISCO_XR),
        ("Cisco IOS Software, Version 15.9", CISCO_IOS),
        ("Cisco IOS XE Software, Version 17.3", CISCO_IOS),
        ("Hostname: x\nJunos: 21.4R3", JUNIPER_JUNOS),
        ("JUNOS 21.4R3 built 2023", JUNIPER_JUNOS),
        ("TiMOS-B-22.10.R3 both/x86_64", NOKIA_SROS),
        ("MikroTik RouterOS 7.11", MIKROTIK_ROS7),
        ("RouterOS", MIKROTIK_ROS7),
        ("OcNOS-SP-PLUS 6.5", IPINFUSION_OCNOS),
        ("Copyright IP Infusion Inc.", IPINFUSION_OCNOS),
        ("<PE1>display version", HUAWEI_VRP),
        ("user@R1> show version\n{master:0}", JUNIPER_JUNOS),
        ("[/]\nA:admin@R1# ", NOKIA_SROS),
        ("[admin@R1] > print", MIKROTIK_ROS7),
        ("RP/0/RSP0/CPU0:R1#show", CISCO_XR),
    ],
)
def test_detect_vendor(text: str, vendor: str) -> None:
    assert detect_vendor(text) == vendor


@pytest.mark.parametrize("text", ["", "nothing here", "R1#show clock", "<PE1>x\nuser@R1> y"])
def test_detect_vendor_inconclusive(text: str) -> None:
    assert detect_vendor(text) is None


def test_segment_basics() -> None:
    segs = segment("R1>show clock\n10:00:00\nR1>\nR1>show version\nline1\nline2\n\n")
    assert [(s.command, s.output, s.line) for s in segs] == [
        ("show clock", "10:00:00", 1),
        ("show version", "line1\nline2", 4),
    ]
    assert segs[0].device == "R1"


def test_segment_ignores_text_before_first_prompt() -> None:
    assert segment("Welcome\nRouter ready\n") == []


def test_segment_keeps_empty_command_with_output() -> None:
    segs = segment("R1#\nsomething appeared\nR1#")
    assert len(segs) == 1
    assert segs[0].command == ""
    assert segs[0].output == "something appeared"


def test_segment_vendor_hint_and_inference() -> None:
    session = "R1#show version\nstuff\n"
    assert segment(session)[0].prompt.vendor is None
    assert segment(session, vendor=IPINFUSION_OCNOS)[0].prompt.vendor == IPINFUSION_OCNOS
    assert segment(session, vendor=CISCO_XR)[0].prompt.vendor is None
    assert segment("R1#show version\nCisco IOS Software\n")[0].prompt.vendor == CISCO_IOS
    assert segment("R1#show version\nOcNOS 6.5\n")[0].prompt.vendor == IPINFUSION_OCNOS
    both = segment("R1#show version\nCisco IOS Software\nOcNOS\n")
    assert both[0].prompt.vendor is None


def test_segment_resolves_vrp_hostnames_seen_later() -> None:
    segs = segment("[~PE1-bgp]display this\nx\n<PE1>quit\n")
    assert segs[0].device == "PE1"
    assert segs[0].prompt.context == "bgp"
    segs = segment("[~PE1-bgp]display this\nx\n")
    assert segs[0].device is None


def test_segment_md_cli_context_lines() -> None:
    text = (
        '[/]\nA:admin@R1# edit-config private\n[pr:/configure router "Base"]\nA:admin@R1# info\nx\n'
    )
    segs = segment(text)
    assert segs[0].prompt.mode == Mode.EXEC
    assert segs[1].prompt.mode == Mode.CONFIG
    assert segs[1].prompt.context == '/configure router "Base"'
    assert segs[0].output == ""
    assert segs[1].output == "x"


def test_segment_junos_banner_not_output() -> None:
    segs = segment("u@R1> configure\nEntering\n\n[edit]\nu@R1# show\nx\n\n[edit]\nu@R1#\n")
    assert segs[0].output == "Entering"
    assert segs[1].prompt.context is None
    assert segs[1].output == "x"


def test_confirm_line_does_not_split_output() -> None:
    segs = segment("R1#show interfaces\nGigabitEthernet0/0 is up\n[confirm]\nsomething\nR1#")
    assert len(segs) == 1
    assert segs[0].output == "GigabitEthernet0/0 is up\n[confirm]\nsomething"


def test_xml_and_unseen_empty_prompts_mid_output_are_output() -> None:
    text = "R1#show x\n<rpc-reply>\n<configuration>\n[Local]\n</rpc-reply>\nR1#"
    segs = segment(text)
    assert len(segs) == 1
    assert "<configuration>" in segs[0].output
    assert "[Local]" in segs[0].output


def test_known_hostname_empty_prompt_still_splits() -> None:
    segs = segment("R1#show x\nfoo\nR1#\nR1#show y\nbar")
    assert [s.command for s in segs] == ["show x", "show y"]


def test_mikrotik_keypad_escape_prompt() -> None:
    segs = segment("\x1b=[admin@MikroTik] > /system identity print\nname: x")
    assert segs[0].prompt.vendor == MIKROTIK_ROS7


def test_vendor_resolved_per_device() -> None:
    text = (
        "R1#show version\nCisco IOS XE Software, Version 17.3\n"
        "R2#show version\nOcNOS version 6.5\nOcNOS\n"
    )
    segs = segment(text)
    assert [s.prompt.vendor for s in segs] == [CISCO_IOS, IPINFUSION_OCNOS]
