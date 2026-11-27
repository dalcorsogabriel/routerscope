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
    VENDORS,
    Mode,
    detect_prompt,
    is_prompt_banner,
)


def _p(line: str, **kw: object):  # type: ignore[no-untyped-def]
    found = detect_prompt(line, **kw)  # type: ignore[arg-type]
    assert found is not None, line
    return found


def test_vendor_constants() -> None:
    assert len(set(VENDORS)) == 7


@pytest.mark.parametrize(
    ("line", "mode", "context"),
    [
        ("R1>", Mode.EXEC, None),
        ("R1#", Mode.EXEC, None),
        ("R1(config)#", Mode.CONFIG, None),
        ("R1(config-if)#", Mode.CONFIG, "config-if"),
        ("R1(config-router)#", Mode.CONFIG, "config-router"),
        ("R1(boot)#", Mode.EXEC, "boot"),
    ],
)
def test_cisco_like(line: str, mode: Mode, context: str | None) -> None:
    prompt, cmd = _p(line + " show clock")
    assert prompt.vendor is None
    assert prompt.candidates == (CISCO_IOS, IPINFUSION_OCNOS)
    assert prompt.hostname == "R1"
    assert (prompt.mode, prompt.context, cmd) == (mode, context, "show clock")
    assert prompt.raw == line


def test_command_directly_after_prompt() -> None:
    prompt, cmd = _p("R1>enable")
    assert (prompt.raw, cmd) == ("R1>", "enable")


@pytest.mark.parametrize(
    ("line", "mode", "context"),
    [
        ("RP/0/RSP0/CPU0:R1#", Mode.EXEC, None),
        ("RP/0/RP0/CPU0:R1(config)#", Mode.CONFIG, None),
        ("RP/0/RP0/CPU0:R1(config-bgp)#", Mode.CONFIG, "config-bgp"),
    ],
)
def test_xr(line: str, mode: Mode, context: str | None) -> None:
    prompt, cmd = _p(line + "  commit ")
    assert prompt.vendor == CISCO_XR
    assert prompt.hostname == "R1"
    assert (prompt.mode, prompt.context, cmd) == (mode, context, "commit")


def test_vrp_exec_and_config() -> None:
    prompt, cmd = _p("<R1>display version")
    assert (prompt.vendor, prompt.hostname, prompt.mode, cmd) == (
        HUAWEI_VRP,
        "R1",
        Mode.EXEC,
        "display version",
    )
    prompt, _ = _p("[R1]")
    assert (prompt.hostname, prompt.mode, prompt.context, prompt.flags) == (
        "R1",
        Mode.CONFIG,
        None,
        frozenset(),
    )
    prompt, _ = _p("[~R1]")
    assert prompt.flags == {"two_stage"}
    prompt, _ = _p("[*R1]")
    assert prompt.flags == {"uncommitted"}


def test_vrp_ambiguous_hostname() -> None:
    prompt, _ = _p("[R1-GigabitEthernet0/0/1]")
    assert prompt.hostname is None
    assert prompt.context is None
    assert prompt.vendor == HUAWEI_VRP
    prompt, _ = _p("[R1-GigabitEthernet0/0/1]", known_hostnames={"R1"})
    assert (prompt.hostname, prompt.context) == ("R1", "GigabitEthernet0/0/1")
    prompt, _ = _p("[~R1-bgp]", known_hostnames={"R1"})
    assert (prompt.hostname, prompt.context, prompt.flags) == ("R1", "bgp", {"two_stage"})
    prompt, _ = _p("[*PE-SP-01-bgp]", known_hostnames={"PE", "PE-SP-01"})
    assert (prompt.hostname, prompt.context) == ("PE-SP-01", "bgp")
    prompt, _ = _p("[PE-SP-01]", known_hostnames={"PE", "PE-SP-01"})
    assert (prompt.hostname, prompt.context) == ("PE-SP-01", None)
    prompt, _ = _p("[PE-SP-01-bgp]", known_hostnames={"X"})
    assert prompt.hostname is None


def test_routeros() -> None:
    prompt, cmd = _p("[admin@R1] >")
    assert (prompt.vendor, prompt.hostname, prompt.mode, prompt.context, cmd) == (
        MIKROTIK_ROS7,
        "R1",
        Mode.EXEC,
        None,
        "",
    )
    prompt, cmd = _p("[admin@R1] /ip/address> print")
    assert (prompt.context, cmd, prompt.flags) == ("/ip/address", "print", frozenset())
    prompt, _ = _p("[admin@R1] <SAFE>")
    assert prompt.flags == {"safe_mode"}
    assert prompt.context is None
    prompt, _ = _p("[admin@R1] /routing/bgp<SAFE>")
    assert (prompt.flags, prompt.context, prompt.mode) == (
        {"safe_mode"},
        "/routing/bgp",
        Mode.EXEC,
    )


def test_junos() -> None:
    prompt, cmd = _p("user@R1> show version")
    assert (prompt.vendor, prompt.hostname, prompt.mode, cmd) == (
        JUNIPER_JUNOS,
        "R1",
        Mode.EXEC,
        "show version",
    )
    prompt, _ = _p("user@R1#")
    assert prompt.mode == Mode.CONFIG


@pytest.mark.parametrize(
    ("line", "mode", "context", "flags"),
    [
        ("A:R1#", Mode.EXEC, None, set()),
        ("*A:R1#", Mode.EXEC, None, {"uncommitted"}),
        ("A:R1>config>router#", Mode.CONFIG, "config>router", set()),
        ("*A:R1>config>router>bgp#", Mode.CONFIG, "config>router>bgp", {"uncommitted"}),
        ("B:R1#", Mode.EXEC, None, {"standby"}),
        ("*B:R1>config#", Mode.CONFIG, "config", {"standby", "uncommitted"}),
        ("A:R1>show>router#", Mode.EXEC, "show>router", set()),
        ("A:admin@R1#", Mode.EXEC, None, {"md_cli"}),
        ("*A:admin@R1#", Mode.EXEC, None, {"md_cli", "uncommitted"}),
    ],
)
def test_nokia(line: str, mode: Mode, context: str | None, flags: set[str]) -> None:
    prompt, _ = _p(line + " info")
    assert prompt.vendor == NOKIA_SROS
    assert prompt.hostname == "R1"
    assert (prompt.mode, prompt.context, set(prompt.flags)) == (mode, context, flags)


@pytest.mark.parametrize(
    "line",
    [
        "Total: 3",
        "[OK]",
        "Building configuration...",
        "<cr>",
        "<1-65535>",
        "R1 uptime is 3 weeks",
        "ip prefix-list X seq 5 permit 192.0.2.0/24",
        "Last login from user@host on ttys001",
        " R1#",
        "  <cr>",
        "",
        "[edit]",
        "[edit protocols bgp]",
        "{master:0}",
        "[/]",
        '[ex:/configure router "Base"]',
        "#",
        "!",
        "*>i 192.0.2.0/24 198.51.100.1",
        "user@host: permission denied",
        "[1]",
        "<OK>x" if False else "[FAILED]",
    ],
)
def test_not_prompts(line: str) -> None:
    assert detect_prompt(line) is None


@pytest.mark.parametrize(
    "line",
    [
        "[edit]",
        "[edit protocols bgp]",
        "{master:0}",
        "{master}",
        "{backup:1}",
        "[/]",
        '[ex:/configure router "Base"]',
        "[pr:/configure]",
        "[gl:/configure]",
        "*[pr:/configure]",
        "(ex)[/configure]",
    ],
)
def test_banners(line: str) -> None:
    assert is_prompt_banner(line)


@pytest.mark.parametrize("line", ["", "R1#", "[admin@R1] >", "[OK]", "[R1]", "edit"])
def test_not_banners(line: str) -> None:
    assert not is_prompt_banner(line)
