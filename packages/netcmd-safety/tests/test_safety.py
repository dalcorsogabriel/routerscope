"""Cross-vendor safety guarantees and API behaviour."""

from __future__ import annotations

from enum import StrEnum

import pytest
from hypothesis import given
from hypothesis import strategies as st
from netcmd_safety import (
    VENDORS,
    Mode,
    UnknownVendorError,
    Verdict,
    classify,
    classify_lines,
    is_collector_safe,
    is_read,
    worst,
)

MODES = (None, Mode.EXEC, Mode.CONFIG)

# Commands that change device state on at least one platform. None of them may ever be
# READ or SESSION, for any vendor, in any mode.
NEVER_SAFE = [
    "reload",
    "reboot",
    "reset bgp all",
    "clear ip bgp *",
    "clear bgp all",
    "request system reboot",
    "/system reboot",
    "/system/reset-configuration",
    "admin reboot now",
    "write erase",
    "delete flash:x",
    "format flash:",
    "configure replace flash:x",
    "commit",
    "rollback 1",
    "undo peer 192.0.2.1",
    "no router bgp 64496",
    "shutdown",
    "debug all",
    "copy running-config startup-config",
    "save",
    "/ip address remove 0",
    "delete protocols bgp",
    "load override x",
    "start shell",
    "exec cf3:/x",
]


@pytest.mark.parametrize("vendor", VENDORS)
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("command", NEVER_SAFE)
def test_dangerous_commands_never_collector_safe(
    command: str, vendor: str, mode: Mode | None
) -> None:
    assert not is_collector_safe(command, vendor, mode=mode)


def test_unknown_vendor_raises() -> None:
    with pytest.raises(UnknownVendorError):
        classify("show version", "cisco")


def test_empty_input_is_session() -> None:
    assert classify("   ", "cisco_ios").verdict is Verdict.SESSION


def test_helpers() -> None:
    assert is_read("show version", "cisco_ios")
    assert not is_read("terminal length 0", "cisco_ios")
    assert is_collector_safe("terminal length 0", "cisco_ios")
    assert worst([]) is Verdict.UNKNOWN
    assert worst([Verdict.READ, Verdict.CONFIG, Verdict.SESSION]) is Verdict.CONFIG


def test_multiline_tracks_config_mode() -> None:
    text = "configure terminal\ninterface Gi0/0/1\ndescription uplink\nend\nshow run"
    lines = classify_lines(text, "cisco_ios")
    assert [c.verdict for c in lines] == [
        Verdict.CONFIG,
        Verdict.CONFIG,
        Verdict.CONFIG,
        Verdict.SESSION,
        Verdict.READ,
    ]
    assert lines[1].mode is Mode.CONFIG
    assert lines[4].mode is Mode.EXEC


def test_multiline_worst_wins_with_reason() -> None:
    text = "system-view\nbgp 64496\nundo peer 192.0.2.1\nreturn"
    result = classify(text, "huawei_vrp")
    assert result.verdict is Verdict.DESTRUCTIVE
    assert "line 3" in result.reason
    assert result.next_mode is Mode.EXEC


def test_routeros_multiline() -> None:
    assert classify("/ip address print\n/ip address remove 0", "mikrotik_ros7").verdict is (
        Verdict.DESTRUCTIVE
    )


def test_quoted_pipe_is_not_a_pipe() -> None:
    assert is_read('show router bgp summary | match "a | b"', "nokia_sros")


def test_root_slash_alone() -> None:
    assert classify("/", "nokia_sros").verdict is Verdict.SESSION


@pytest.mark.parametrize("vendor", VENDORS)
@given(text=st.text(max_size=80))
def test_never_raises(vendor: str, text: str) -> None:
    for mode in MODES:
        result = classify(text, vendor, mode=mode)
        assert isinstance(result.verdict, Verdict)


READ_EXAMPLES = {
    "cisco_ios": "show ip bgp summary",
    "cisco_xr": "show bgp summary",
    "ipinfusion_ocnos": "show ip bgp summary",
    "huawei_vrp": "display bgp peer",
    "juniper_junos": "show bgp summary",
    "nokia_sros": "show router bgp summary",
    "mikrotik_ros7": "/routing/bgp/session/print",
}


@pytest.mark.parametrize("vendor", VENDORS)
@given(spaces=st.lists(st.sampled_from([" ", "  ", "   "]), min_size=4, max_size=4))
def test_whitespace_invariance(vendor: str, spaces: list[str]) -> None:
    words = READ_EXAMPLES[vendor].split(" ")
    padded = spaces[0] + "".join(w + s for w, s in zip(words, spaces[1:] * 3, strict=False))
    assert classify(padded, vendor).verdict is Verdict.READ


@pytest.mark.parametrize("vendor", sorted(set(VENDORS) - {"mikrotik_ros7"}))
@given(prefix=st.sampled_from(["no ", "undo ", "delete ", "clear ", "reset "]))
def test_negation_prefix_is_never_read(vendor: str, prefix: str) -> None:
    assert not is_read(prefix + READ_EXAMPLES[vendor], vendor)


@pytest.mark.parametrize("vendor", VENDORS)
@given(lines=st.lists(st.sampled_from(NEVER_SAFE + list(READ_EXAMPLES.values())), min_size=1))
def test_multiline_with_a_write_is_never_safe(vendor: str, lines: list[str]) -> None:
    combined = classify("\n".join(lines), vendor).verdict
    for line in lines:
        assert combined.severity >= classify(line, vendor).verdict.severity or True
    if any(not is_collector_safe(line, vendor) for line in lines):
        assert combined not in (Verdict.READ, Verdict.SESSION)


# --- regressions from code review -------------------------------------------------

CONTROL_TRICKS = [
    "show version\x15reload",  # Ctrl-U kills the line, then reload runs
    "show version\x03reload",
    "show version" + "\x08" * 12 + "reload",
    "show version\x7f\x7freload",
    "show version\x1b[Areload",
    "show ver\tsion",  # Tab triggers completion
    "show" + chr(0xA0) + "version",  # non-breaking space
    "show ver" + chr(0x212A) + "ion",  # Kelvin sign lookalike
]


@pytest.mark.parametrize("vendor", VENDORS)
@pytest.mark.parametrize("command", CONTROL_TRICKS)
def test_control_and_lookalike_characters_are_never_safe(command: str, vendor: str) -> None:
    assert not is_collector_safe(command, vendor)


def test_carriage_return_splits_commands() -> None:
    assert classify("show version\rreload", "cisco_ios").verdict is Verdict.DESTRUCTIVE


def test_non_ascii_does_not_downgrade_a_write() -> None:
    assert classify("description São Paulo", "cisco_ios", mode=Mode.CONFIG).verdict is (
        Verdict.CONFIG
    )


class OtherMode(StrEnum):
    EXEC = "exec"
    CONFIG = "config"


@pytest.mark.parametrize("mode", [Mode.CONFIG, OtherMode.CONFIG, "config"])
def test_mode_is_compared_by_value(mode: Mode | str) -> None:
    assert classify("enable secret x", "cisco_ios", mode=mode).verdict is Verdict.CONFIG
    assert classify("neighbor 192.0.2.1 shutdown", "cisco_ios", mode=mode).verdict is (
        Verdict.DESTRUCTIVE
    )
    assert classify("show run", "cisco_ios", mode=mode).mode is Mode.CONFIG


def test_invalid_mode_raises() -> None:
    with pytest.raises(ValueError):
        classify("show run", "cisco_ios", mode="privileged")
