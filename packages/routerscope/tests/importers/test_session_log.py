from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from routerscope.capture.importers import SessionLogImporter, detect_format
from routerscope.capture.importers.base import ImportError_, ImportItem
from routerscope.capture.importers.session_log import is_full_config_command, parse_session_log

TZ = timezone(timedelta(hours=2))  # not UTC, so zone handling is exercised
MTIME = 1_767_700_000
LOGS = {
    "securecrt.log": "securecrt",
    "putty.log": "putty",
    "mobaxterm.log": "mobaxterm",
    "script.log": "script",
    "iso.log": "iso",
    "plain.log": "plain",
}
Stage = Callable[..., Path]


def load(path: Path, **kwargs: object) -> list[ImportItem]:
    kwargs.setdefault("tz", TZ)
    return list(SessionLogImporter(path, **kwargs).items())  # type: ignore[arg-type]


@pytest.mark.parametrize(("name", "fmt"), LOGS.items())
def test_golden(name: str, fmt: str, stage: Stage, check_golden: Callable[..., None]) -> None:
    path = stage(name)
    items = load(path)
    assert items[0].kind == "session"
    assert {i.source.importer for i in items} == {fmt}
    assert all(i.source.kind == "session_log" and i.source.uri == str(path) for i in items)
    check_golden(items, name)


@pytest.mark.parametrize(("name", "fmt"), LOGS.items())
def test_detect_format(name: str, fmt: str, data_dir: Path) -> None:
    assert detect_format((data_dir / name).read_text(encoding="utf-8")) == fmt


@pytest.mark.parametrize("name", LOGS)
def test_crlf_and_bom_do_not_change_items(name: str, stage: Stage, data_dir: Path) -> None:
    text = (data_dir / name).read_text(encoding="utf-8")

    def keyed(items: list[ImportItem]) -> list[tuple[object, ...]]:
        return [(i.kind, i.command, i.captured_at, i.content) for i in items]

    crlf = stage("crlf-" + name, b"\xef\xbb\xbf" + text.replace("\n", "\r\n").encode())
    assert keyed(load(crlf)) == keyed(load(stage(name)))


def test_timestamps_are_stripped_from_session_content(stage: Stage) -> None:
    item = load(stage("securecrt.log"))[0]
    assert item.content.startswith("<R1>display version\n")
    assert "[2026-01-05" not in item.content
    assert item.hostname == "R1"
    assert item.vendor == "huawei_vrp"


def test_header_and_footer_lines_are_removed(stage: Stage) -> None:
    script = load(stage("script.log"))[0]
    assert "Script started" not in script.content
    assert "Script done" not in script.content
    assert "PuTTY log" not in load(stage("putty.log"))[0].content


def test_precedence_line_then_header_then_mtime(stage: Stage) -> None:
    mtime = datetime.fromtimestamp(MTIME, TZ)
    # no stamps, no header: modification time
    assert {i.captured_at for i in load(stage("plain.log"))} == {mtime}
    # header only: the header time, read in tz when it has no zone
    putty = {i.captured_at for i in load(stage("putty.log"))}
    assert putty == {datetime(2026, 1, 5, 10, 22, 1, tzinfo=TZ)}
    # a header with an explicit offset keeps it
    script = {i.captured_at for i in load(stage("script.log"))}
    assert script == {datetime(2026, 1, 5, 10, 22, 1, tzinfo=UTC)}
    # line stamps win and every command has its own
    crt = load(stage("securecrt.log"))
    assert len({i.captured_at for i in crt}) == 3
    assert crt[1].captured_at == datetime(2026, 1, 5, 10, 22, 1, tzinfo=TZ)


def test_iso_stamp_with_zone_is_kept(stage: Stage) -> None:
    items = load(stage("iso.log"))
    assert items[1].captured_at == datetime(2026, 1, 5, 10, 22, 1, 123000, tzinfo=UTC)


def test_default_timezone_is_local_and_never_naive(stage: Stage) -> None:
    for name in LOGS:
        for item in load(stage(name), tz=None):
            assert item.captured_at.utcoffset() is not None
    plain = load(stage("plain.log"), tz=None)[0]
    assert plain.captured_at == datetime.fromtimestamp(MTIME).astimezone()


def test_time_only_stamps_take_the_mtime_date_and_roll_over_midnight(stage: Stage) -> None:
    items = load(stage("mobaxterm.log"))
    first, second = items[1].captured_at, items[2].captured_at
    assert first == datetime(2026, 1, 6, 23, 58, 30, tzinfo=TZ)
    assert second == datetime(2026, 1, 7, 0, 1, 2, tzinfo=TZ)


def test_invalid_stamp_is_stripped_without_time(stage: Stage) -> None:
    text = "[2026-13-45 10:00:00] R1#show clock\n[2026-13-45 10:00:00] 10:00:00 UTC\n"
    items = load(stage("bad.log", text.encode()), format="securecrt")
    assert items[1].command == "show clock"
    assert items[1].captured_at == datetime.fromtimestamp(MTIME, TZ)


def test_forced_format_and_aliases(stage: Stage) -> None:
    path = stage("plain.log")
    for alias in ("windows_terminal", "tabby", "iterm", "termius", "plain"):
        assert load(path, format=alias)[0].source.importer == "plain"
    assert load(path, format="securecrt")[0].source.importer == "securecrt"
    with pytest.raises(ValueError, match="unknown log format"):
        SessionLogImporter(path, format="nope")


def test_ansi_export_is_cleaned(stage: Stage) -> None:
    raw = (
        "\x1b[32mR1#\x1b[0mshow clock\r\n\x1b]0;title\x07*10:00:00.000 UTC Mon Jan 5 2026\r\n"
        "R1#\r\n"
    )
    items = load(stage("wt.txt", raw.encode()))
    assert items[1].command == "show clock"
    assert items[1].content == "*10:00:00.000 UTC Mon Jan 5 2026"
    assert "\x1b" not in items[0].content


def test_pagination_is_removed_and_times_stay_aligned() -> None:
    text = (
        "[2026-01-05 10:00:00] <R1>display interface brief\n"
        "[2026-01-05 10:00:01] GE0/0/1  up\n"
        "[2026-01-05 10:00:02]   ---- More ----\n"
        "[2026-01-05 10:00:03] GE0/0/2  down\n"
        "[2026-01-05 10:00:09] <R1>display clock\n"
        "[2026-01-05 10:00:09] 2026-01-05 10:00:09\n"
    )
    parsed = parse_session_log(text, tz=TZ, fallback=datetime(2026, 1, 1, tzinfo=UTC))
    assert "More" not in parsed.content
    assert parsed.content.count("\n") == 5
    assert [s.command for s in parsed.segments] == ["display interface brief", "display clock"]
    assert parsed.command_times[1] == datetime(2026, 1, 5, 10, 0, 9, tzinfo=TZ)


def test_commands_without_output_are_not_emitted(stage: Stage) -> None:
    commands = {i.command for i in load(stage("securecrt.log"))}
    assert "system-view" not in commands
    assert "quit" not in commands


def test_log_without_prompts_yields_only_the_session(stage: Stage) -> None:
    items = load(stage("n.txt", b"just some notes\n"))
    assert [i.kind for i in items] == ["session"]
    assert items[0].hostname is None
    assert items[0].vendor is None


def test_errors(tmp_path: Path, stage: Stage) -> None:
    with pytest.raises(ImportError_, match="cannot read"):
        load(tmp_path / "missing.log")
    with pytest.raises(ImportError_, match="empty"):
        load(stage("e.log", b"  \n"))


def test_detect_format_edge_cases() -> None:
    assert detect_format("") == "plain"
    assert detect_format("\n\n") == "plain"
    assert detect_format("[10:00:00] a\nb\nc\nd\n") == "plain"  # minority prefix
    assert detect_format("[10:00:00] a\n[10:00:01] b\nc\n") == "mobaxterm"


FULLCONFIG = {
    "fullconfig-ios.log": ("cisco_ios", ["show run"]),
    "fullconfig-vrp.log": ("huawei_vrp", ["dis cur"]),
    "fullconfig-junos.log": ("juniper_junos", ["show configuration | display set"]),
    "fullconfig-ros7.log": ("mikrotik_ros7", ["/export terse"]),
    "fullconfig-sros.log": ("nokia_sros", ["admin display-config"]),
}


@pytest.mark.parametrize(("name", "expected"), FULLCONFIG.items())
def test_full_config_commands_also_yield_a_config_item(
    name: str,
    expected: tuple[str, list[str]],
    stage: Stage,
    check_golden: Callable[..., None],
) -> None:
    vendor, commands = expected
    items = load(stage(name))
    configs = [i for i in items if i.kind == "config"]
    assert [c.command for c in configs] == commands
    assert configs[0].vendor == vendor
    twin = next(i for i in items if i.kind == "command_output" and i.command == commands[0])
    assert (configs[0].content, configs[0].hostname, configs[0].captured_at) == (
        twin.content,
        twin.hostname,
        twin.captured_at,
    )
    assert commands[0] not in str(configs[0].content)  # no command echo
    assert "More" not in str(configs[0].content)
    check_golden(items, name)


@pytest.mark.parametrize(
    "command",
    [
        "show running-config",
        "show run",
        "sh run",
        "SHOW RUN",
        "show  running-config ",
        "show runn",
        "display current-configuration",
        "dis cur",
        "display cur",
        "show configuration",
        "show configuration | display set",
        "show configuration | display set | no-more",
        "show conf | no-more",
        "admin display-config",
        "admin show configuration",
        "/export",
        "/export compact",
        "/export verbose terse",
    ],
)
def test_is_full_config_command_positive(command: str) -> None:
    assert is_full_config_command(command)


@pytest.mark.parametrize(
    "command",
    [
        "",
        "show run interface Gi0/0",
        "show run | include hostname",
        "show run | section bgp",
        "show running-config | begin router",
        "show running-config | exclude !",
        "s run",
        "show ru",
        "dis cur interface",
        "display current-configuration | include sysname",
        "display version",
        "show configuration interfaces",
        "show configuration | match x",
        "show configuration | display set | count",
        "show version",
        "admin display-config | match x",
        "admin show version",
        "admin display-config x",
        "/ip address export",
        "/export file=backup",
        "/export | grep x",
        "info",
    ],
)
def test_is_full_config_command_negative(command: str) -> None:
    assert not is_full_config_command(command)


def test_full_config_vendor_guard() -> None:
    assert not is_full_config_command("show configuration", "cisco_xr")
    assert is_full_config_command("show configuration", "juniper_junos")
    assert not is_full_config_command("show run", "huawei_vrp")
    assert not is_full_config_command("dis cur", "cisco_ios")
    assert not is_full_config_command("/export", "cisco_ios")
    assert not is_full_config_command("admin display-config", "cisco_ios")
    assert not is_full_config_command("admin show configuration", "cisco_ios")
    assert is_full_config_command("show run", "cisco_xr")
