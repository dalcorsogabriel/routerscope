from __future__ import annotations

import logging
from collections.abc import Sequence
from importlib.metadata import EntryPoint

import netcmd_safety
import pytest
from routerscope.model import Snapshot
from routerscope.vendors import (
    BaseVendorPlugin,
    Snippet,
    SnippetIntent,
    VendorPlugin,
    VendorRegistry,
    all_plugins,
    default_registry,
    detect_vendor,
    get,
)
from routerscope.vendors.registry import check_plugin

HUAWEI_SESSION = "<R1>display version\nHuawei Versatile Routing Platform Software\n"
IOS_SESSION = "r1#show version\nCisco IOS Software, Version 15.2\n"


class Dummy(BaseVendorPlugin):
    id = "dummy_os"
    name = "Dummy"


class UnsafeIOS(BaseVendorPlugin):
    id = "cisco_ios"
    name = "Unsafe"

    def readonly_commands(self) -> Sequence[str]:
        return ("show version", "reload")


class Exploding(BaseVendorPlugin):
    id = "boom_os"
    name = "Boom"

    def readonly_commands(self) -> Sequence[str]:
        raise RuntimeError("boom")


def make_ep(name: str, value: str, dist: str = "") -> EntryPoint:
    return EntryPoint(name=name, value=value, group="routerscope.vendors")


def test_builtins_registered() -> None:
    ids = [p.id for p in all_plugins()]
    assert ids == sorted(netcmd_safety.VENDORS)
    assert default_registry().is_builtin("cisco_ios")
    assert get("nokia_sros") is not None
    assert get("nope") is None


def test_builtin_readonly_commands_are_safe() -> None:
    for plugin in all_plugins():
        for cmd in plugin.readonly_commands():
            assert netcmd_safety.is_collector_safe(cmd, plugin.id), (plugin.id, cmd)


def test_registry_detect_vendor() -> None:
    assert detect_vendor(HUAWEI_SESSION) == "huawei_vrp"
    assert detect_vendor(IOS_SESSION) == "cisco_ios"
    assert detect_vendor("nothing to see") is None
    ranked = default_registry().detect_ranked(HUAWEI_SESSION)
    assert ranked[0] == ("huawei_vrp", 1.0)


def test_detect_tie_returns_none() -> None:
    reg = VendorRegistry()

    class A(Dummy):
        id = "a_os"

        def detect(self, text: str) -> float:
            return 0.5

    class B(A):
        id = "b_os"

    assert reg.register(A()) and reg.register(B())
    assert reg.detect_vendor("x") is None


def test_detect_failure_is_skipped(caplog: pytest.LogCaptureFixture) -> None:
    class Bad(Dummy):
        def detect(self, text: str) -> float:
            raise ValueError("nope")

    reg = VendorRegistry()
    reg.register(Bad())
    with caplog.at_level(logging.WARNING):
        assert reg.detect_ranked("x") == []
    assert "failed in detect" in caplog.text


def test_unsafe_plugin_rejected(caplog: pytest.LogCaptureFixture) -> None:
    reg = VendorRegistry()
    with caplog.at_level(logging.WARNING):
        assert reg.register(UnsafeIOS()) is False
    assert "not collector-safe" in caplog.text
    assert reg.get("cisco_ios") is None


def test_check_plugin_problems() -> None:
    assert check_plugin(Dummy()) is None
    assert "protocol" in (check_plugin(object()) or "")
    assert "invalid plugin id" in (check_plugin(type("P", (Dummy,), {"id": "Bad Id"})()) or "")
    assert "missing plugin name" in (check_plugin(type("P", (Dummy,), {"name": ""})()) or "")
    assert "readonly_commands() failed" in (check_plugin(Exploding()) or "")


def test_non_string_command_rejected() -> None:
    class P(BaseVendorPlugin):
        id = "huawei_vrp"
        name = "x"

        def readonly_commands(self) -> Sequence[str]:
            return [42]  # type: ignore[list-item]

    assert "not a string" in (check_plugin(P()) or "")


def test_duplicate_id_keeps_first(caplog: pytest.LogCaptureFixture) -> None:
    reg = VendorRegistry()
    first, second = Dummy(), Dummy()
    assert reg.register(first, builtin=True)
    with caplog.at_level(logging.WARNING):
        assert reg.register(second) is False
    assert "already registered" in caplog.text
    assert reg.get("dummy_os") is first
    assert reg.is_builtin("dummy_os")
    assert reg.register(second, replace=True)
    assert reg.get("dummy_os") is second
    assert not reg.is_builtin("dummy_os")


def test_collector_commands_only_for_verified_vendors() -> None:
    class Known(BaseVendorPlugin):
        id = "huawei_vrp"
        name = "k"

        def readonly_commands(self) -> Sequence[str]:
            return ("display version",)

    class Unknown(Dummy):
        def readonly_commands(self) -> Sequence[str]:
            return ("show version",)

    reg = VendorRegistry()
    reg.register(Known())
    reg.register(Unknown())
    assert reg.collector_commands("huawei_vrp") == ["display version"]
    assert reg.collector_commands("dummy_os") == []
    assert reg.collector_commands("missing") == []


def test_discover_skips_bad_entry_points(caplog: pytest.LogCaptureFixture) -> None:
    eps = [
        make_ep("nonexistent", "no_such_module_xyz:Plugin"),
        make_ep("dummy_os", "routerscope.vendors.base:BaseVendorPlugin"),  # id mismatch
        make_ep("x", "routerscope.vendors.base:SnippetIntent"),  # cannot instantiate
        make_ep("ok", "routerscope.vendors.cisco_ios:Plugin"),  # name != id
        make_ep("cisco_ios", "routerscope.vendors.cisco_ios:Plugin"),
    ]
    reg = VendorRegistry()
    with caplog.at_level(logging.WARNING):
        reg.discover(eps, override=[])
    assert [p.id for p in reg.all()] == ["cisco_ios"]
    assert "failed to load" in caplog.text
    assert "entry-point name must equal plugin id" in caplog.text


def test_protocol_and_base_defaults(snapshot: Snapshot) -> None:
    plugin = Dummy()
    assert isinstance(plugin, VendorPlugin)
    assert not isinstance(object(), VendorPlugin)
    assert plugin.detect("anything") == 0.0
    cfg = plugin.parse_config("x", snapshot)
    assert cfg.snapshot_id == snapshot.id
    assert cfg.vendor == "dummy_os"
    assert plugin.parse_command("show x", "out", snapshot) is None
    assert plugin.readonly_commands() == ()
    assert plugin.render_snippet(SnippetIntent(action="a", target="b")) is None
    assert plugin.segment("") == []


def test_base_detect_and_segment_delegate_to_netprompt() -> None:
    plugin = get("huawei_vrp")
    assert plugin is not None
    assert plugin.detect(HUAWEI_SESSION) == 1.0
    assert plugin.detect(IOS_SESSION) == 0.0
    segs = plugin.segment(HUAWEI_SESSION)
    assert segs
    assert segs[0].command == "display version"


def test_snippet_model() -> None:
    snip = Snippet(apply="a", rollback="b")
    assert Snippet.model_validate_json(snip.model_dump_json()) == snip
    intent = SnippetIntent(action="x", target="y", params={"k": "v"})
    assert SnippetIntent.model_validate_json(intent.model_dump_json()) == intent


# --- regressions from code review: commands are frozen at registration ------------


class Flipping(BaseVendorPlugin):
    id = "cisco_ios"
    name = "Flipping"

    def __init__(self) -> None:
        self.calls = 0

    def readonly_commands(self) -> Sequence[str]:
        self.calls += 1
        return ["show version"] if self.calls == 1 else ["reload"]


class Mutating(BaseVendorPlugin):
    id = "cisco_ios"
    name = "Mutating"
    shared: list[str] = ["show version"]  # noqa: RUF012

    def readonly_commands(self) -> Sequence[str]:
        return self.shared


def test_commands_cannot_change_after_registration() -> None:
    reg = VendorRegistry()
    assert reg.register(Flipping())
    assert reg.collector_commands("cisco_ios") == ["show version"]

    reg = VendorRegistry()
    plugin = Mutating()
    assert reg.register(plugin)
    plugin.shared.append("reload")
    assert reg.collector_commands("cisco_ios") == ["show version"]


class StringCommands(BaseVendorPlugin):
    id = "cisco_ios"
    name = "Str"

    def readonly_commands(self) -> Sequence[str]:
        return "show version"


class GeneratorCommands(BaseVendorPlugin):
    id = "cisco_ios"
    name = "Gen"

    def readonly_commands(self) -> Sequence[str]:
        return (c for c in ["show version"])  # type: ignore[return-value]


@pytest.mark.parametrize("plugin", [StringCommands(), GeneratorCommands()])
def test_commands_must_be_a_list_or_tuple(plugin: BaseVendorPlugin) -> None:
    assert "list or tuple" in (check_plugin(plugin) or "")
