"""Discovery through real entry points: a temporary dist-info on sys.path, no mocking."""

from __future__ import annotations

import importlib
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from routerscope.model import Snapshot
from routerscope.vendors import SnippetIntent, VendorRegistry

TEMPLATE_SRC = Path(__file__).resolve().parents[3] / "examples" / "vendor-plugin-template" / "src"

CONFIG = "ExampleOS 1.0\nhostname edge1\ninterface eth0\n description uplink\n mtu 1500\nexit\n"


def write_dist(root: Path, name: str, entry_points: str) -> None:
    dist = root / f"{name.replace('-', '_')}-0.0.1.dist-info"
    dist.mkdir()
    (dist / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {name}\nVersion: 0.0.1\n", encoding="utf-8", newline="\n"
    )
    (dist / "entry_points.txt").write_text(
        f"[routerscope.vendors]\n{entry_points}\n", encoding="utf-8", newline="\n"
    )


@pytest.fixture
def template_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    assert TEMPLATE_SRC.is_dir()
    monkeypatch.syspath_prepend(str(TEMPLATE_SRC))
    monkeypatch.syspath_prepend(str(tmp_path))
    yield tmp_path
    sys.modules.pop("routerscope_vendor_template", None)
    importlib.invalidate_caches()


def test_template_plugin_discovered_via_real_entry_points(
    template_on_path: Path, snapshot: Snapshot
) -> None:
    write_dist(
        template_on_path,
        "routerscope-vendor-template",
        "example_os = routerscope_vendor_template:ExamplePlugin",
    )
    reg = VendorRegistry()
    reg.discover()
    plugin = reg.get("example_os")
    assert plugin is not None
    assert not reg.is_builtin("example_os")
    assert reg.get("cisco_ios") is not None  # built-ins are still there

    assert reg.detect_vendor(CONFIG) == "example_os"
    cfg = plugin.parse_config(CONFIG, snapshot)
    assert cfg.device is not None
    assert cfg.device.hostname == "edge1"
    assert [i.name for i in cfg.interfaces] == ["eth0"]
    iface = cfg.interfaces[0]
    assert (iface.ref.line_start, iface.ref.line_end) == (3, 5)
    assert iface.description == "uplink"
    snip = plugin.render_snippet(SnippetIntent(action="shutdown_interface", target="eth0"))
    assert snip is not None
    assert "no shutdown" in snip.rollback
    assert plugin.render_snippet(SnippetIntent(action="other", target="x")) is None
    # Unknown to netcmd-safety, so a collector must not use its commands.
    assert reg.collector_commands("example_os") == []


def test_third_party_cannot_replace_builtin_without_override(
    template_on_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    write_dist(
        template_on_path,
        "evil-plugin",
        "cisco_ios = routerscope_vendor_template:ExamplePlugin",
    )
    reg = VendorRegistry()
    with caplog.at_level("WARNING"):
        reg.discover(override=[])
    plugin = reg.get("cisco_ios")
    assert plugin is not None
    assert reg.is_builtin("cisco_ios")
    assert "entry-point name must equal plugin id" in caplog.text


def test_third_party_override_of_builtin(
    template_on_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A plugin class whose id is cisco_ios, shipped by another distribution.
    (template_on_path / "my_ios_plugin.py").write_text(
        "from routerscope.vendors import BaseVendorPlugin\n\n\n"
        "class Mine(BaseVendorPlugin):\n    id = 'cisco_ios'\n    name = 'Mine'\n",
        encoding="utf-8",
        newline="\n",
    )
    write_dist(template_on_path, "my-ios", "cisco_ios = my_ios_plugin:Mine")
    try:
        default = VendorRegistry()
        default.discover(override=[])
        assert default.get("cisco_ios") is not None
        assert default.get("cisco_ios").name != "Mine"  # type: ignore[union-attr]

        overridden = VendorRegistry()
        overridden.discover(override=["cisco_ios"])
        assert overridden.get("cisco_ios").name == "Mine"  # type: ignore[union-attr]
        assert not overridden.is_builtin("cisco_ios")

        monkeypatch.setenv("ROUTERSCOPE_VENDOR_OVERRIDE", " , cisco_ios")
        from_env = VendorRegistry()
        from_env.discover()
        assert from_env.get("cisco_ios").name == "Mine"  # type: ignore[union-attr]
    finally:
        sys.modules.pop("my_ios_plugin", None)


def test_broken_third_party_does_not_crash(
    template_on_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    write_dist(template_on_path, "broken", "broken_os = module_that_does_not_exist:Plugin")
    reg = VendorRegistry()
    with caplog.at_level("WARNING"):
        reg.discover()
    assert reg.get("broken_os") is None
    assert len(reg.all()) >= 7
    assert "broken_os" in caplog.text
