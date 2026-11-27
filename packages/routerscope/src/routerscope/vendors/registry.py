"""Discovery and lookup of vendor plugins through the ``routerscope.vendors`` entry-point group.

Rules:

* Built-in plugins (entry points shipped by the ``routerscope`` distribution) are registered
  first. A later plugin with an id that is already taken is skipped with a warning, so a
  third-party package cannot silently replace a built-in. To replace one deliberately, list its
  id in the ``ROUTERSCOPE_VENDOR_OVERRIDE`` environment variable (comma separated) or pass
  ``override=`` to :meth:`VendorRegistry.discover`.
* The entry-point name must equal ``plugin.id``.
* Anything that fails to import, instantiate or satisfy :class:`VendorPlugin`, or whose
  ``readonly_commands()`` contains a command rejected by netcmd-safety (for vendors netcmd-safety
  knows), is skipped with a warning. Discovery never raises because of a plugin.
* For vendor ids netcmd-safety does not know, commands cannot be verified, so
  :meth:`VendorRegistry.collector_commands` returns nothing for them.
* ``readonly_commands()`` is called once, at registration. The validated commands are frozen
  in the registry, so a plugin cannot change them later, and they are checked again (in exec
  mode) every time :meth:`VendorRegistry.collector_commands` hands them out.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterable, Sequence
from functools import lru_cache
from importlib.metadata import EntryPoint, entry_points

import netcmd_safety

from routerscope.vendors.base import VendorPlugin

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "routerscope.vendors"
OVERRIDE_ENV = "ROUTERSCOPE_VENDOR_OVERRIDE"
_BUILTIN_DIST = "routerscope"
_ID_RE = re.compile(r"^[a-z][a-z0-9_]*$")


def _dist_name(ep: EntryPoint) -> str:
    dist = getattr(ep, "dist", None)
    return str(dist.name).lower().replace("_", "-") if dist is not None else ""


def _safe(cmd: str, vendor_id: str) -> bool:
    return netcmd_safety.is_collector_safe(cmd, vendor_id, mode=netcmd_safety.Mode.EXEC)


def _validated_commands(plugin: VendorPlugin) -> tuple[str, ...] | str:
    """The plugin's read-only commands as a tuple, or the reason they are unacceptable."""
    try:
        raw = plugin.readonly_commands()
    except Exception as exc:
        return f"readonly_commands() failed: {exc!r}"
    if isinstance(raw, str | bytes) or not isinstance(raw, Sequence):
        return "readonly_commands() must return a list or tuple of strings"
    commands = tuple(raw)
    for cmd in commands:
        if not isinstance(cmd, str):
            return f"readonly command {cmd!r} is not a string"
        if plugin.id in netcmd_safety.VENDORS and not _safe(cmd, plugin.id):
            return f"readonly command {cmd!r} is not collector-safe for {plugin.id}"
    return commands


def check_plugin(plugin: object) -> str | None:
    """Return why ``plugin`` is unacceptable, or ``None`` if it is fine."""
    problem = _check(plugin)
    return problem if isinstance(problem, str) else None


def _check(plugin: object) -> tuple[str, ...] | str:
    if not isinstance(plugin, VendorPlugin):
        return "does not satisfy the VendorPlugin protocol"
    plugin_id = plugin.id
    if not isinstance(plugin_id, str) or not _ID_RE.match(plugin_id):
        return f"invalid plugin id {plugin_id!r} (use lowercase letters, digits, underscores)"
    if not isinstance(plugin.name, str) or not plugin.name:
        return "missing plugin name"
    return _validated_commands(plugin)


class VendorRegistry:
    """Holds validated plugins by id."""

    def __init__(self) -> None:
        self._plugins: dict[str, VendorPlugin] = {}
        self._commands: dict[str, tuple[str, ...]] = {}
        self._builtin: set[str] = set()

    def register(
        self, plugin: object, *, builtin: bool = False, replace: bool = False, source: str = ""
    ) -> bool:
        """Validate and add ``plugin``. Returns ``False`` (and logs) if it was rejected."""
        checked = _check(plugin)
        if isinstance(checked, str):
            logger.warning("skipping vendor plugin %s: %s", source or repr(plugin), checked)
            return False
        assert isinstance(plugin, VendorPlugin)
        if plugin.id in self._plugins and not replace:
            logger.warning(
                "skipping vendor plugin %s: id %r is already registered (set %s=%s to override)",
                source or repr(plugin),
                plugin.id,
                OVERRIDE_ENV,
                plugin.id,
            )
            return False
        self._plugins[plugin.id] = plugin
        self._commands[plugin.id] = checked
        if builtin:
            self._builtin.add(plugin.id)
        else:
            self._builtin.discard(plugin.id)
        return True

    def discover(
        self,
        eps: Iterable[EntryPoint] | None = None,
        *,
        override: Iterable[str] | None = None,
    ) -> None:
        """Load plugins from entry points (default: the installed ``routerscope.vendors`` group)."""
        if eps is None:
            eps = entry_points(group=ENTRY_POINT_GROUP)
        if override is None:
            override = [v.strip() for v in os.environ.get(OVERRIDE_ENV, "").split(",")]
        overrides = {v for v in override if v}
        ordered = sorted(eps, key=lambda e: (_dist_name(e) != _BUILTIN_DIST, _dist_name(e), e.name))
        for ep in ordered:
            label = f"{ep.name} ({ep.value})"
            builtin = _dist_name(ep) == _BUILTIN_DIST
            try:
                obj = ep.load()
                plugin = obj() if isinstance(obj, type) else obj
            except Exception as exc:
                logger.warning("skipping vendor plugin %s: failed to load: %r", label, exc)
                continue
            plugin_id = getattr(plugin, "id", None)
            if plugin_id != ep.name:
                logger.warning(
                    "skipping vendor plugin %s: entry-point name must equal plugin id (%r)",
                    label,
                    plugin_id,
                )
                continue
            self.register(
                plugin,
                builtin=builtin,
                replace=ep.name in overrides and not builtin,
                source=label,
            )

    def get(self, vendor_id: str) -> VendorPlugin | None:
        """Return the plugin for ``vendor_id`` or ``None``."""
        return self._plugins.get(vendor_id)

    def all(self) -> list[VendorPlugin]:
        """All plugins, sorted by id."""
        return [self._plugins[k] for k in sorted(self._plugins)]

    def is_builtin(self, vendor_id: str) -> bool:
        """True if the registered plugin for ``vendor_id`` is a built-in one."""
        return vendor_id in self._builtin

    def detect_ranked(self, text: str) -> list[tuple[str, float]]:
        """``(vendor_id, confidence)`` for every plugin with confidence > 0, best first."""
        scored: list[tuple[str, float]] = []
        for plugin in self.all():
            try:
                score = float(plugin.detect(text))
            except Exception as exc:
                logger.warning("vendor plugin %s failed in detect(): %r", plugin.id, exc)
                continue
            if score > 0:
                scored.append((plugin.id, min(score, 1.0)))
        return sorted(scored, key=lambda item: (-item[1], item[0]))

    def detect_vendor(self, text: str) -> str | None:
        """Best vendor id for ``text``; ``None`` if nothing matches or the top two tie."""
        ranked = self.detect_ranked(text)
        if not ranked or (len(ranked) > 1 and ranked[0][1] == ranked[1][1]):
            return None
        return ranked[0][0]

    def collector_commands(self, vendor_id: str) -> list[str]:
        """Read-only commands a collector may send for ``vendor_id`` (verified vendors only).

        These are the commands validated at registration, checked again here; they are meant to
        be sent in exec mode.
        """
        commands = self._commands.get(vendor_id, ())
        if vendor_id not in netcmd_safety.VENDORS:
            return []
        if not all(_safe(cmd, vendor_id) for cmd in commands):  # pragma: no cover - defensive
            logger.error("vendor plugin %s: stored commands failed re-check", vendor_id)
            return []
        return list(commands)


@lru_cache(maxsize=1)
def default_registry() -> VendorRegistry:
    """The process-wide registry, discovered once from installed entry points."""
    registry = VendorRegistry()
    registry.discover()
    return registry


def get(vendor_id: str) -> VendorPlugin | None:
    """Look up a plugin in the default registry."""
    return default_registry().get(vendor_id)


def all_plugins() -> list[VendorPlugin]:
    """All plugins of the default registry."""
    return default_registry().all()


def detect_vendor(text: str) -> str | None:
    """Detect the vendor of ``text`` with the default registry."""
    return default_registry().detect_vendor(text)
