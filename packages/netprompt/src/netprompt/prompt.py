"""Prompt and prompt-banner detection."""

from __future__ import annotations

import re
from collections.abc import Collection
from dataclasses import dataclass
from enum import StrEnum
from typing import NamedTuple

from netprompt.constants import (
    CISCO_IOS,
    CISCO_XR,
    HUAWEI_VRP,
    IPINFUSION_OCNOS,
    JUNIPER_JUNOS,
    MIKROTIK_ROS7,
    NOKIA_SROS,
)


class Mode(StrEnum):
    """CLI mode of a prompt."""

    EXEC = "exec"
    CONFIG = "config"


@dataclass(frozen=True, slots=True)
class Prompt:
    """A detected prompt.

    ``vendor`` is ``None`` when ambiguous; ``candidates`` lists every consistent vendor.
    ``flags`` may contain ``uncommitted``, ``two_stage``, ``safe_mode``, ``standby`` and
    ``md_cli`` (Nokia MD-CLI two-line prompt).
    """

    raw: str
    hostname: str | None
    vendor: str | None
    candidates: tuple[str, ...]
    mode: Mode
    context: str | None = None
    flags: frozenset[str] = frozenset()


_CISCO_LIKE = (CISCO_IOS, IPINFUSION_OCNOS)

_XR = re.compile(
    r"[A-Z]+/\d+/[A-Z0-9]+/CPU\d+:(?P<host>[A-Za-z0-9][\w.\-]*)(?:\((?P<ctx>[^()\s]+)\))?#"
)
_NOKIA_MD = re.compile(
    r"(?P<star>\*?)(?P<role>[AB]):(?P<user>[A-Za-z0-9_][\w.\-]*)@(?P<host>[A-Za-z0-9][\w.\-]*)#"
)
_NOKIA_CLASSIC = re.compile(
    r"(?P<star>\*?)(?P<role>[AB]):(?P<host>[A-Za-z0-9][\w.\-]*)"
    r'(?P<path>(?:>[^\s#$>]+(?: "[^"]*")?)*)[#$]'
)
_ROS = re.compile(
    r"\[(?P<user>[^\s@\[\]]+)@(?P<host>[^\s\[\]]+)\] ?(?P<path>/[^\s<>]*)?(?:(?P<safe><SAFE>)|>)"
)
_VRP_EXEC = re.compile(r"<(?P<host>[A-Za-z][\w.\-]*)>(?!.*</)")
_VRP_CFG = re.compile(r"\[(?P<flags>[~*]{0,2})(?P<name>[A-Za-z][\w.\-/]*)\]")
_VRP_REJECT = frozenset(
    {"cr", "ok", "fail", "failed", "edit", "pass", "passed", "done", "info", "warn", "warning"}
    | {"error", "debug", "skip", "skipped"}
    | {"confirm", "yes", "no", "y/n", "yes/no"}
)
_JUNOS = re.compile(
    r"(?P<user>[A-Za-z_][\w.\-]*)@(?P<host>[A-Za-z0-9][\w.\-]*)(?P<end>[>#])(?=\s|$)"
)
_CISCO = re.compile(
    r"(?P<host>[A-Za-z0-9][\w.\-]*)(?:\((?P<ctx>[^()\s]+)\))?(?P<end>[>#])(?![\d:=])"
)
_NUMERIC_HOST = re.compile(r"[\d.]+")

_JUNOS_EDIT = re.compile(r"\[edit(?: (?P<ctx>[^\]]*))?\]\s*$")
_JUNOS_STATE = re.compile(r"\{[a-z]+(?::[\w-]+)?\}\s*$")
_MDCLI_A = re.compile(r"[*!]?\[(?:(?:ex|pr|gl|ro|in):)?(?P<path>/[^\]]*)\]\s*$")
_MDCLI_B = re.compile(r"[*!]?\((?:ex|pr|gl|ro|in)\)\[(?P<path>/[^\]]*)\]\s*$")


class Banner(NamedTuple):
    """A non-prompt line printed above a prompt."""

    kind: str  # "junos_edit" | "junos_state" | "mdcli"
    context: str | None
    config: bool


def parse_banner(line: str) -> Banner | None:
    """Classify ``line`` as a prompt banner, or return ``None``."""
    if not line or line[0] not in "[{*!(":
        return None
    if m := _JUNOS_EDIT.match(line):
        return Banner("junos_edit", m.group("ctx") or None, True)
    if _JUNOS_STATE.match(line):
        return Banner("junos_state", None, False)
    m = _MDCLI_A.match(line) or _MDCLI_B.match(line)
    if m:
        path = m.group("path").strip()
        config = path == "/configure" or path.startswith(("/configure ", "/configure/"))
        return Banner("mdcli", None if path == "/" else path, config)
    return None


def is_prompt_banner(line: str) -> bool:
    """Return True for lines printed above prompts that are not prompts themselves.

    Junos ``[edit]`` / ``[edit protocols bgp]`` and ``{master:0}``, and Nokia MD-CLI context
    lines such as ``[/]`` or ``[ex:/configure router "Base"]``.
    """
    return parse_banner(line) is not None


def _resolve_vrp(name: str, known: Collection[str] | None) -> tuple[str | None, str | None]:
    if "-" not in name:
        return name, None
    best: str | None = None
    for host in known or ():
        if name == host:
            return host, None
        if name.startswith(host + "-") and (best is None or len(host) > len(best)):
            best = host
    if best is not None:
        return best, name[len(best) + 1 :]
    return None, None


def _cisco_mode(ctx: str | None, end: str) -> tuple[Mode, str | None]:
    if end == ">" or ctx is None:
        return Mode.EXEC, None
    if ctx == "config":
        return Mode.CONFIG, None
    if ctx.startswith(("config", "cfg")):
        return Mode.CONFIG, ctx
    return Mode.EXEC, ctx


def detect_prompt(
    line: str, *, known_hostnames: Collection[str] | None = None
) -> tuple[Prompt, str] | None:
    """Detect a prompt at the start (column 0) of ``line``.

    Returns ``(prompt, command)`` where ``command`` is the rest of the line, stripped, or
    ``None`` if the line does not start with a prompt. ``known_hostnames`` disambiguates Huawei
    VRP prompts such as ``[PE-SP-01-bgp]`` where the hostname itself contains hyphens.
    """
    if not line or line[0].isspace() or is_prompt_banner(line):
        return None
    found = _match(line, known_hostnames)
    if found is None:
        return None
    prompt, end = found
    return prompt, line[end:].strip()


def _nokia(m: re.Match[str], mode: Mode, ctx: str | None, extra: set[str]) -> Prompt:
    flags = set(extra)
    if m["star"]:
        flags.add("uncommitted")
    if m["role"] == "B":
        flags.add("standby")
    return Prompt(m[0], m["host"], NOKIA_SROS, (NOKIA_SROS,), mode, ctx, frozenset(flags))


def _vrp_config(m: re.Match[str], known: Collection[str] | None) -> Prompt | None:
    if m["name"].lower() in _VRP_REJECT:
        return None
    flags: set[str] = set()
    if "*" in m["flags"]:
        flags.add("uncommitted")
    if "~" in m["flags"]:
        flags.add("two_stage")
    host, ctx = _resolve_vrp(m["name"], known)
    return Prompt(m[0], host, HUAWEI_VRP, (HUAWEI_VRP,), Mode.CONFIG, ctx, frozenset(flags))


def _match(line: str, known: Collection[str] | None) -> tuple[Prompt, int] | None:
    if m := _XR.match(line):
        mode, ctx = _cisco_mode(m["ctx"], "#")
        return Prompt(m[0], m["host"], CISCO_XR, (CISCO_XR,), mode, ctx), m.end()
    if m := _NOKIA_MD.match(line):
        return _nokia(m, Mode.EXEC, None, {"md_cli"}), m.end()
    if m := _NOKIA_CLASSIC.match(line):
        path = m["path"].lstrip(">")
        mode = Mode.CONFIG if path == "config" or path.startswith("config>") else Mode.EXEC
        return _nokia(m, mode, path or None, set()), m.end()
    if m := _ROS.match(line):
        flags = frozenset({"safe_mode"}) if m["safe"] else frozenset[str]()
        prompt = Prompt(
            m[0], m["host"], MIKROTIK_ROS7, (MIKROTIK_ROS7,), Mode.EXEC, m["path"], flags
        )
        return prompt, m.end()
    if m := _VRP_EXEC.match(line):
        if m["host"].lower() in _VRP_REJECT:
            return None
        return Prompt(m[0], m["host"], HUAWEI_VRP, (HUAWEI_VRP,), Mode.EXEC), m.end()
    if m := _VRP_CFG.match(line):
        vrp = _vrp_config(m, known)
        return (vrp, m.end()) if vrp is not None else None
    if m := _JUNOS.match(line):
        mode = Mode.CONFIG if m["end"] == "#" else Mode.EXEC
        return Prompt(m[0], m["host"], JUNIPER_JUNOS, (JUNIPER_JUNOS,), mode), m.end()
    if (m := _CISCO.match(line)) and not _NUMERIC_HOST.fullmatch(m["host"]):
        mode, ctx = _cisco_mode(m["ctx"], m["end"])
        return Prompt(m[0], m["host"], None, _CISCO_LIKE, mode, ctx), m.end()
    return None
