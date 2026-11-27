"""Cisco IOS / IOS-XE, IOS-XR and IP Infusion OcNOS (Cisco-like CLI)."""

from __future__ import annotations

from collections.abc import Sequence

from .._engine import (
    CONFIG,
    DESTRUCTIVE,
    READ,
    SESSION,
    SESSION_ARGS,
    Node,
    VendorSpec,
    leaf,
    session,
)
from .._model import Mode, Verdict

_TERMINAL = Node(
    verdict=Verdict.UNKNOWN,
    min_abbrev=3,
    children={
        "length": SESSION_ARGS,
        "width": SESSION_ARGS,
        "monitor": SESSION,
        "no": SESSION_ARGS,
        "exec": SESSION_ARGS,
    },
    default=Verdict.UNKNOWN,
)

_CONFIGURE = Node(
    verdict=Verdict.CONFIG,
    min_abbrev=4,
    enters=Mode.CONFIG,
    children={"replace": DESTRUCTIVE},
    default=Verdict.CONFIG,
)

_WRITE = Node(
    verdict=Verdict.CONFIG,
    min_abbrev=2,
    children={"erase": DESTRUCTIVE},
    default=Verdict.CONFIG,
)


def _show_args(rest: Sequence[str]) -> Verdict | None:
    """`show tech-support ... file <path>` (and `compressed`) writes to the device disk."""
    tech = bool(rest) and len(rest[0]) >= 3 and "tech-support".startswith(rest[0])
    if tech and any(":" in w or w == "compressed" or "file".startswith(w) for w in rest[1:]):
        return Verdict.DESTRUCTIVE
    return None


_SHOW = Node(verdict=Verdict.READ, min_abbrev=2, handler=_show_args)

_COMMON_EXEC: dict[str, Node] = {
    "show": _SHOW,
    "terminal": _TERMINAL,
    "configure": _CONFIGURE,
    "write": _WRITE,
    "copy": DESTRUCTIVE,
    "delete": DESTRUCTIVE,
    "erase": DESTRUCTIVE,
    "format": DESTRUCTIVE,
    "reload": DESTRUCTIVE,
    "clear": DESTRUCTIVE,
    "debug": DESTRUCTIVE,
    "undebug": CONFIG,
    "no": DESTRUCTIVE,
    "squeeze": DESTRUCTIVE,
    "undelete": DESTRUCTIVE,
    "exit": SESSION,
    "end": SESSION,
    "quit": SESSION,
    "logout": SESSION,
    "enable": session(numeric=True),
    "disable": session(numeric=True),
}

_DO = Node(verdict=Verdict.UNKNOWN, recurse=Mode.EXEC)
_END = session(enters=Mode.EXEC)

_COMMON_CONFIG: dict[str, Node] = {
    "do": _DO,
    "end": _END,
    "exit": SESSION,
    "no": DESTRUCTIVE,
    "shutdown": DESTRUCTIVE,
}

_CISCO_PIPES: dict[str, Node] = {
    "begin": READ,
    "count": READ,
    "exclude": READ,
    "include": READ,
    "section": READ,
    "format": READ,
    "append": DESTRUCTIVE,
    "redirect": DESTRUCTIVE,
    "tee": DESTRUCTIVE,
}

IOS = VendorSpec(
    exec_table=_COMMON_EXEC,
    config_table=_COMMON_CONFIG,
    pipes=_CISCO_PIPES,
    destructive_words=frozenset({"shutdown"}),
    quotes=False,
)

XR = VendorSpec(
    exec_table={
        **_COMMON_EXEC,
        "admin": Node(verdict=Verdict.UNKNOWN, recurse=Mode.EXEC),
        "rollback": DESTRUCTIVE,
    },
    config_table={
        **_COMMON_CONFIG,
        "show": _SHOW,
        "pwd": SESSION,
        "commit": Node(
            verdict=Verdict.CONFIG, children={"replace": DESTRUCTIVE}, default=Verdict.CONFIG
        ),
        "abort": leaf(Verdict.CONFIG, enters=Mode.EXEC),
        "rollback": DESTRUCTIVE,
    },
    pipes={
        "begin": READ,
        "count": READ,
        "exclude": READ,
        "include": READ,
        "file": DESTRUCTIVE,
    },
    destructive_words=frozenset({"shutdown"}),
    quotes=False,
)

OCNOS = VendorSpec(
    exec_table=_COMMON_EXEC,
    config_table={
        **_COMMON_CONFIG,
        "commit": CONFIG,
        "abort": CONFIG,
    },
    pipes={
        "begin": READ,
        "count": READ,
        "exclude": READ,
        "include": READ,
        "grep": READ,
        "last": READ,
        "json": READ,
        "section": READ,
        "no-more": READ,
        "append": DESTRUCTIVE,
        "redirect": DESTRUCTIVE,
        "tee": DESTRUCTIVE,
    },
    destructive_words=frozenset({"shutdown"}),
    quotes=False,
)
