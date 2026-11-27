"""Cisco IOS / IOS-XE, IOS-XR and IP Infusion OcNOS (Cisco-like CLI)."""

from __future__ import annotations

from .._engine import CONFIG, DESTRUCTIVE, READ, SESSION, Node, VendorSpec, leaf
from .._model import Mode, Verdict

_TERMINAL = Node(
    verdict=Verdict.UNKNOWN,
    min_abbrev=3,
    children={
        "length": SESSION,
        "width": SESSION,
        "monitor": SESSION,
        "no": SESSION,
        "exec": SESSION,
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

_COMMON_EXEC: dict[str, Node] = {
    "show": leaf(Verdict.READ, min_abbrev=2),
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
    "enable": SESSION,
    "disable": SESSION,
}

_DO = Node(verdict=Verdict.UNKNOWN, recurse=True)
_END = leaf(Verdict.SESSION, enters=Mode.EXEC)

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
    redirect=False,
)

XR = VendorSpec(
    exec_table={
        **_COMMON_EXEC,
        "admin": Node(verdict=Verdict.UNKNOWN, recurse=True),
        "rollback": DESTRUCTIVE,
    },
    config_table={
        **_COMMON_CONFIG,
        "show": READ,
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
    redirect=False,
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
    redirect=False,
)
