"""Huawei VRP (V5 and V8)."""

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


def _temporary_only(rest: Sequence[str]) -> Verdict:
    """``screen-length 0 temporary`` lasts for the session; without it, it is config."""
    if rest and len(rest[-1]) >= 4 and "temporary".startswith(rest[-1]):
        return Verdict.SESSION
    return Verdict.CONFIG


_SCREEN = Node(verdict=Verdict.CONFIG, handler=_temporary_only)

# `display diagnostic-information <file>` writes the output to a file on flash.
_DISPLAY = Node(
    verdict=Verdict.READ,
    min_abbrev=3,
    children={
        "diagnostic-information": Node(
            verdict=Verdict.READ, children={}, default=Verdict.DESTRUCTIVE
        )
    },
    default=Verdict.READ,
)

_EXEC: dict[str, Node] = {
    "display": _DISPLAY,
    "screen-length": _SCREEN,
    "screen-width": _SCREEN,
    "terminal": Node(
        verdict=Verdict.UNKNOWN,
        children={
            "monitor": SESSION,
            "debugging": SESSION,
            "logging": SESSION,
            "trapping": SESSION,
        },
        default=Verdict.UNKNOWN,
    ),
    "undo": Node(
        verdict=Verdict.DESTRUCTIVE,
        children={
            "screen-length": _SCREEN,
            "screen-width": _SCREEN,
            "terminal": SESSION_ARGS,
            "debugging": CONFIG,
        },
        default=Verdict.DESTRUCTIVE,
    ),
    "quit": SESSION,
    "return": SESSION,
    "system-view": leaf(Verdict.CONFIG, min_abbrev=3, enters=Mode.CONFIG),
    "save": CONFIG,
    "reset": DESTRUCTIVE,
    "reboot": DESTRUCTIVE,
    "startup": DESTRUCTIVE,
    "delete": DESTRUCTIVE,
    "format": DESTRUCTIVE,
    "debugging": DESTRUCTIVE,
    "copy": DESTRUCTIVE,
    "move": DESTRUCTIVE,
    "rename": DESTRUCTIVE,
    "rollback": DESTRUCTIVE,
    "clear": DESTRUCTIVE,
}

_CONFIG: dict[str, Node] = {
    "display": _DISPLAY,
    "undo": DESTRUCTIVE,
    "quit": SESSION,
    "return": session(enters=Mode.EXEC),
    "commit": CONFIG,
    "rollback": DESTRUCTIVE,
    "clear": DESTRUCTIVE,
    "shutdown": DESTRUCTIVE,
}

VRP = VendorSpec(
    exec_table=_EXEC,
    config_table=_CONFIG,
    pipes={
        "begin": READ,
        "count": READ,
        "exclude": READ,
        "include": READ,
        "section": READ,
        "no-more": READ,
        "refresh": READ,
    },
    destructive_words=frozenset({"shutdown", "ignore"}),
    quotes=False,
)
