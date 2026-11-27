"""Juniper Junos."""

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

_EXEC: dict[str, Node] = {
    "show": leaf(Verdict.READ, min_abbrev=2),
    "file": Node(
        verdict=Verdict.DESTRUCTIVE,
        children={"show": READ, "list": READ, "compare": READ, "checksum": READ},
        default=Verdict.DESTRUCTIVE,
    ),
    # `set cli ...` only changes the CLI session; any other operational `set` changes state.
    "set": Node(
        verdict=Verdict.CONFIG,
        children={"cli": SESSION_ARGS},
        default=Verdict.CONFIG,
    ),
    "configure": leaf(Verdict.CONFIG, enters=Mode.CONFIG),
    "edit": leaf(Verdict.CONFIG, enters=Mode.CONFIG),
    "request": DESTRUCTIVE,
    "clear": DESTRUCTIVE,
    "restart": DESTRUCTIVE,
    "start": DESTRUCTIVE,
    "op": DESTRUCTIVE,
    "delete": DESTRUCTIVE,
    "save": DESTRUCTIVE,
    "load": DESTRUCTIVE,
    "quit": SESSION,
    "exit": SESSION,
}

_EDIT_FORBIDDEN = frozenset(
    {
        "set",
        "delete",
        "deactivate",
        "activate",
        "rollback",
        "load",
        "replace",
        "insert",
        "rename",
        "copy",
        "annotate",
        "commit",
        "run",
        "disable",
    }
)


def _edit_path(rest: Sequence[str]) -> Verdict | None:
    """``edit <hierarchy>`` only navigates; a command word in the path is suspicious."""
    if any(w in _EDIT_FORBIDDEN for w in rest):
        return Verdict.UNKNOWN
    return None


_CONFIG: dict[str, Node] = {
    "show": READ,
    "status": READ,
    "help": READ,
    "run": Node(verdict=Verdict.UNKNOWN, recurse=Mode.EXEC),
    "commit": Node(verdict=Verdict.CONFIG, children={"check": READ}, default=Verdict.CONFIG),
    "exit": Node(
        verdict=Verdict.SESSION,
        children={"configuration-mode": session(enters=Mode.EXEC)},
        default=Verdict.UNKNOWN,
    ),
    "quit": SESSION,
    # `top <command>` and `up [n] <command>` run the command at another level.
    "up": Node(verdict=Verdict.SESSION, recurse=Mode.CONFIG, skip_number=True),
    "top": Node(verdict=Verdict.SESSION, recurse=Mode.CONFIG),
    "edit": Node(verdict=Verdict.SESSION, handler=_edit_path),
    "delete": DESTRUCTIVE,
    "deactivate": DESTRUCTIVE,
    "rollback": DESTRUCTIVE,
    "load": DESTRUCTIVE,
    "replace": DESTRUCTIVE,
    "set": CONFIG,
}

JUNOS = VendorSpec(
    exec_table=_EXEC,
    config_table=_CONFIG,
    pipes={
        "compare": READ,
        "count": READ,
        "display": READ,
        "except": READ,
        "find": READ,
        "hold": READ,
        "last": READ,
        "match": READ,
        "no-more": READ,
        "refresh": READ,
        "resolve": READ,
        "trim": READ,
        "save": DESTRUCTIVE,
        "append": DESTRUCTIVE,
        "tee": DESTRUCTIVE,
    },
    destructive_words=frozenset({"disable", "deactivate"}),
)
