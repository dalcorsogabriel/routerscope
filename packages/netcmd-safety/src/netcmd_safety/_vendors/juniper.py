"""Juniper Junos."""

from __future__ import annotations

from .._engine import CONFIG, DESTRUCTIVE, READ, SESSION, Node, VendorSpec, leaf
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
        children={"cli": Node(verdict=Verdict.SESSION, children={}, default=Verdict.SESSION)},
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

_CONFIG: dict[str, Node] = {
    "show": READ,
    "status": READ,
    "help": READ,
    "run": Node(verdict=Verdict.UNKNOWN, recurse=True),
    "commit": Node(verdict=Verdict.CONFIG, children={"check": READ}, default=Verdict.CONFIG),
    "exit": Node(
        verdict=Verdict.SESSION,
        children={"configuration-mode": leaf(Verdict.SESSION, enters=Mode.EXEC)},
        default=Verdict.SESSION,
    ),
    "quit": SESSION,
    "up": SESSION,
    "top": SESSION,
    "edit": SESSION,
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
