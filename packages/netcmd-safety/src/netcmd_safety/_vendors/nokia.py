"""Nokia SR OS, classic CLI and MD-CLI."""

from __future__ import annotations

from collections.abc import Sequence

from .._engine import CONFIG, DESTRUCTIVE, READ, SESSION, Node, VendorSpec, leaf
from .._model import Mode, Verdict


def _environment(rest: Sequence[str]) -> Verdict | None:
    """``environment`` settings last for the session unless they are saved."""
    return Verdict.CONFIG if "save" in rest else None


_EXEC: dict[str, Node] = {
    "show": leaf(Verdict.READ, min_abbrev=2),
    "info": READ,
    "monitor": READ,
    "environment": Node(verdict=Verdict.SESSION, handler=_environment),
    "admin": Node(
        verdict=Verdict.DESTRUCTIVE,
        children={
            "display-config": READ,
            "show": Node(
                verdict=Verdict.UNKNOWN,
                children={"configuration": READ},
                default=Verdict.UNKNOWN,
            ),
            "save": CONFIG,
            "reboot": DESTRUCTIVE,
        },
        default=Verdict.DESTRUCTIVE,
    ),
    "configure": leaf(Verdict.CONFIG, enters=Mode.CONFIG),
    "edit-config": Node(
        verdict=Verdict.CONFIG,
        enters=Mode.CONFIG,
        children={"read-only": SESSION},
        default=Verdict.CONFIG,
    ),
    "tools": Node(
        verdict=Verdict.DESTRUCTIVE, children={"dump": READ}, default=Verdict.DESTRUCTIVE
    ),
    "file": Node(
        verdict=Verdict.DESTRUCTIVE,
        children={"dir": READ, "type": READ, "version": READ},
        default=Verdict.DESTRUCTIVE,
    ),
    "clear": DESTRUCTIVE,
    "debug": DESTRUCTIVE,
    "exec": DESTRUCTIVE,
    "exit": SESSION,
    "logout": SESSION,
    "back": SESSION,
    "quit-config": SESSION,
}

_CONFIG: dict[str, Node] = {
    "info": READ,
    "compare": READ,
    "validate": READ,
    "show": READ,
    "exit": Node(
        verdict=Verdict.SESSION,
        children={"all": leaf(Verdict.SESSION, enters=Mode.EXEC)},
        default=Verdict.SESSION,
    ),
    "back": SESSION,
    "top": SESSION,
    "quit-config": leaf(Verdict.SESSION, enters=Mode.EXEC),
    "commit": CONFIG,
    "discard": CONFIG,
    "delete": DESTRUCTIVE,
    "rollback": DESTRUCTIVE,
    "load": DESTRUCTIVE,
    "shutdown": DESTRUCTIVE,
    "no": DESTRUCTIVE,
}

SROS = VendorSpec(
    exec_table=_EXEC,
    config_table=_CONFIG,
    pipes={"match": READ, "count": READ, "no-more": READ, "as-json": READ},
    destructive_words=frozenset({"shutdown"}),
    destructive_pairs=frozenset({("admin-state", "disable")}),
    strip_root_slash=True,
)
