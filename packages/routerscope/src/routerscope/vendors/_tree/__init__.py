"""Shared configuration-tree parsers used by the vendor plugins.

See ``docs/decisions/0003-config-tree-parser.md`` for why this is our own small parser.
"""

from routerscope.vendors._tree.brace import BraceDialect, parse_brace
from routerscope.vendors._tree.indent import Dialect, parse_indented
from routerscope.vendors._tree.node import ConfigNode
from routerscope.vendors._tree.routeros import RosCommand, parse_command, parse_routeros
from routerscope.vendors._tree.setstyle import SetDialect, looks_like_set, parse_set
from routerscope.vendors._tree.words import split_tokens, split_words, unquote

__all__ = [
    "BraceDialect",
    "ConfigNode",
    "Dialect",
    "RosCommand",
    "SetDialect",
    "looks_like_set",
    "parse_brace",
    "parse_command",
    "parse_indented",
    "parse_routeros",
    "parse_set",
    "split_tokens",
    "split_words",
    "unquote",
]
