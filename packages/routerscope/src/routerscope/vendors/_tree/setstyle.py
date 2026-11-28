"""Set-style parser: Junos ``display set`` and SR OS MD-CLI ``info flat`` (``/configure ...``).

Each line is a path. The words are grouped into the same chunks the brace form would show
(``unit 0``, ``neighbor 192.0.2.2``, ``route 192.0.2.0/24``) using small keyword tables, so
:attr:`ConfigNode.flat_words` is identical for both forms of the same configuration. Grouping
is a heuristic: unknown keywords end the path and the rest of the line becomes one leaf.
"""

from __future__ import annotations

from typing import Literal

from routerscope.model import split_lines
from routerscope.vendors._tree.node import MAX_DEPTH, ConfigNode, finalize_tree
from routerscope.vendors._tree.words import split_tokens

SetDialect = Literal["junos", "mdcli"]

_JUNOS_NOARG = frozenset(
    {
        "system",
        "protocols",
        "bgp",
        "ospf",
        "ospf3",
        "isis",
        "mpls",
        "ldp",
        "rsvp",
        "routing-options",
        "static",
        "policy-options",
        "firewall",
        "forwarding-options",
        "security",
        "snmp",
        "chassis",
    }
)
_JUNOS_ARG1 = frozenset(
    {
        "unit",
        "family",
        "group",
        "neighbor",
        "route",
        "prefix-list",
        "policy-statement",
        "term",
        "filter",
        "rib",
        "area",
        "community",
        "as-path",
        "vrrp-group",
    }
)
# After these a single word names the child (``interfaces ge-0/0/0``).
_JUNOS_NAMED = frozenset({"interfaces", "routing-instances", "vlans", "groups"})

_MDCLI_NOARG = frozenset(
    {
        "configure",
        "bgp",
        "ipv4",
        "ipv6",
        "primary",
        "static-routes",
        "policy-options",
        "ospf",
        "isis",
        "import",
        "export",
    }
)


def looks_like_set(text: str, dialect: SetDialect) -> bool:
    """True if some line starts like a set-style command for ``dialect``."""
    if dialect == "junos":
        starts: tuple[str, ...] = ("set ", "deactivate ")
    else:
        starts = ("/configure ",)
    return any(line.lstrip().startswith(starts) for line in split_lines(text))


def _chunks(tokens: list[str], dialect: SetDialect) -> list[str]:
    out: list[str] = []
    p = 0
    n = len(tokens)
    while p < n:
        word = tokens[p]
        if len(out) >= MAX_DEPTH - 1:
            out.append(" ".join(tokens[p:]))
            p = n
        elif dialect == "junos":
            if out and out[-1] in _JUNOS_NAMED and len(out[-1].split()) == 1:
                out.append(word)
                p += 1
            elif word in _JUNOS_ARG1 and p + 1 < n:
                out.append(f"{word} {tokens[p + 1]}")
                p += 2
            elif (word in _JUNOS_NOARG and p + 1 < n) or (word in _JUNOS_NAMED and p + 1 < n):
                out.append(word)
                p += 1
            else:
                out.append(" ".join(tokens[p:]))
                p = n
        else:
            if (p + 1 < n and tokens[p + 1].startswith('"') and word not in _MDCLI_NOARG) or (
                word == "route" and p + 1 < n
            ):
                out.append(f"{word} {tokens[p + 1]}")
                p += 2
            elif word in _MDCLI_NOARG and p + 1 < n:
                out.append(word)
                p += 1
            else:
                out.append(" ".join(tokens[p:]))
                p = n
    return out


def parse_set(text: str, dialect: SetDialect = "junos") -> ConfigNode:
    """Parse ``set ...`` / ``/configure ...`` lines into a tree of merged path nodes.

    Lines are added in order; path nodes shared by several lines are merged and their line
    range grows to cover all of them (so sibling ranges may interleave when the input is not
    sorted). The final chunk of each ``set`` line is its own leaf node. ``deactivate`` lines
    mark the addressed node ``inactive``; ``protect`` marks it ``protected``. Lines that are
    not set commands (comments, ``delete``, ``activate``, banners) are left unclaimed.
    """
    lines = split_lines(text)
    root = ConfigNode("", 1, max(len(lines), 1))
    index: dict[tuple[int, str], ConfigNode] = {}
    for number, raw in enumerate(lines, start=1):
        tokens = split_tokens(raw.strip())
        if not tokens:
            continue
        mode = "set"
        if dialect == "junos":
            if tokens[0] in ("set", "deactivate", "protect"):
                mode = tokens.pop(0)
            else:
                continue
        elif tokens[0] == "/configure":
            tokens[0] = "configure"
        else:
            continue
        chunks = _chunks(tokens, dialect)
        if not chunks:
            continue
        parent = root
        for position, chunk in enumerate(chunks):
            last = position == len(chunks) - 1
            if last and mode == "set":
                node = ConfigNode(chunk, number, number, own_lines=[number])
                parent.add_child(node)
                break
            key = (id(parent), chunk)
            found = index.get(key)
            if found is None:
                found = ConfigNode(chunk, number, number)
                parent.add_child(found)
                index[key] = found
            else:
                cursor: ConfigNode | None = found
                while cursor is not None and not cursor.is_root:
                    cursor.line_start = min(cursor.line_start, number)
                    cursor.line_end = max(cursor.line_end, number)
                    cursor = cursor.parent
            if last:
                found.own_lines.append(number)
                if mode == "deactivate":
                    found.inactive = True
                elif mode == "protect":
                    found.protected = True
            parent = found
    return finalize_tree(root, len(lines))
