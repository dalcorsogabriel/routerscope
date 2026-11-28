"""Indentation-based parser: Cisco IOS/XE/XR, OcNOS, Huawei VRP and Nokia SR OS classic."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from routerscope.model import split_lines
from routerscope.vendors._tree.node import ConfigNode

Dialect = Literal["ios", "xr", "vrp", "sros"]

_BANNER = re.compile(r"^banner\s+\S+\s+(\^C|\S)", re.IGNORECASE)
_CERT = re.compile(r"^certificate\b", re.IGNORECASE)
_HEX = re.compile(r"^[0-9A-Fa-f\s]+$")

# XR terminators and the opener each one closes.
_XR_CLOSERS: dict[str, re.Pattern[str]] = {
    "end-policy": re.compile(r"route-policy\b"),
    "end-set": re.compile(r"\S+-set\b"),
    "end-group": re.compile(r"\S*group\b"),
    "end-template": re.compile(r"\S*template\b"),
}


@dataclass(frozen=True)
class _Rules:
    comment_prefix: str
    leaf_prefixes: tuple[str, ...] = ()
    exit_closes: bool = False
    banners: bool = True
    xr_closers: bool = False


_RULES: dict[str, _Rules] = {
    "ios": _Rules("!"),
    "xr": _Rules("!", xr_closers=True),
    "vrp": _Rules("#", banners=False),
    "sros": _Rules("#", leaf_prefixes=("echo ",), exit_closes=True, banners=False),
}


def _indent_of(raw: str) -> int:
    width = 0
    for ch in raw:
        if ch == " ":
            width += 1
        elif ch == "\t":
            width += 8 - width % 8
        else:
            break
    return width


def _finalize(root: ConfigNode, line_count: int) -> ConfigNode:
    claimed: set[int] = set()
    for node in root.walk():
        claimed.update(node.own_lines)
    root.own_lines = [n for n in range(1, line_count + 1) if n not in claimed]
    return root


def _extend(node: ConfigNode, line: int) -> None:
    cursor: ConfigNode | None = node
    while cursor is not None and not cursor.is_root:
        cursor.line_end = max(cursor.line_end, line)
        cursor = cursor.parent


def parse_indented(text: str, dialect: Dialect = "ios") -> ConfigNode:
    """Parse indentation-structured CLI configuration into a tree.

    A statement indented deeper than the previous one is its child. Blank lines and comment
    lines (``!`` for IOS/XR/OcNOS, ``#`` for VRP and SR OS) are not nodes. Multi-line banners
    and ``certificate ... quit`` blocks become one node. XR ``end-policy``/``end-set``/... and
    SR OS ``exit`` lines are recorded as the closer of the block they end (part of its range).
    Never raises; unknown syntax is just more nodes.
    """
    rules = _RULES[dialect]
    lines = split_lines(text)
    root = ConfigNode("", 1, max(len(lines), 1))
    stack: list[tuple[int, ConfigNode]] = [(-1, root)]
    i = 0
    total = len(lines)
    while i < total:
        raw = lines[i]
        stripped = raw.strip()
        number = i + 1
        i += 1
        if not stripped or stripped.startswith(rules.comment_prefix):
            continue
        indent = _indent_of(raw)

        if rules.xr_closers and stripped in _XR_CLOSERS:
            opener = _XR_CLOSERS[stripped]
            for pos in range(len(stack) - 1, 0, -1):
                if opener.match(stack[pos][1].text):
                    target = stack[pos][1]
                    target.own_lines.append(number)
                    _extend(target, number)
                    del stack[pos:]
                    break
            else:
                _attach(stack, indent, ConfigNode(stripped, number, number, own_lines=[number]))
            continue

        if rules.exit_closes and stripped == "exit":
            while len(stack) > 1 and stack[-1][0] > indent:
                stack.pop()
            if len(stack) > 1 and stack[-1][0] == indent:
                target = stack.pop()[1]
                target.own_lines.append(number)
                _extend(target, number)
                continue

        if rules.exit_closes and stripped == "exit all":
            del stack[1:]
            root.add_child(ConfigNode(stripped, number, number, own_lines=[number]))
            continue

        node_text = stripped
        own = [number]
        end = number
        if rules.banners and (m := _BANNER.match(stripped)):
            delim = m.group(1)
            if delim not in stripped[m.end() :]:
                j = i
                while j < total and delim not in lines[j]:
                    j += 1
                if j < total:
                    node_text = "\n".join(line.strip() for line in lines[i - 1 : j + 1])
                    own = list(range(number, j + 2))
                    end = j + 1
                    i = j + 1
        elif rules.banners and _CERT.match(stripped):
            j = i
            while j < total and lines[j].strip() and _HEX.match(lines[j]):
                j += 1
            if j < total and lines[j].strip() == "quit":
                node_text = "\n".join(line.strip() for line in lines[i - 1 : j + 1])
                own = list(range(number, j + 2))
                end = j + 1
                i = j + 1

        node = ConfigNode(node_text, number, end, own_lines=own)
        leaf = any(stripped.startswith(prefix) for prefix in rules.leaf_prefixes)
        _attach(stack, indent, node, push=not leaf)
    return _finalize(root, total)


def _attach(
    stack: list[tuple[int, ConfigNode]], indent: int, node: ConfigNode, *, push: bool = True
) -> None:
    while len(stack) > 1 and stack[-1][0] >= indent:
        stack.pop()
    stack[-1][1].add_child(node)
    if push:
        stack.append((indent, node))
