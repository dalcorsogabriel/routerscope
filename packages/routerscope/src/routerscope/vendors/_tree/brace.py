"""Brace-based parser: Junos hierarchical configuration and SR OS MD-CLI ``info`` output."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from routerscope.model import split_lines
from routerscope.vendors._tree.indent import _finalize
from routerscope.vendors._tree.node import ConfigNode

BraceDialect = Literal["junos", "mdcli"]

_PREFIXES = {"inactive:", "protect:"}
_STOP = set('{};"')


@dataclass
class _Tok:
    start: int
    end: int
    line: int
    end_line: int
    raw: str


def parse_brace(text: str, dialect: BraceDialect = "junos") -> ConfigNode:
    """Parse brace-structured configuration into a tree.

    Junos statements end with ``;``; MD-CLI leaf statements end at the end of the line. Both
    support ``/* ... */`` comments, ``#`` and ``##`` comment lines, ``[ a b c ]`` lists (kept
    as ``[``, values, ``]`` words inside the statement) and quoted strings that may contain
    braces or semicolons. ``inactive:`` / ``protect:`` prefixes are stripped and recorded in
    :attr:`ConfigNode.inactive` / :attr:`ConfigNode.protected`. Never raises.
    """
    lines = split_lines(text)
    src = "\n".join(lines)
    n = len(src)
    root = ConfigNode("", 1, max(len(lines), 1))
    stack: list[ConfigNode] = [root]
    cur: list[_Tok] = []
    bracket = 0
    line = 1
    last_line = 1
    i = 0

    def statement() -> tuple[str, int, int, bool, bool]:
        toks = list(cur)
        inactive = protected = False
        while toks and toks[0].raw in _PREFIXES:
            inactive = inactive or toks[0].raw == "inactive:"
            protected = protected or toks[0].raw == "protect:"
            toks.pop(0)
        if not toks:
            return "", cur[0].line, cur[-1].end_line, inactive, protected
        segment = src[toks[0].start : toks[-1].end]
        body = " ".join(part.strip() for part in segment.split("\n"))
        return body, cur[0].line, cur[-1].end_line, inactive, protected

    def emit(*, is_block: bool, end_line: int) -> None:
        nonlocal last_line
        body, first, tok_end, inactive, protected = statement()
        end = max(end_line, tok_end)
        node = ConfigNode(
            body,
            first,
            end,
            own_lines=list(range(first, end + 1)),
            inactive=inactive,
            protected=protected,
        )
        stack[-1].add_child(node)
        if is_block:
            stack.append(node)
        last_line = max(last_line, end)
        cur.clear()

    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            if dialect == "mdcli" and cur and bracket == 0:
                emit(is_block=False, end_line=cur[-1].end_line)
            continue
        if c in " \t\r\f\v":
            i += 1
            continue
        if c == "/" and src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += src.count("\n", i, j)
            i = j
            continue
        if c == "#" and not cur:
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "{":
            emit(is_block=True, end_line=line)
            bracket = 0
            i += 1
            continue
        if c == "}":
            if cur:
                emit(is_block=False, end_line=cur[-1].end_line)
            bracket = 0
            if len(stack) > 1:
                node = stack.pop()
                node.line_end = max(node.line_end, line)
                if line not in node.own_lines:
                    node.own_lines.append(line)
                last_line = max(last_line, line)
            i += 1
            continue
        if c == ";":
            if cur:
                emit(is_block=False, end_line=line)
            bracket = 0
            i += 1
            continue
        start = i
        start_line = line
        if c == '"':
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\" and i + 1 < n:
                    i += 1
                if src[i] == "\n":
                    line += 1
                i += 1
            i = min(i + 1, n)
        elif c == "[" and (i + 1 >= n or src[i + 1] in ' \t\n"'):
            bracket += 1
            i += 1
        elif c == "]" and bracket > 0:
            bracket -= 1
            i += 1
        else:
            i += 1
            while i < n and not src[i].isspace() and src[i] not in _STOP:
                if bracket > 0 and src[i] == "]":
                    break
                i += 1
        cur.append(_Tok(start, i, start_line, line, src[start:i]))
    if cur:
        emit(is_block=False, end_line=cur[-1].end_line)
    for node in stack[1:]:
        node.line_end = max(node.line_end, last_line)
    return _finalize(root, len(lines))
