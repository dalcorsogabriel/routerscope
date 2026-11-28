"""Hierarchical (block-aware) diff of two configuration texts of the same vendor.

The texts are parsed with the vendor's tree parser (``routerscope.vendors._tree``) and the trees
are compared statement by statement, so every change is shown under its parent block::

     interface GigabitEthernet0/0/1
    -  description old
    +  description new

How statements are matched
--------------------------
* Siblings are matched by their (whitespace-normalized) text and **order is ignored**: moving
  blocks or statements around is not a change.
* In *ordered sections* (where order changes behaviour) the siblings of a group are matched as a
  sequence, so a reorder shows as removed + added. See :data:`ORDERED_SECTIONS` and
  ``docs/diff.md`` for the per-vendor rules.
* Comments are not statements: the tree parsers drop them, so ``! Last configuration change``,
  ``## Last commit:`` or RouterOS ``# <date> by RouterOS`` never cause a diff. Statement-shaped
  noise (``Building configuration...``, ``ntp clock-period``, Huawei ``!Software Version``) is
  removed by the per-vendor volatile line filters in :data:`VOLATILE_LINES`.
* Junos ``set`` vs brace (and MD-CLI flat vs ``info``) inputs are compared through their flat
  paths when the two sides use different forms.
* Whitespace inside statements is ignored (outside quotes) unless ``show_whitespace`` is set.
  Indentation and trailing spaces are never compared (the indentation defines the structure).

Never raises on arbitrary text.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Literal

from routerscope.model import split_lines
from routerscope.vendors._tree import (
    ConfigNode,
    looks_like_set,
    parse_brace,
    parse_indented,
    parse_routeros,
    parse_set,
)
from routerscope.vendors._tree.setstyle import _chunks

__all__ = [
    "ORDERED_SECTIONS",
    "VOLATILE_LINES",
    "ConfigChange",
    "ConfigDiff",
    "ConfigDiffOptions",
    "DiffNode",
    "OrderedRule",
    "diff_config",
]

Status = Literal["context", "added", "removed"]
Lines = tuple[int, int]
_MDCLI = re.compile(r"^\s*(configure\s*\{|/configure\s)", re.MULTILINE)


# --------------------------------------------------------------------------- rules


@dataclass(frozen=True, slots=True)
class OrderedRule:
    """Marks (some) children of matching blocks as order-sensitive.

    ``parent`` is searched in the ``" > "``-joined texts of the block's path (``""`` for the
    top level). ``group(text)`` returns a group id for a child (children with the same id are
    compared as an ordered sequence) or ``None`` for an unordered child.
    """

    parent: re.Pattern[str]
    group: Callable[[str], str | None]


def _whole(_text: str) -> str:
    return ""


def _unless_numbered(text: str) -> str | None:
    """Entries that carry their own sequence number are unordered; bare ones are ordered."""
    return None if re.match(r"\d+(\s|$)", text) else ""


def _vrp_rule(text: str) -> str | None:
    """``rule 5 permit ...`` is numbered (unordered); ``rule permit ...`` is auto-numbered."""
    return None if re.match(r"rule \d+(\s|$)", text) else ""


def _only_terms(text: str) -> str | None:
    return "term" if text.startswith("term ") else None


_IOS_LIST = re.compile(
    r"^(access-list \S+"
    r"|(?:ip|ipv6) (?:as-path access-list \S+"
    r"|community-list (?:standard |expanded )?\S+"
    r"|extcommunity-list (?:standard |expanded )?\S+"
    r"|prefix-list \S+))\s(?!seq\s)"
)


def _ios_top(text: str) -> str | None:
    match = _IOS_LIST.match(text)
    return match.group(1) if match else None


_IOS_ORDERED = (
    OrderedRule(re.compile(r"^$"), _ios_top),
    OrderedRule(re.compile(r"^(?:ip|ipv6|mac) access-list "), _unless_numbered),
    OrderedRule(re.compile(r"^policy-map "), _whole),
)

ORDERED_SECTIONS: dict[str, tuple[OrderedRule, ...]] = {
    "cisco_ios": _IOS_ORDERED,
    "ipinfusion_ocnos": _IOS_ORDERED,
    "cisco_xr": (
        OrderedRule(re.compile(r"(?:^| > )route-policy "), _whole),
        OrderedRule(re.compile(r"^(?:ipv4|ipv6|ethernet-services) access-list "), _unless_numbered),
        OrderedRule(re.compile(r"^policy-map "), _whole),
    ),
    "huawei_vrp": (OrderedRule(re.compile(r"^acl "), _vrp_rule),),
    "juniper_junos": (
        OrderedRule(re.compile(r"(?:^| > )(?:policy-statement|filter) [^>]*$"), _only_terms),
        OrderedRule(re.compile(r"(?:^| > )then$"), _whole),
    ),
    "mikrotik_ros7": (
        OrderedRule(re.compile(r"^/ip(?:v6)? firewall (?:filter|nat|mangle|raw)$"), _whole),
        OrderedRule(re.compile(r"^/routing filter(?: rule)?$"), _whole),
        OrderedRule(re.compile(r"^/queue simple$"), _whole),
        OrderedRule(re.compile(r"^/interface bridge (?:filter|nat)$"), _whole),
    ),
}
"""Order-sensitive sections per vendor id (vendors without an entry have none)."""

_IOS_VOLATILE = (
    r"Building configuration\.\.\.",
    r"Current configuration\s*:\s*\d+ bytes",
    r"Using \d+ out of \d+ bytes.*",
    r"Last configuration change at .*",
    r"NVRAM config last updated at .*",
    r"ntp clock-period \d+",
)

VOLATILE_LINES: dict[str, tuple[str, ...]] = {
    "cisco_ios": _IOS_VOLATILE,
    "ipinfusion_ocnos": _IOS_VOLATILE,
    "cisco_xr": (
        r"Building configuration\.\.\.",
        r"\w{3} \w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \w+",
        r"!*\s*Last configuration change at .*",
    ),
    "huawei_vrp": (
        r"!\s*Software Version .*",
        r"!\s*Last configuration was (?:updated|saved) at .*",
    ),
    "juniper_junos": (r"##\s*Last (?:commit|changed):.*",),
    "nokia_sros": (r"#\s*(?:Generated|Finished|Last modified)\b.*",),
    "mikrotik_ros7": (
        r"#.* by RouterOS.*",
        r"#\s*(?:software id|model|serial number) = .*",
    ),
}
"""``re.fullmatch`` patterns of unindented lines that change on each save (blanked first)."""


@dataclass(frozen=True, slots=True)
class ConfigDiffOptions:
    """Knobs of :func:`diff_config`."""

    show_whitespace: bool = False
    """Compare inner whitespace of statements literally (default: collapse it)."""
    ignore_volatile_lines: bool = True
    """Blank the vendor's volatile unindented lines (see :data:`VOLATILE_LINES`)."""
    extra_volatile_lines: tuple[str, ...] = ()
    """Extra ``fullmatch`` regexes of unindented lines to ignore."""


# --------------------------------------------------------------------------- result


@dataclass(slots=True)
class DiffNode:
    """One statement of the diff: ``context`` (parent of a change), ``added`` or ``removed``.

    ``old_lines`` / ``new_lines`` are the 1-based inclusive line ranges in each text (``None``
    on the side where the statement does not exist). Added/removed blocks carry their whole
    subtree.
    """

    text: str
    status: Status
    old_lines: Lines | None = None
    new_lines: Lines | None = None
    children: list[DiffNode] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "text": self.text,
            "status": self.status,
            "old_lines": None if self.old_lines is None else list(self.old_lines),
            "new_lines": None if self.new_lines is None else list(self.new_lines),
            "children": [child.to_dict() for child in self.children],
        }

    def count(self) -> int:
        """Number of statements in this subtree (this node included)."""
        total = 0
        stack = [self]
        while stack:
            node = stack.pop()
            total += 1
            stack.extend(node.children)
        return total


@dataclass(frozen=True, slots=True)
class ConfigChange:
    """A flattened change: the top-most added/removed statement and its parent path."""

    op: Literal["added", "removed"]
    path: tuple[str, ...]
    text: str
    old_lines: Lines | None
    new_lines: Lines | None
    statements: int = 1
    """Statements in the subtree (more than 1 for a whole added/removed block)."""

    def to_dict(self) -> dict[str, object]:
        return {
            "op": self.op,
            "path": list(self.path),
            "text": self.text,
            "old_lines": None if self.old_lines is None else list(self.old_lines),
            "new_lines": None if self.new_lines is None else list(self.new_lines),
            "statements": self.statements,
        }


@dataclass(slots=True)
class ConfigDiff:
    """Result of :func:`diff_config`: a tree of changes under their parent blocks."""

    vendor: str | None
    old_format: str
    new_format: str
    nodes: list[DiffNode] = field(default_factory=list)
    ignored_volatile_old: int = 0
    ignored_volatile_new: int = 0

    @property
    def is_empty(self) -> bool:
        return not self.nodes

    def changes(self) -> list[ConfigChange]:
        """Flat list of the top-most added/removed statements in document order."""
        out: list[ConfigChange] = []
        stack: list[tuple[DiffNode, tuple[str, ...]]] = [(n, ()) for n in reversed(self.nodes)]
        while stack:
            node, path = stack.pop()
            if node.status == "context":
                inner = (*path, node.text)
                stack.extend((child, inner) for child in reversed(node.children))
            else:
                out.append(
                    ConfigChange(
                        "added" if node.status == "added" else "removed",
                        path,
                        node.text,
                        node.old_lines,
                        node.new_lines,
                        node.count(),
                    )
                )
        return out

    @property
    def stats(self) -> dict[str, int]:
        """Counts of added and removed statements (blocks count every nested statement)."""
        counts = {"added": 0, "removed": 0}
        for change in self.changes():
            counts[change.op] += change.statements
        return counts

    def render_text(
        self, *, line_numbers: bool = False, old_label: str = "old", new_label: str = "new"
    ) -> str:
        """Unified-style text: ``-``/``+`` lines, parent blocks as context, indented by depth.

        With ``line_numbers`` two columns (old, new line number) precede the marker.
        """
        if not self.nodes:
            return ""
        out = [f"--- {old_label}", f"+++ {new_label}"]
        marks: dict[Status, str] = {"context": " ", "added": "+", "removed": "-"}
        stack: list[tuple[DiffNode, int]] = [(n, 0) for n in reversed(self.nodes)]
        while stack:
            node, depth = stack.pop()
            for index, line in enumerate(node.text.split("\n")):
                prefix = ""
                if line_numbers:
                    old_no = _line_no(node.old_lines, index)
                    new_no = _line_no(node.new_lines, index)
                    prefix = f"{old_no:>6} {new_no:>6} "
                out.append(f"{prefix}{marks[node.status]}{'  ' * depth}{line}")
            stack.extend((child, depth + 1) for child in reversed(node.children))
        return "\n".join(out)

    def to_dict(self) -> dict[str, object]:
        return {
            "vendor": self.vendor,
            "old_format": self.old_format,
            "new_format": self.new_format,
            "ignored_volatile": {
                "old": self.ignored_volatile_old,
                "new": self.ignored_volatile_new,
            },
            "stats": self.stats,
            "changes": [c.to_dict() for c in self.changes()],
            "tree": [n.to_dict() for n in self.nodes],
        }


def _line_no(lines: Lines | None, index: int) -> str:
    if lines is None:
        return ""
    return str(min(lines[0] + index, lines[1]))


# --------------------------------------------------------------------------- parsing


def _parse(text: str, vendor: str | None) -> tuple[ConfigNode, str]:
    """Parse ``text`` with the tree parser of ``vendor``; also returns the format name."""
    if vendor == "cisco_xr":
        return parse_indented(text, "xr"), "indent"
    if vendor == "huawei_vrp":
        return parse_indented(text, "vrp"), "indent"
    if vendor == "mikrotik_ros7":
        return parse_routeros(text), "routeros"
    if vendor == "juniper_junos":
        if looks_like_set(text, "junos"):
            return parse_set(text, "junos"), "set"
        return parse_brace(text), "brace"
    if vendor == "nokia_sros":
        if looks_like_set(text, "mdcli"):
            return parse_set(text, "mdcli"), "set"
        if _MDCLI.search("\n".join(split_lines(text))):
            return parse_brace(text, "mdcli"), "brace"
        return parse_indented(text, "sros"), "indent"
    return parse_indented(text, "ios"), "indent"


def _scrub(text: str, patterns: tuple[re.Pattern[str], ...]) -> tuple[str, int]:
    """Blank the unindented lines matching a volatile pattern; line numbers stay the same.

    Done on the text, before parsing, because some of these lines (Huawei ``!Software Version``)
    would otherwise swallow the indented statements that follow them as children.
    """
    if not patterns:
        return text, 0
    lines = split_lines(text)
    count = 0
    for index, line in enumerate(lines):
        if line and not line[0].isspace() and any(p.fullmatch(line.rstrip()) for p in patterns):
            lines[index] = ""
            count += 1
    return ("\n".join(lines) if count else text), count


def _canonical(root: ConfigNode, vendor: str | None) -> ConfigNode:
    """Rebuild ``root`` from its leaves' flat words, so brace and set forms look the same."""
    out = ConfigNode("", 1, root.line_end)
    index: dict[tuple[int, str], ConfigNode] = {}
    for leaf in root.walk():
        if leaf.children:
            continue
        words = list(leaf.flat_words)
        chunks = _chunks(words, "junos") if vendor == "juniper_junos" else words
        if not chunks:
            continue
        inactive = any(n.inactive for n in _ancestors(leaf))
        protected = any(n.protected for n in _ancestors(leaf))
        parent = out
        for position, chunk in enumerate(chunks):
            if position == len(chunks) - 1:
                parent.add_child(
                    ConfigNode(
                        chunk,
                        leaf.line_start,
                        leaf.line_end,
                        inactive=inactive,
                        protected=protected,
                    )
                )
                break
            found = index.get((id(parent), chunk))
            if found is None:
                found = ConfigNode(chunk, leaf.line_start, leaf.line_end)
                parent.add_child(found)
                index[(id(parent), chunk)] = found
            else:
                cursor: ConfigNode | None = found
                while cursor is not None and not cursor.is_root:
                    cursor.line_start = min(cursor.line_start, leaf.line_start)
                    cursor.line_end = max(cursor.line_end, leaf.line_end)
                    cursor = cursor.parent
            parent = found
    return out


def _ancestors(node: ConfigNode) -> Iterator[ConfigNode]:
    cursor: ConfigNode | None = node
    while cursor is not None and not cursor.is_root:
        yield cursor
        cursor = cursor.parent


def _squeeze(text: str) -> str:
    """Collapse runs of whitespace outside double quotes (line breaks of banners are kept)."""
    if '"' not in text:
        return "\n".join(" ".join(line.split()) for line in text.split("\n"))
    out: list[str] = []
    in_quote = False
    pending_space = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_quote:
            out.append(ch)
            if ch == "\\" and i + 1 < len(text):
                i += 1
                out.append(text[i])
            elif ch == '"':
                in_quote = False
        elif ch == "\n":
            out.append(ch)
            pending_space = False
        elif ch.isspace():
            pending_space = True
        else:
            if pending_space and out and out[-1] != "\n":
                out.append(" ")
            pending_space = False
            out.append(ch)
            in_quote = ch == '"'
        i += 1
    return "".join(out)


def _display(node: ConfigNode) -> str:
    prefix = ("inactive: " if node.inactive else "") + ("protect: " if node.protected else "")
    return prefix + node.text


# --------------------------------------------------------------------------- diffing


@dataclass
class _Ctx:
    rules: tuple[OrderedRule, ...]
    literal: bool

    def key(self, node: ConfigNode) -> str:
        text = node.text if self.literal else _squeeze(node.text)
        return f"{text}\0{int(node.inactive)}{int(node.protected)}"

    def group(self, path: str, text: str) -> str | None:
        for rule in self.rules:
            if rule.parent.search(path) and (group := rule.group(text)) is not None:
                return f"{rule.parent.pattern}\0{group}"
        return None


def _subtree(node: ConfigNode, status: Status) -> DiffNode:
    span = (node.line_start, node.line_end)
    out = DiffNode(
        _display(node),
        status,
        old_lines=span if status == "removed" else None,
        new_lines=span if status == "added" else None,
    )
    out.children = [_subtree(child, status) for child in node.children]
    return out


def _match(old: list[ConfigNode], new: list[ConfigNode], ctx: _Ctx, path: str) -> dict[int, int]:
    """Map index in ``old`` to index in ``new`` for siblings that are the same statement."""
    groups: dict[str | None, tuple[list[int], list[int]]] = defaultdict(lambda: ([], []))
    for side, nodes in enumerate((old, new)):
        for i, node in enumerate(nodes):
            groups[ctx.group(path, node.text)][side].append(i)
    pairs: dict[int, int] = {}
    for group, (old_idx, new_idx) in groups.items():
        if group is None:
            pool: dict[str, deque[int]] = defaultdict(deque)
            for j in new_idx:
                pool[ctx.key(new[j])].append(j)
            for i in old_idx:
                queue = pool.get(ctx.key(old[i]))
                if queue:
                    pairs[i] = queue.popleft()
        else:
            keys_old = [ctx.key(old[i]) for i in old_idx]
            keys_new = [ctx.key(new[j]) for j in new_idx]
            matcher = SequenceMatcher(None, keys_old, keys_new, autojunk=False)
            for block in matcher.get_matching_blocks():
                for offset in range(block.size):
                    pairs[old_idx[block.a + offset]] = new_idx[block.b + offset]
    return pairs


def _diff_children(old: ConfigNode, new: ConfigNode, ctx: _Ctx, path: str) -> list[DiffNode]:
    old_kids = old.children
    new_kids = new.children
    if not old_kids and not new_kids:
        return []
    pairs = _match(old_kids, new_kids, ctx, path)
    partner = {j: i for i, j in pairs.items()}
    # Removed statements are emitted right after the previous matched statement.
    removed_after: dict[int, list[int]] = defaultdict(list)
    last = -1
    for idx in range(len(old_kids)):
        if idx in pairs:
            last = idx
        else:
            removed_after[last].append(idx)
    out = [_subtree(old_kids[i], "removed") for i in removed_after.get(-1, ())]
    for j, node in enumerate(new_kids):
        i = partner.get(j)
        if i is None:
            out.append(_subtree(node, "added"))
            continue
        inner = path + " > " + node.text if path else node.text
        kids = _diff_children(old_kids[i], node, ctx, inner)
        if kids:
            out.append(
                DiffNode(
                    _display(node),
                    "context",
                    (old_kids[i].line_start, old_kids[i].line_end),
                    (node.line_start, node.line_end),
                    kids,
                )
            )
        out.extend(_subtree(old_kids[r], "removed") for r in removed_after.get(i, ()))
    return out


def diff_config(
    old_text: str,
    new_text: str,
    vendor: str | None = None,
    *,
    options: ConfigDiffOptions | None = None,
) -> ConfigDiff:
    """Hierarchical diff of two configuration texts of ``vendor`` (a plugin id).

    An unknown or ``None`` vendor is parsed as indentation-structured IOS-like text with no
    ordered sections and no volatile-line filter.
    """
    opts = options if options is not None else ConfigDiffOptions()
    patterns: list[str] = list(opts.extra_volatile_lines)
    if opts.ignore_volatile_lines and vendor is not None:
        patterns.extend(VOLATILE_LINES.get(vendor, ()))
    compiled = tuple(re.compile(p) for p in patterns)
    old_text, ignored_old = _scrub(old_text, compiled)
    new_text, ignored_new = _scrub(new_text, compiled)
    old_root, old_fmt = _parse(old_text, vendor)
    new_root, new_fmt = _parse(new_text, vendor)
    if {old_fmt, new_fmt} == {"set", "brace"}:
        old_root = _canonical(old_root, vendor)
        new_root = _canonical(new_root, vendor)
        old_fmt, new_fmt = f"{old_fmt}->flat", f"{new_fmt}->flat"
    ctx = _Ctx(ORDERED_SECTIONS.get(vendor or "", ()), opts.show_whitespace)
    nodes = _diff_children(old_root, new_root, ctx, "")
    return ConfigDiff(vendor, old_fmt, new_fmt, nodes, ignored_old, ignored_new)
