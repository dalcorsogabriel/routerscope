"""The configuration tree: :class:`ConfigNode`."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from routerscope.vendors._tree.words import split_words


@dataclass(eq=False, repr=False)
class ConfigNode:
    """One statement of a configuration and the statements nested under it.

    Line numbers are 1-based indexes into :func:`routerscope.model.split_lines` of the parsed
    text, so they can go straight into a :class:`~routerscope.model.SourceRef`.

    * ``text``: the statement without indentation, comment markers, terminators or the Junos
      ``inactive:``/``protect:`` prefixes. Multi-line statements (banners, RouterOS line
      continuations) are joined: banners with ``"\n"``, continuations with a single space.
    * ``line_start`` / ``line_end``: the whole block, header through the last nested line (and
      the closing ``}`` / ``exit`` / ``end-policy`` when the syntax has one).
    * ``own_lines``: the physical lines that belong to this node itself (header lines and
      closer). For the root node these are the lines no node claims: blanks and comments.
    * ``depth``: 0 for the root, 1 for top-level statements, and so on.
    """

    text: str
    line_start: int
    line_end: int
    depth: int = 0
    parent: ConfigNode | None = field(default=None, repr=False)
    children: list[ConfigNode] = field(default_factory=list, repr=False)
    own_lines: list[int] = field(default_factory=list, repr=False)
    inactive: bool = False
    protected: bool = False
    _words: list[str] | None = field(default=None, repr=False, compare=False)
    _flat: tuple[str, ...] | None = field(default=None, repr=False, compare=False)

    @property
    def is_root(self) -> bool:
        return self.parent is None

    @property
    def words(self) -> list[str]:
        """The statement split into words, quotes removed (cached)."""
        if self._words is None:
            self._words = split_words(self.text)
        return self._words

    def path(self) -> tuple[str, ...]:
        """Texts of the ancestors from the top-level statement down to this node (inclusive)."""
        parts: list[str] = []
        node: ConfigNode | None = self
        while node is not None and node.parent is not None:
            parts.append(node.text)
            node = node.parent
        parts.reverse()
        return tuple(parts)

    @property
    def flat_words(self) -> tuple[str, ...]:
        """Words of :meth:`path` concatenated: identical for brace and ``set`` forms of Junos."""
        if self._flat is None:
            if self.parent is None:
                self._flat = ()
            else:
                self._flat = self.parent.flat_words + tuple(self.words)
        return self._flat

    def add_child(self, child: ConfigNode) -> ConfigNode:
        """Attach ``child`` (setting parent and depth) and widen the line range of ancestors."""
        child.parent = self
        child.depth = self.depth + 1
        self.children.append(child)
        node: ConfigNode | None = self
        while node is not None and not node.is_root:
            node.line_end = max(node.line_end, child.line_end)
            node.line_start = min(node.line_start, child.line_start)
            node = node.parent
        return child

    def walk(self, *, include_self: bool = False) -> Iterator[ConfigNode]:
        """Yield descendants in document (pre-order) order."""
        if include_self:
            yield self
        for child in self.children:
            yield from child.walk(include_self=True)

    def find(self, pattern: str | re.Pattern[str], *, recursive: bool = True) -> list[ConfigNode]:
        """Descendants whose text matches ``pattern`` (``re.match``: anchored at the start).

        ``recursive=False`` only looks at direct children.
        """
        rx = re.compile(pattern) if isinstance(pattern, str) else pattern
        source = self.walk() if recursive else iter(self.children)
        return [node for node in source if rx.match(node.text)]

    def child(self, prefix: str) -> ConfigNode | None:
        """The first direct child whose text equals ``prefix`` or starts with ``prefix + " "``."""
        for node in self.children:
            if node.text == prefix or node.text.startswith(prefix + " "):
                return node
        return None

    def __repr__(self) -> str:
        return (
            f"ConfigNode({self.text!r}, lines={self.line_start}-{self.line_end}, "
            f"children={len(self.children)})"
        )
