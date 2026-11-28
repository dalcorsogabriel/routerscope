"""Helpers for extractors that match on :attr:`ConfigNode.flat_words` (Junos, SR OS MD-CLI)."""

from __future__ import annotations

from routerscope.vendors._tree import ConfigNode


def anchor_at(node: ConfigNode, k: int) -> ConfigNode:
    """The topmost ancestor-or-self whose path already holds at least ``k`` words.

    In the brace form this is the block (``neighbor 192.0.2.2 { ... }``); in the ``set`` form
    it is the merged path node, so both forms give a block-like source range.
    """
    current = node
    while (
        current.parent is not None
        and not current.parent.is_root
        and len(current.parent.flat_words) >= k
    ):
        current = current.parent
    return current


def values(words: tuple[str, ...]) -> list[str]:
    """Values of ``x`` or ``[ x y z ]`` (the words right after a keyword)."""
    if not words:
        return []
    if words[0] == "[":
        out = []
        for word in words[1:]:
            if word == "]":
                break
            out.append(word)
        return out
    return [words[0]]


def is_inactive(node: ConfigNode) -> bool:
    """True if the node or any ancestor is deactivated."""
    current: ConfigNode | None = node
    while current is not None:
        if current.inactive:
            return True
        current = current.parent
    return False
