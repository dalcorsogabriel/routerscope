"""Deterministic pseudonyms (R1, desc-3, user2...) assigned in order of first appearance."""

from __future__ import annotations

import re


class Namer:
    """Maps values to ``template.format(n=...)`` names, reusing names for equal values.

    Values that already look like a produced name (``done``) are kept and their number is
    reserved, which is what makes sanitizing a second time change nothing.
    """

    def __init__(self, template: str, *, fold: bool = False) -> None:
        self.template = template
        self.fold = fold
        self.done = re.compile(re.escape(template).replace(r"\{n\}", r"(\d+)") + "$")
        self.map: dict[str, str] = {}
        self._taken: set[int] = set()
        self._counter = 0

    def _key(self, value: str) -> str:
        return value.lower() if self.fold else value

    def is_done(self, value: str) -> bool:
        return self.done.match(value) is not None

    def reserve(self, value: str) -> None:
        m = self.done.match(value)
        if m:
            self._taken.add(int(m.group(1)))

    def get(self, value: str) -> str:
        """Return the pseudonym for ``value`` (already-produced names map to themselves)."""
        if self.is_done(value):
            self.reserve(value)
            return value
        key = self._key(value)
        name = self.map.get(key)
        if name is None:
            n = self._counter + 1
            while n in self._taken:
                n += 1
            self._counter = n
            self._taken.add(n)
            name = self.template.format(n=n)
            self.map[key] = name
        return name
