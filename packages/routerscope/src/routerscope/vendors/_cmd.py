"""Command recognition and dispatch shared by every vendor's ``parse_command``.

A vendor declares a table of :class:`Spec` objects. Each spec has one or more *patterns*, a
tiny word language that accepts the abbreviations engineers type:

* ``show:2`` is the word ``show`` abbreviated to at least 2 letters (``sh``, ``sho``, ``show``);
  a bare word (``vrf``) must be typed in full;
* ``a:2/b:3`` accepts either word;
* ``<vrf>`` captures one token (double quotes are removed) under that name;
* ``[ ... ]`` is an optional group: it is entered when its first word matches the next token
  and must then match completely (no backtracking), otherwise it is skipped.

Anything left over after a pattern (an extra argument such as an address filter) means the
command is not recognised: a filtered view must never be mistaken for the full table. The same
goes for output pipes, except the ones a vendor lists as harmless (``| no-more``).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from functools import cache
from typing import Any

from routerscope.model import ParsedObjectUnion, ParseResult, Snapshot, SourceRef, split_lines
from routerscope.vendors._extract import make

_TOKEN = re.compile(r'"([^"]*)"|(\S+)')


@dataclass(frozen=True)
class _Word:
    alternatives: tuple[tuple[str, int], ...]

    def matches(self, token: str) -> bool:
        low = token.lower()
        return any(
            low == word or (len(low) >= minimum and word.startswith(low))
            for word, minimum in self.alternatives
        )


@dataclass(frozen=True)
class _Capture:
    name: str


@dataclass(frozen=True)
class _Group:
    items: tuple[_Item, ...]


_Item = _Word | _Capture | _Group


def _compile_word(text: str) -> _Word:
    alternatives = []
    for alt in text.split("/"):
        word, _, minimum = alt.partition(":")
        word = word.lower()
        alternatives.append((word, int(minimum) if minimum else len(word)))
    return _Word(tuple(alternatives))


@cache
def compile_pattern(pattern: str) -> tuple[_Item, ...]:
    """Compile a pattern string (see the module docstring)."""
    stack: list[list[_Item]] = [[]]
    for token in re.findall(r"\[|\]|[^\s\[\]]+", pattern):
        if token == "[":
            stack.append([])
        elif token == "]":
            group = _Group(tuple(stack.pop()))
            stack[-1].append(group)
        elif token.startswith("<") and token.endswith(">"):
            stack[-1].append(_Capture(token[1:-1]))
        else:
            stack[-1].append(_compile_word(token))
    if len(stack) != 1:  # pragma: no cover - programming error in a table
        raise ValueError(f"unbalanced brackets in {pattern!r}")
    return tuple(stack[0])


def _match_items(
    items: Sequence[_Item], tokens: Sequence[str], pos: int, caps: dict[str, str]
) -> int | None:
    for item in items:
        if isinstance(item, _Group):
            first = item.items[0]
            if pos >= len(tokens) or not (isinstance(first, _Word) and first.matches(tokens[pos])):
                continue
            end = _match_items(item.items, tokens, pos, caps)
            if end is None:
                return None
            pos = end
        elif pos >= len(tokens):
            return None
        elif isinstance(item, _Capture):
            caps[item.name] = tokens[pos]
            pos += 1
        elif item.matches(tokens[pos]):
            pos += 1
        else:
            return None
    return pos


def match_pattern(pattern: str, tokens: Sequence[str]) -> dict[str, str] | None:
    """Match ``tokens`` against ``pattern``; the captures, or ``None`` if it does not match."""
    caps: dict[str, str] = {}
    end = _match_items(compile_pattern(pattern), tokens, 0, caps)
    return caps if end == len(tokens) else None


def split_command(command: str, harmless_pipes: frozenset[str]) -> list[str] | None:
    """Tokens of ``command`` without harmless pipes; ``None`` if a filtering pipe is present."""
    head, *pipes = command.split("|")
    if any(pipe.strip().lower() not in harmless_pipes for pipe in pipes):
        return None
    return [m.group(1) if m.group(1) is not None else m.group(2) for m in _TOKEN.finditer(head)]


class Ctx:
    """What a handler gets: the output lines (as :func:`split_lines` numbers them) and captures."""

    def __init__(self, vendor: str, snapshot_id: str, lines: list[str], caps: dict[str, str]):
        self.vendor = vendor
        self.snapshot_id = snapshot_id
        self.lines = lines
        self.caps = caps

    @property
    def vrf(self) -> str | None:
        return self.caps.get("vrf")

    def ref(self, start: int, end: int | None = None) -> SourceRef:
        """A :class:`SourceRef` for 1-based, inclusive lines (clamped into the output)."""
        total = max(len(self.lines), 1)
        first = min(max(start, 1), total)
        last = min(max(end if end is not None else start, first), total)
        return SourceRef(snapshot_id=self.snapshot_id, line_start=first, line_end=last)

    def make[T](self, cls: type[T], start: int, end: int | None = None, **kwargs: Any) -> T | None:
        """Build ``cls`` with ``ref`` (and ``vendor`` if the class has one); ``None`` if invalid."""
        fields = getattr(cls, "model_fields", {})
        if "vendor" in fields:
            kwargs.setdefault("vendor", self.vendor)
        return make(cls, ref=self.ref(start, end), **kwargs)


Handler = Callable[[Ctx], Sequence[ParsedObjectUnion | None] | None]


@dataclass(frozen=True)
class Spec:
    """One parseable command: its patterns, the handler and the canonical collector command."""

    patterns: tuple[str, ...]
    handler: Handler
    canonical: tuple[str, ...] = ()


def spec(canonical: str | Sequence[str], handler: Handler, *patterns: str) -> Spec:
    """Build a :class:`Spec`; ``canonical`` is the read-only command(s) a collector may send."""
    names = (canonical,) if isinstance(canonical, str) else tuple(canonical)
    return Spec(patterns=patterns, handler=handler, canonical=names)


def dispatch(
    specs: Sequence[Spec],
    command: str,
    output: str,
    snapshot: Snapshot,
    vendor: str,
    *,
    harmless_pipes: frozenset[str] = frozenset(),
    normalize: Callable[[str], list[str] | None] | None = None,
) -> ParseResult | None:
    """Find the spec matching ``command`` and run its handler on ``output``."""
    command = command.strip()
    if not command or not output.strip():
        return None
    tokens = normalize(command) if normalize else split_command(command, harmless_pipes)
    if not tokens:
        return None
    for sp in specs:
        for pattern in sp.patterns:
            caps = match_pattern(pattern, tokens)
            if caps is None:
                continue
            ctx = Ctx(vendor, snapshot.id, split_lines(output), caps)
            found = sp.handler(ctx)
            if found is None:
                return None
            return ParseResult(
                snapshot_id=snapshot.id,
                command=command,
                vendor=vendor,
                objects=tuple(o for o in found if o is not None),
            )
    return None


def readonly(specs: Sequence[Spec]) -> tuple[str, ...]:
    """The canonical collector commands of a spec table, without duplicates."""
    return tuple(dict.fromkeys(name for s in specs for name in s.canonical))
