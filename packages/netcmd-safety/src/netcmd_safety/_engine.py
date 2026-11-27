"""Table-driven classifier for hierarchical CLIs (Cisco-like, VRP, Junos, SR OS).

Each vendor is described by keyword trees. A typed word matches a keyword when it is
the keyword itself or an unambiguous prefix of it (CLIs accept abbreviations such as
``sh ip int br``). Anything that does not match fails closed as ``UNKNOWN``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from itertools import pairwise

from ._model import Mode, Verdict, worst
from ._tokens import split_unquoted, tokenize

Handler = Callable[[Sequence[str]], Verdict | None]


@dataclass(frozen=True, slots=True)
class Node:
    """One keyword in a command tree.

    ``verdict`` applies when the command ends at this keyword, or when the following
    words are free arguments (``children`` is None). When ``children`` is given and the
    next word matches none of them, ``default`` applies (or ``verdict`` if unset).
    """

    verdict: Verdict = Verdict.UNKNOWN
    children: Mapping[str, Node] | None = None
    default: Verdict | None = None
    min_abbrev: int = 1
    enters: Mode | None = None
    recurse: bool = False
    """Classify the remaining words as an exec-mode command (``do``, ``run``, ``admin``)."""
    handler: Handler | None = None
    """Inspect the remaining words; a non-None result overrides the verdict."""


def leaf(verdict: Verdict, *, min_abbrev: int = 1, enters: Mode | None = None) -> Node:
    return Node(verdict=verdict, min_abbrev=min_abbrev, enters=enters)


READ = leaf(Verdict.READ)
SESSION = leaf(Verdict.SESSION)
CONFIG = leaf(Verdict.CONFIG)
DESTRUCTIVE = leaf(Verdict.DESTRUCTIVE)


@dataclass(frozen=True, slots=True)
class VendorSpec:
    exec_table: Mapping[str, Node]
    config_table: Mapping[str, Node]
    pipes: Mapping[str, Node]
    destructive_words: frozenset[str] = frozenset()
    """Words that make a config-mode statement destructive wherever they appear."""
    destructive_pairs: frozenset[tuple[str, str]] = frozenset()
    """Consecutive word pairs that make a config-mode statement destructive."""
    redirect: bool = True
    """Whether a standalone ``>`` / ``>>`` writes the output to a file."""
    strip_root_slash: bool = False
    """Whether a leading ``/`` means "run from the root context" (SR OS)."""


@dataclass(frozen=True, slots=True)
class Result:
    verdict: Verdict
    reason: str
    next_mode: Mode | None


def match_keyword(word: str, table: Mapping[str, Node]) -> tuple[str, Node] | None:
    """Resolve ``word`` against ``table`` with unambiguous-prefix abbreviation."""
    if word in table:
        return word, table[word]
    candidates = [k for k in table if k.startswith(word)]
    if len(candidates) != 1:
        return None
    key = candidates[0]
    node = table[key]
    if len(word) < node.min_abbrev:
        return None
    return key, node


def _walk(
    words: Sequence[str], table: Mapping[str, Node], spec: VendorSpec
) -> tuple[Verdict, str, Mode | None] | None:
    """Walk a keyword tree. Returns None if the first word matches nothing."""
    first = match_keyword(words[0], table)
    if first is None:
        return None
    path = [first[0]]
    node = first[1]
    rest = list(words[1:])
    while True:
        if node.recurse:
            if not rest:
                return node.verdict, " ".join(path), node.enters
            inner = _walk(rest, spec.exec_table, spec)
            if inner is None:
                return Verdict.UNKNOWN, f"{' '.join(path)} <unknown>", None
            return inner[0], f"{' '.join(path)} {inner[1]}", inner[2]
        if node.handler is not None:
            override = node.handler(rest)
            if override is not None:
                return override, " ".join(path), node.enters
        if not rest or node.children is None:
            return node.verdict, " ".join(path), node.enters
        child = match_keyword(rest[0], node.children)
        if child is None:
            verdict = node.default if node.default is not None else node.verdict
            return verdict, " ".join(path), node.enters
        path.append(child[0])
        node = child[1]
        rest = rest[1:]


def _classify_main(words: list[str], mode: Mode | None, spec: VendorSpec) -> Result:
    if spec.strip_root_slash and words and words[0].startswith("/"):
        words = [words[0][1:], *words[1:]] if words[0] != "/" else words[1:]
        if not words or not words[0]:
            return Result(Verdict.SESSION, "root context", mode)
        mode_for_table: Mode | None = Mode.EXEC
    else:
        mode_for_table = mode

    if mode_for_table is Mode.CONFIG:
        walked = _walk(words, spec.config_table, spec)
        if walked is None:
            verdict, reason, enters = Verdict.CONFIG, "configuration statement", None
        else:
            verdict, reason, enters = walked
        if verdict is Verdict.CONFIG and _has_destructive_words(words, spec):
            return Result(Verdict.DESTRUCTIVE, f"{reason}: disables or removes", mode)
        return Result(verdict, reason, enters if enters is not None else mode)

    walked = _walk(words, spec.exec_table, spec)
    if walked is not None:
        verdict, reason, enters = walked
        if mode is None and verdict is Verdict.UNKNOWN and _has_destructive_words(words, spec):
            return Result(Verdict.DESTRUCTIVE, f"{reason}: disables or removes", mode)
        return Result(verdict, reason, enters if enters is not None else mode)

    if mode is None:
        # The mode is unknown: the line may be a configuration statement. Only escalate
        # when it is clearly destructive; otherwise fail closed as UNKNOWN.
        # Exact keyword only: an abbreviation is not clear evidence.
        cfg = _walk(words, spec.config_table, spec) if words[0] in spec.config_table else None
        if cfg is not None and cfg[0] is Verdict.DESTRUCTIVE:
            return Result(Verdict.DESTRUCTIVE, cfg[1], mode)
        if _has_destructive_words(words, spec):
            return Result(Verdict.DESTRUCTIVE, "disables or removes", mode)
    return Result(Verdict.UNKNOWN, f"unrecognized command '{words[0]}'", mode)


def _has_destructive_words(words: Sequence[str], spec: VendorSpec) -> bool:
    if any(w in spec.destructive_words for w in words):
        return True
    return any((a, b) in spec.destructive_pairs for a, b in pairwise(words))


def classify_tree(command: str, mode: Mode | None, spec: VendorSpec) -> Result:
    """Classify one command line with a vendor's keyword trees."""
    segments = split_unquoted(command, "|")
    main_tokens = tokenize(segments[0])
    if not main_tokens:
        return Result(Verdict.SESSION, "empty line", mode)

    verdicts: list[Verdict] = []
    reasons: list[str] = []

    if spec.redirect and any(
        not t.quoted and t.text in (">", ">>") for s in segments for t in tokenize(s)
    ):
        return Result(Verdict.DESTRUCTIVE, "output redirected to a file", mode)

    words = [t.text if t.quoted else t.text.lower() for t in main_tokens]
    main = _classify_main(words, mode, spec)
    verdicts.append(main.verdict)
    reasons.append(main.reason)

    for seg in segments[1:]:
        ptoks = tokenize(seg)
        if not ptoks:
            verdicts.append(Verdict.UNKNOWN)
            reasons.append("empty pipe")
            continue
        pwords = [t.text if t.quoted else t.text.lower() for t in ptoks]
        walked = _walk(pwords, spec.pipes, spec)
        if walked is None:
            verdicts.append(Verdict.UNKNOWN)
            reasons.append(f"unknown pipe '| {pwords[0]}'")
        else:
            verdicts.append(walked[0])
            reasons.append(f"| {walked[1]}")

    verdict = worst(verdicts)
    reason = next(r for v, r in zip(verdicts, reasons, strict=True) if v is verdict)
    return Result(verdict, reason, main.next_mode)
