"""MikroTik RouterOS 7.

RouterOS commands are a menu path followed by a verb (``/ip/address/print``,
``/ip address print``, or just ``print`` inside a menu). Menu names and verbs can be
abbreviated, so every bare word is checked against the verb list and the most
dangerous match wins. Scripting syntax fails closed.
"""

from __future__ import annotations

from .._engine import Result
from .._model import Mode, Verdict, worst
from .._tokens import has_unquoted, split_unquoted, tokenize

_VERBS: dict[str, Verdict] = {
    # read
    "print": Verdict.READ,
    "export": Verdict.READ,
    "monitor": Verdict.READ,
    "monitor-traffic": Verdict.READ,
    "find": Verdict.READ,
    "get": Verdict.READ,
    # session
    "quit": Verdict.SESSION,
    # config
    "add": Verdict.CONFIG,
    "set": Verdict.CONFIG,
    "edit": Verdict.CONFIG,
    "enable": Verdict.CONFIG,
    "comment": Verdict.CONFIG,
    "move": Verdict.CONFIG,
    "unset": Verdict.CONFIG,
    # destructive
    "remove": Verdict.DESTRUCTIVE,
    "disable": Verdict.DESTRUCTIVE,
    "reset": Verdict.DESTRUCTIVE,
    "reset-counters": Verdict.DESTRUCTIVE,
    "reset-counters-all": Verdict.DESTRUCTIVE,
    "reset-configuration": Verdict.DESTRUCTIVE,
    "reboot": Verdict.DESTRUCTIVE,
    "shutdown": Verdict.DESTRUCTIVE,
    "import": Verdict.DESTRUCTIVE,
    "run": Verdict.DESTRUCTIVE,
    "install": Verdict.DESTRUCTIVE,
    "upgrade": Verdict.DESTRUCTIVE,
    "downgrade": Verdict.DESTRUCTIVE,
    "uninstall": Verdict.DESTRUCTIVE,
    "apply": Verdict.DESTRUCTIVE,
    "flush": Verdict.DESTRUCTIVE,
}

_READ_MIN_ABBREV = 2


def _verb(word: str) -> tuple[str, Verdict] | None:
    """Resolve a word to a verb; an ambiguous abbreviation takes the worst candidate."""
    if word in _VERBS:
        return word, _VERBS[word]
    candidates = [v for v in _VERBS if v.startswith(word)]
    if not candidates:
        return None
    verdict = worst([_VERBS[c] for c in candidates])
    if verdict is Verdict.READ and len(word) < _READ_MIN_ABBREV:
        return None
    return candidates[0] if len(candidates) == 1 else word + "*", verdict


def _classify_one(command: str) -> tuple[Verdict, str]:
    text = command.strip()
    if not text:
        return Verdict.SESSION, "empty line"
    if text in ("..", "/"):
        return Verdict.SESSION, "menu navigation"
    if has_unquoted(text, "[]{}$") or text.startswith(":"):
        return Verdict.UNKNOWN, "scripting syntax"

    words: list[str] = []
    for tok in tokenize(text):
        if tok.quoted:
            words.append(tok.text)
            continue
        words.extend(p for p in tok.text.split("/") if p)

    verdicts: list[Verdict] = []
    reasons: list[str] = []
    for word in words:
        lower = word.lower()
        if lower == "where":
            break  # the rest is a filter expression
        if "=" in lower:
            key, _, value = lower.partition("=")
            if key == "file":
                verdicts.append(Verdict.DESTRUCTIVE)
                reasons.append("writes a file (file=)")
            elif key == "disabled" and value in ("yes", "true"):
                verdicts.append(Verdict.DESTRUCTIVE)
                reasons.append("disables an item (disabled=yes)")
            continue
        if word.startswith('"'):
            continue
        found = _verb(lower)
        if found is not None:
            verdicts.append(found[1])
            reasons.append(f"verb '{found[0]}'")

    if not verdicts:
        return Verdict.UNKNOWN, "no recognized verb"
    verdict = worst(verdicts)
    reason = next(r for v, r in zip(verdicts, reasons, strict=True) if v is verdict)
    return verdict, reason


def classify_routeros(command: str, mode: Mode | None) -> Result:
    """Classify a RouterOS line; ``;`` separates several commands."""
    results = [_classify_one(part) for part in split_unquoted(command, ";")]
    verdict = worst([v for v, _ in results])
    reason = next(r for v, r in results if v is verdict)
    return Result(verdict, reason, mode)
