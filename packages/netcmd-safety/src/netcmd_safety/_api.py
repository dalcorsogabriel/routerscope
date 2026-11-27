"""Public entry points."""

from __future__ import annotations

import re

from ._engine import Result, classify_tree
from ._model import (
    MIKROTIK_ROS7,
    VENDORS,
    Classification,
    Mode,
    UnknownVendorError,
    Verdict,
    worst,
)
from ._vendors import TREE_SPECS
from ._vendors.mikrotik import classify_routeros

# A terminal executes on CR as well as LF.
_LINE_BREAK = re.compile(r"\r\n|\r|\n")
# Control characters (other than tab) edit the line on a pty: Ctrl-U kills it,
# backspace and DEL erase, ESC starts sequences. What runs is not what we see.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _check_vendor(vendor: str) -> None:
    if vendor not in VENDORS:
        raise UnknownVendorError(f"unknown vendor {vendor!r}; expected one of {', '.join(VENDORS)}")


def _coerce_mode(mode: Mode | str | None) -> Mode | None:
    """Accept any str/StrEnum with the value ``"exec"`` or ``"config"`` (e.g. netprompt's)."""
    if mode is None:
        return None
    try:
        return Mode(str(mode.value) if isinstance(mode, Mode) else str(mode))
    except ValueError:
        raise ValueError(f"invalid mode {mode!r}; expected 'exec', 'config' or None") from None


def _classify_line(line: str, vendor: str, mode: Mode | None) -> Result:
    if _CONTROL.search(line):
        return Result(Verdict.UNKNOWN, "contains terminal control characters", mode)
    if vendor == MIKROTIK_ROS7:
        result = classify_routeros(line, mode)
    else:
        result = classify_tree(line, mode, TREE_SPECS[vendor])
    if not line.isascii() and result.verdict in (Verdict.READ, Verdict.SESSION):
        # Lookalike characters (non-breaking space, Kelvin sign...) may not mean what
        # they look like to the device.
        return Result(Verdict.UNKNOWN, "contains non-ASCII characters", result.next_mode)
    return result


def classify_lines(
    text: str,
    vendor: str,
    *,
    mode: Mode | str | None = None,
) -> list[Classification]:
    """Classify each line of ``text``, tracking mode changes between lines.

    Lines are split on LF, CR and CRLF. A line such as ``configure terminal`` or
    ``system-view`` switches the following lines to configuration mode, and ``end`` /
    ``return`` switch back. Blank lines are skipped.
    """
    _check_vendor(vendor)
    current = _coerce_mode(mode)
    results: list[Classification] = []
    for raw in _LINE_BREAK.split(text):
        line = raw.strip(" \t")
        if not line:
            continue
        res = _classify_line(line, vendor, current)
        results.append(
            Classification(
                command=line,
                vendor=vendor,
                verdict=res.verdict,
                reason=res.reason,
                mode=current,
                next_mode=res.next_mode,
            )
        )
        current = res.next_mode
    return results


def classify(command: str, vendor: str, *, mode: Mode | str | None = None) -> Classification:
    """Classify a command typed on a ``vendor`` device.

    ``mode`` is the CLI mode if known (``Mode.EXEC``, ``Mode.CONFIG``, the strings
    ``"exec"``/``"config"``, or an equivalent enum such as netprompt's ``Mode``).
    Multi-line input is classified line by line and the most dangerous verdict wins.
    Unknown commands are ``UNKNOWN`` (never read). Raises :class:`UnknownVendorError`
    for an unsupported vendor ID and ``ValueError`` for an invalid mode.
    """
    start = _coerce_mode(mode)
    lines = classify_lines(command, vendor, mode=start)
    if not lines:
        return Classification(command, vendor, Verdict.SESSION, "empty input", start, start)
    if len(lines) == 1:
        one = lines[0]
        return Classification(command, vendor, one.verdict, one.reason, start, one.next_mode)
    verdict = worst([c.verdict for c in lines])
    index, first = next((i, c) for i, c in enumerate(lines, 1) if c.verdict is verdict)
    reason = f"line {index} ({first.command!r}): {first.reason}"
    return Classification(command, vendor, verdict, reason, start, lines[-1].next_mode)


def is_read(command: str, vendor: str, *, mode: Mode | str | None = None) -> bool:
    """True only if ``command`` just displays information."""
    return classify(command, vendor, mode=mode).verdict is Verdict.READ


def is_collector_safe(command: str, vendor: str, *, mode: Mode | str | None = None) -> bool:
    """True if a read-only collector may send ``command`` (``READ`` or ``SESSION``)."""
    return classify(command, vendor, mode=mode).collector_safe
