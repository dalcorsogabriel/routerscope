"""Public entry points."""

from __future__ import annotations

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


def _check_vendor(vendor: str) -> None:
    if vendor not in VENDORS:
        raise UnknownVendorError(f"unknown vendor {vendor!r}; expected one of {', '.join(VENDORS)}")


def _classify_line(line: str, vendor: str, mode: Mode | None) -> Result:
    if vendor == MIKROTIK_ROS7:
        return classify_routeros(line, mode)
    return classify_tree(line, mode, TREE_SPECS[vendor])


def classify_lines(
    text: str,
    vendor: str,
    *,
    mode: Mode | None = None,
    version: str | None = None,
) -> list[Classification]:
    """Classify each line of ``text``, tracking mode changes between lines.

    A line such as ``configure terminal`` or ``system-view`` switches the following
    lines to configuration mode, and ``end`` / ``return`` switch back. Blank lines are
    skipped. ``version`` is reserved for version-specific rules.
    """
    del version  # reserved
    _check_vendor(vendor)
    results: list[Classification] = []
    current = mode
    for raw in text.splitlines():
        line = raw.strip()
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


def classify(
    command: str,
    vendor: str,
    *,
    mode: Mode | None = None,
    version: str | None = None,
) -> Classification:
    """Classify a command typed on a ``vendor`` device.

    Multi-line input is classified line by line and the most dangerous verdict wins.
    Unknown commands are ``UNKNOWN`` (never read). Raises :class:`UnknownVendorError`
    for an unsupported vendor ID.
    """
    lines = classify_lines(command, vendor, mode=mode, version=version)
    if not lines:
        return Classification(command, vendor, Verdict.SESSION, "empty input", mode, mode)
    if len(lines) == 1:
        one = lines[0]
        return Classification(command, vendor, one.verdict, one.reason, mode, one.next_mode)
    verdict = worst([c.verdict for c in lines])
    index, first = next((i, c) for i, c in enumerate(lines, 1) if c.verdict is verdict)
    reason = f"line {index} ({first.command!r}): {first.reason}"
    return Classification(command, vendor, verdict, reason, mode, lines[-1].next_mode)


def is_read(command: str, vendor: str, *, mode: Mode | None = None) -> bool:
    """True only if ``command`` just displays information."""
    return classify(command, vendor, mode=mode).verdict is Verdict.READ


def is_collector_safe(command: str, vendor: str, *, mode: Mode | None = None) -> bool:
    """True if a read-only collector may send ``command`` (``READ`` or ``SESSION``)."""
    return classify(command, vendor, mode=mode).collector_safe
