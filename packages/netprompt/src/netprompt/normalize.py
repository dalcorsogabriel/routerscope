"""Terminal-noise removal: ANSI escapes, backspaces, carriage returns and pagination."""

from __future__ import annotations

import re

_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_CRLF = re.compile(r"\r+\n")

# Devices erase a pagination prompt by moving the cursor back, overwriting with spaces and
# moving back again (cursor-left CSI, backspaces or carriage returns).
_ERASE = r"(?:(?:\x1b\[\d*D|\x08+|\r)[ ]*(?:\x1b\[\d*D|\x08+|\r))?"
_MARKERS = (
    r"---- More ----",  # Huawei VRP
    r"--More--",  # Cisco IOS / IOS-XE
    r"---\(more(?: \d+%)?\)---",  # Junos
    r"-- \[Q quit\|D dump\|[^\]\r\n]*\]",  # RouterOS
    r"Press any key to continue \(Q to quit\)",  # SR OS classic
)
PAGINATION = re.compile(r"[ \t]*(?:" + "|".join(_MARKERS) + r")[ ]*" + _ERASE)
"""Regex matching a pagination prompt (and the erase sequence that follows it)."""


def _apply_controls(line: str) -> str:
    """Apply backspace and bare carriage-return semantics to a single line."""
    if "\b" not in line and "\r" not in line:
        return line
    buf: list[str] = []
    cur = 0
    for ch in line:
        if ch == "\r":
            cur = 0
        elif ch == "\b":
            if cur == len(buf) and cur > 0:
                buf.pop()
                cur -= 1
            elif cur > 0:
                cur -= 1
        else:
            if cur < len(buf):
                buf[cur] = ch
            else:
                buf.append(ch)
            cur += 1
    return "".join(buf)


def _normalize_once(text: str) -> str:
    out: list[str] = []
    for line in _CRLF.sub("\n", text).split("\n"):
        stripped, count = PAGINATION.subn("", line)
        cleaned = _apply_controls(_ANSI.sub("", stripped))
        if count and not cleaned.strip():
            continue  # blank residue left by a pagination marker
        out.append(cleaned)
    return "\n".join(out)


def normalize(text: str) -> str:
    """Return ``text`` without terminal noise.

    Removes ANSI CSI/OSC escape sequences, applies backspaces (``abc\\bd`` -> ``abd``) and bare
    carriage-return overwrites, converts CRLF to LF and removes pagination prompts for Huawei,
    Cisco, Junos, RouterOS and SR OS together with the blank residue they leave. Everything else
    is kept byte-identical (trailing spaces of real output are preserved). Idempotent.
    """
    while True:
        new = _normalize_once(text)
        if new == text:
            return text
        text = new
