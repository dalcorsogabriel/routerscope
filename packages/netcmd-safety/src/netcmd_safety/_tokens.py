"""Tokenizer shared by all vendors.

Quote handling is per vendor: Junos, SR OS and RouterOS honour double quotes, while
the Cisco-like CLIs and VRP do not, so there a ``"`` is an ordinary character and can
never hide a pipe or a redirect.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Token:
    text: str
    quoted: bool = False


def split_unquoted(text: str, sep: str, *, quotes: bool = True) -> list[str]:
    """Split ``text`` on ``sep`` characters that are outside double quotes."""
    parts: list[str] = []
    buf: list[str] = []
    in_quote = False
    for ch in text:
        if quotes and ch == '"':
            in_quote = not in_quote
            buf.append(ch)
        elif ch == sep and not in_quote:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


def tokenize(text: str, *, quotes: bool = True) -> list[Token]:
    """Split on whitespace, keeping double-quoted strings together when ``quotes``."""
    tokens: list[Token] = []
    buf: list[str] = []
    in_quote = False
    quoted = False

    def flush() -> None:
        nonlocal buf, quoted
        if buf or quoted:
            tokens.append(Token("".join(buf), quoted))
        buf = []
        quoted = False

    for ch in text:
        if quotes and ch == '"':
            in_quote = not in_quote
            quoted = True
            buf.append(ch)
        elif ch.isspace() and not in_quote:
            flush()
        else:
            buf.append(ch)
    flush()
    return tokens


def has_unquoted(text: str, chars: str, *, quotes: bool = True) -> bool:
    """True if any of ``chars`` appears outside double quotes."""
    in_quote = False
    for ch in text:
        if quotes and ch == '"':
            in_quote = not in_quote
        elif not in_quote and ch in chars:
            return True
    return False


def balanced_quotes(text: str) -> bool:
    return text.count('"') % 2 == 0
