"""Quote-aware word splitting shared by the tree parsers and the vendor extractors."""

from __future__ import annotations

_ESCAPES = {"n": "\n", "r": "\r", "t": "\t"}


def split_tokens(text: str) -> list[str]:
    """Split ``text`` on whitespace, keeping double-quoted strings (and their quotes) whole.

    ``comment="a b" mtu=1500`` gives ``['comment="a b"', 'mtu=1500']``. A backslash inside
    quotes escapes the next character. An unterminated quote swallows the rest of the text.
    A ``[`` that starts a word and is followed by a space or a quote opens a list: it and the
    matching ``]`` become words of their own (``["A" "B"]`` gives ``[``, ``"A"``, ``"B"``, ``]``).
    """
    tokens: list[str] = []
    current: list[str] = []
    in_quote = False
    depth = 0
    i = 0
    n = len(text)

    def flush() -> None:
        if current:
            tokens.append("".join(current))
            current.clear()

    while i < n:
        c = text[i]
        if in_quote:
            current.append(c)
            if c == "\\" and i + 1 < n:
                i += 1
                current.append(text[i])
            elif c == '"':
                in_quote = False
        elif c == '"':
            in_quote = True
            current.append(c)
        elif c.isspace():
            flush()
        elif c == "[" and not current and (i + 1 >= n or text[i + 1] in ' 	"'):
            tokens.append(c)
            depth += 1
        elif c == "]" and depth > 0:
            flush()
            tokens.append(c)
            depth -= 1
        else:
            current.append(c)
        i += 1
    flush()
    return tokens


def unquote(token: str) -> str:
    """Remove double quotes (also inside ``key="value"`` tokens) and resolve backslash escapes."""
    if '"' not in token:
        return token
    out: list[str] = []
    in_quote = False
    i = 0
    n = len(token)
    while i < n:
        c = token[i]
        if c == '"':
            in_quote = not in_quote
        elif c == "\\" and in_quote and i + 1 < n:
            i += 1
            nxt = token[i]
            out.append(_ESCAPES.get(nxt, nxt))
        else:
            out.append(c)
        i += 1
    return "".join(out)


def split_words(text: str) -> list[str]:
    """Like :func:`split_tokens` but with the quotes removed from every word."""
    return [unquote(token) for token in split_tokens(text)]
