from __future__ import annotations

import pytest
from netprompt import normalize

ESC = "\x1b"


def test_ansi_csi_and_osc() -> None:
    assert (
        normalize(f"{ESC}[1;32mok{ESC}[0m {ESC}]0;title\x07done {ESC}]8;;x{ESC}\\z") == "ok done z"
    )


def test_backspace_and_cr() -> None:
    assert normalize("abc\bd") == "abd"
    assert normalize("abc\b \b") == "ab"
    assert normalize("\bx") == "x"
    assert normalize("hello\rHE") == "HEllo"
    assert normalize("a\r\nb\r\r\nc\n") == "a\nb\nc\n"
    assert normalize("abc\b\bX") == "aX"
    assert normalize("abcd\rxy\bz") == "xzcd"


def test_keeps_trailing_spaces_and_blank_lines() -> None:
    text = "line one   \n\n  indented  \n"
    assert normalize(text) == text


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (f"a\n  ---- More ----{ESC}[42D{' ' * 42}{ESC}[42D  b\nc", "a\n  b\nc"),
        ("a\n  ---- More ----\nb", "a\nb"),
        (f"a\n --More-- {chr(8) * 9}{' ' * 9}{chr(8) * 9}b", "a\nb"),
        ("a\n---(more)---\r            \rb", "a\nb"),
        ("a\n---(more 35%)---\r                \rb", "a\nb"),
        ("a\n-- [Q quit|D dump|down]\r                       \rb", "a\nb"),
        ("a\nPress any key to continue (Q to quit)\r" + " " * 37 + "\rb", "a\nb"),
        ("a\nPress any key to continue (Q to quit)\nb", "a\nb"),
    ],
)
def test_pagination(raw: str, expected: str) -> None:
    assert normalize(raw) == expected


def test_idempotent_on_tricky_input() -> None:
    raw = "--\x1b[0m-- More --\n---(more)\x08---\x1b[Km"
    once = normalize(raw)
    assert normalize(once) == once
