from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st
from netprompt import detect_prompt, detect_vendor, normalize, segment
from netprompt.normalize import PAGINATION

_FRAGMENTS = [
    "R1#",
    "R1>",
    "<PE1>",
    "[~PE1-bgp]",
    "[admin@R1] >",
    "user@R1#",
    "A:R1#",
    "[edit]",
    "[/]",
    "\r\n",
    "\n",
    "\r",
    "\x08",
    "\x1b[42D",
    "\x1b[0m",
    "---- More ----",
    " --More-- ",
    "---(more 35%)---",
    "-- [Q quit|D dump|down]",
    "Press any key to continue (Q to quit)",
    " ",
    "show version",
    "---",
]

_texts = st.one_of(
    st.text(max_size=200),
    st.lists(st.sampled_from(_FRAGMENTS) | st.text(max_size=5), max_size=30).map("".join),
)


@given(_texts)
def test_normalize_idempotent(text: str) -> None:
    once = normalize(text)
    assert normalize(once) == once


@given(_texts)
def test_detect_prompt_never_raises(text: str) -> None:
    detect_prompt(text)
    detect_prompt(text, known_hostnames={"PE1", "R1"})
    detect_vendor(text)


@settings(max_examples=200)
@given(_texts)
def test_segment_no_pagination_markers(text: str) -> None:
    segs = segment(text)
    joined = "\n".join(s.output for s in segs)
    assert PAGINATION.search(joined) is None
    for s in segs:
        assert s.line >= 1
