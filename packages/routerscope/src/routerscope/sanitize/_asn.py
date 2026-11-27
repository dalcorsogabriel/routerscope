"""Find AS numbers in AS contexts only (conservative: bare numbers are never touched)."""

from __future__ import annotations

import re
from typing import NamedTuple

from routerscope.sanitize._lines import split_lines


class AsnSpan(NamedTuple):
    start: int  # absolute offsets of the number
    end: int
    value: int


def is_public_asn(n: int) -> bool:
    """Public = not private, documentation or reserved (AS_TRANS 23456 and 65535 are kept)."""
    return (1 <= n <= 64495 and n != 23456) or 131072 <= n <= 4199999999


_NUM = r"(?P<asn>\d{1,10})(?![\d.:])"
_WS = r"(?:\s*=\s*|\s+)"
_KW_WS = re.compile(
    r"(?<![\w.-])(?:router\s+bgp|remote-as|peer-as|as-number|local-as|autonomous-system"
    r"|confederation\s+(?:identifier|peers)|(?:remote|local|peer)\s+AS(?:\s+number)?(?:\s+is)?"
    rf"|aggregated\s+by){_WS}{_NUM}",
    re.IGNORECASE,
)
_KW_EQ = re.compile(rf"(?<![\w-])(?:[\w.]*\.)?as(?:\s+number)?\s*[:=]\s*{_NUM}", re.IGNORECASE)
_KW_BGP = re.compile(rf"^\s*bgp\s+{_NUM}", re.IGNORECASE)
_KW_JUNOS_PEER = re.compile(rf"\+\d{{1,5}}\s+AS\s+{_NUM}", re.IGNORECASE)
_LABEL = re.compile(r"(?<![\w-])as[ -]?path\s*:", re.IGNORECASE)
_PREPEND = re.compile(
    r"(?:as-path(?:-prepend)?|apply\s+as-path)\s+(?:prepend\s+)?\"?(?P<list>(?:\d{1,10}(?:\s+|(?=[\";]|$)))+)",
    re.IGNORECASE,
)
_DIGITS = re.compile(r"(?<![\d.:])\d{1,10}(?![\d.:])")
_REGEX_ASN = re.compile(r"(?<=[_^(|\s\"'\[])(?P<asn>\d{1,10})(?=[_$)|+*?\s\"'\];]|$)")
_REGEX_KW = re.compile(r"\b(?:permit|deny)\b", re.IGNORECASE)
_REGEX_KW2 = re.compile(r"\b(?:ios-regex|expression)\b", re.IGNORECASE)
_REGEX_JUNOS = re.compile(r"\bas-path\s+\S+\s+(?=\")", re.IGNORECASE)
_COMM_CTX = re.compile(
    r"communit|route-target|route-distinguisher|vpn-target|vrf-target|\brt\b|\brd\b|\bsoo\b"
    r"|\bmembers\b|target:|origin:",
    re.IGNORECASE,
)
_COMM = re.compile(
    r"(?:(?<![\w:.-])|(?<=target:)|(?<=origin:)|(?<=soo:))(?P<asn>\d{1,10}):\d{1,10}"
    r"(?::\d{1,10})?(?![\w:.])"
)
_IP = r"(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+)(?:%\S+)?"
_PEER_HEADER = re.compile(r"^\s*(?:(?:Neighbor|Peer)\b.*\bAS\b|AS\s+PktRcvd)")
_PEER_ROW = re.compile(rf"^\s*(?:{_IP}\s+)?(?:\d\s+)?(?P<asn>\d{{1,10}})(?=\s+\d+\s+\d+\s)")
_BGP_HEADER = re.compile(r"^\s*(?:Network|Prefix)\b.*?(?P<p>Path/Ogn|AS[ -]?Path|Path)\s*$")
_PATH_TAIL = re.compile(r"^(?P<p>(?:\d{1,10}[ \t]+)*\d{0,10})(?P<o>[ie?])[ \t]*$")
_PATHS_START = re.compile(r"^\s*(?:Paths:\s*\(|Path\s+#\d+:)")
_NUM_LINE = re.compile(r"^\s+(?P<l>\d{1,10}(?:\s+\d{1,10})*)\s*(?:,.*)?$")
_FROM_LINE = re.compile(r"\bfrom\s+\S+\s+\(")


def iter_asn_spans(text: str) -> list[AsnSpan]:
    """Return every AS number found in a recognised AS context, in text order."""
    found: dict[tuple[int, int], int] = {}

    def add(off: int, m: re.Match[str], group: str = "asn") -> None:
        found[(off + m.start(group), off + m.end(group))] = int(m.group(group))

    def add_digits(off: int, body: str, base: int, end: int) -> None:
        for m in _DIGITS.finditer(body, base, end):
            found[(off + m.start(), off + m.end())] = int(m.group())

    lines = list(split_lines(text))
    peer_table = False
    path_col: int | None = None
    in_paths = False
    for i, line in enumerate(lines):
        body, off = line.body, line.start
        if not body.strip():
            peer_table = False
            continue
        for rx in (_KW_WS, _KW_EQ, _KW_BGP, _KW_JUNOS_PEER):
            for m in rx.finditer(body):
                add(off, m)
        for m in _LABEL.finditer(body):
            add_digits(off, body, m.end(), len(body))
        for m in _PREPEND.finditer(body):
            add_digits(off, body, m.start("list"), m.end("list"))
        low = body.lower()
        km = None
        if "as-path" in low or "as path" in low:
            km = _REGEX_KW.search(body) or _REGEX_JUNOS.search(body)
        km = km or _REGEX_KW2.search(body)
        if km is not None:
            for m in _REGEX_ASN.finditer(body, km.end()):
                add(off, m)
        if _COMM_CTX.search(body):
            for m in _COMM.finditer(body):
                add(off, m)
        if _PEER_HEADER.match(body):
            peer_table = True
        elif peer_table and (pm := _PEER_ROW.match(body)):
            add(off, pm)
        hm = _BGP_HEADER.match(body)
        if hm:
            path_col = hm.start("p")
        elif (
            path_col is not None
            and len(body) > path_col
            and (path_col == 0 or body[path_col - 1].isspace())
        ):
            tm = _PATH_TAIL.match(body[path_col:])
            if tm:
                add_digits(off, body, path_col, path_col + tm.end("p"))
        if not body[0].isspace():
            in_paths = False
        if _PATHS_START.match(body):
            in_paths = True
        elif in_paths and (nm := _NUM_LINE.match(body)):
            nxt = next((n.body for n in lines[i + 1 :] if n.body.strip()), "")
            if _FROM_LINE.search(nxt):
                add_digits(off, body, nm.start("l"), nm.end("l"))
    return [AsnSpan(s, e, v) for (s, e), v in sorted(found.items())]
