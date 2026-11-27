"""Device identifiers: serial numbers, ESNs, license IDs, EUI-64 interface IDs, ISIS NETs."""

from __future__ import annotations

import re
from collections.abc import Iterator

_VALUE = r"(?P<v>(?=[A-Za-z0-9._/-]*\d)[A-Za-z0-9][A-Za-z0-9._/-]{3,})"
# keyword followed by the identifier; short keywords need a ":" or "="
SERIAL_RE = re.compile(
    r"(?<![\w-])(?:"
    r"(?:processor board id|system serial number|chassis serial number|motherboard serial number"
    r"|serial number|serial-number|serial no\.?|board id|software-id|licen[cs]e id|device esn)"
    r"\s*[:=#]?\s*"
    r"|(?:serial|sn|s/n|esn)\s*[:=]\s*"
    r")" + _VALUE,
    re.IGNORECASE,
)
_SERIAL_HEADER = re.compile(r"^\s*Item\s+.*\bSerial number\b", re.IGNORECASE)
_JUNOS_ITEM = re.compile(
    r"^\s*(?:Chassis|Midplane|FPC|PIC|MIC|Routing Engine|CB|Power Supply|PEM|PSM|Fan Tray|FPM"
    r"|SPMB|SFB|Xcvr|Mezz|CPU|Craft Interface|HDD|SFP)\b"
)
_PART_NUMBER = re.compile(r"\d{3}-\d{5,}")
_SERIAL_TOKEN = re.compile(r"(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z])[A-Z0-9]{6,20}")
_COLUMNS = re.compile(r"\S+(?: \S+)*")

# bare 12-hex MAC when the surrounding words say it is a MAC
MAC_BARE_RE = re.compile(
    r"(?<![\w-])(?:mac(?:[- ]?address)?|hwaddr|hardware[- ]address|bia)\s*[:=]?\s*"
    r"(?P<v>[0-9A-Fa-f]{12})(?![0-9A-Fa-f])",
    re.IGNORECASE,
)

ISIS_NET_RE = re.compile(
    r"(?<![\w.])(?P<head>\d{2}(?:\.[0-9A-Fa-f]{4}){1,3}\.)"
    r"(?P<sys>\d{4}\.\d{4}\.\d{4})(?P<tail>\.[0-9A-Fa-f]{2})(?![\w.])"
)


def iter_serial_spans(lines: list[tuple[int, str]]) -> Iterator[tuple[int, int, str]]:
    """Yield ``(start, end, value)`` for serial numbers. ``lines`` is ``(offset, body)``."""
    in_table = False
    for off, body in lines:
        if not body.strip():
            in_table = False
            continue
        for m in SERIAL_RE.finditer(body):
            yield off + m.start("v"), off + m.end("v"), m.group("v")
        if _SERIAL_HEADER.match(body):
            in_table = True
        elif in_table or _JUNOS_ITEM.match(body):
            for col in _COLUMNS.finditer(body):
                tok = col.group()
                if _SERIAL_TOKEN.fullmatch(tok) and not _PART_NUMBER.search(tok):
                    yield off + col.start(), off + col.end(), tok
                    break


def is_eui64(iid: int) -> bool:
    """True when the low 64 bits look like a modified EUI-64 (``xxxx:xxFF:FExx:xxxx``)."""
    return (iid >> 24) & 0xFFFF == 0xFFFE


def mac_of_eui64(iid: int) -> str:
    """The MAC (``aa:bb:cc:dd:ee:ff``) an EUI-64 interface ID was derived from."""
    b = iid.to_bytes(8, "big")
    mac = bytes([b[0] ^ 0x02, b[1], b[2], b[5], b[6], b[7]])
    return ":".join(f"{x:02x}" for x in mac)


def eui64_of_mac(mac: str) -> int:
    """The modified EUI-64 interface ID for ``mac``."""
    m = bytes.fromhex(mac.replace(":", ""))
    return int.from_bytes(bytes([m[0] ^ 0x02, m[1], m[2], 0xFF, 0xFE, m[3], m[4], m[5]]), "big")
