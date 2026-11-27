"""Detect the text encoding of a capture so no byte pattern can hide data from the sanitizer.

Supported: UTF-8 (with or without BOM), UTF-16 and UTF-32 with a BOM, and UTF-16/UTF-32 without a
BOM when the bytes are NUL-interleaved. Anything else (Latin-1, binary, archives) is
:class:`UndecodableError`: callers must refuse (the CLI exits 2; the scanner reports a finding).
Sanitized output is re-encoded with the encoding it was read in, BOM included.
"""

from __future__ import annotations

import codecs
from dataclasses import dataclass


class UndecodableError(ValueError):
    """The bytes are not text in a supported encoding."""


@dataclass(frozen=True, slots=True)
class Decoded:
    text: str
    encoding: str  # codec used to decode (and to re-encode)
    bom: bytes  # BOM to put back in front of the re-encoded text


_BOMS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF32_LE, "utf-32-le"),  # before UTF-16: FF FE 00 00 starts with FF FE
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)


def _nul_layout(data: bytes) -> str | None:
    """Guess a BOM-less wide encoding from where the NUL bytes sit."""
    if len(data) < 4 or data.count(0) * 4 < len(data):
        return None
    head = data[:4096]
    n = len(head)
    even = sum(1 for b in head[0::2] if b == 0)
    odd = sum(1 for b in head[1::2] if b == 0)
    half = max(n // 2, 1)
    if odd * 3 >= half * 2 and even * 3 < half:
        return "utf-16-le"
    if even * 3 >= half * 2 and odd * 3 < half:
        return "utf-16-be"
    quarter = max(n // 4, 1)
    p = [sum(1 for b in head[i::4] if b == 0) for i in range(4)]
    if p[1] * 3 >= quarter * 2 and p[2] * 3 >= quarter * 2 and p[3] * 3 >= quarter * 2:
        return "utf-32-le"
    if p[0] * 3 >= quarter * 2 and p[1] * 3 >= quarter * 2 and p[2] * 3 >= quarter * 2:
        return "utf-32-be"
    return None


def decode_bytes(data: bytes) -> Decoded:
    """Decode ``data`` or raise :class:`UndecodableError`."""
    for bom, enc in _BOMS:
        if data.startswith(bom):
            try:
                return Decoded(data[len(bom) :].decode(enc), enc, bom)
            except UnicodeDecodeError as exc:
                raise UndecodableError(f"invalid {enc} data") from exc
    wide = _nul_layout(data)
    if wide is not None:
        try:
            return Decoded(data.decode(wide), wide, b"")
        except UnicodeDecodeError:
            pass  # fall through: maybe plain UTF-8 with many NULs
    try:
        return Decoded(data.decode("utf-8"), "utf-8", b"")
    except UnicodeDecodeError as exc:
        raise UndecodableError("not valid UTF-8, UTF-16 or UTF-32 text") from exc


def encode_text(text: str, decoded: Decoded) -> bytes:
    """Re-encode ``text`` the way the input was encoded."""
    return decoded.bom + text.encode(decoded.encoding)
