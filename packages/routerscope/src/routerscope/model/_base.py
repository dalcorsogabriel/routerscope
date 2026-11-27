"""Shared pydantic base and validated scalar types for the neutral data model."""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class Frozen(BaseModel):
    """Base for every model: immutable and rejecting unknown fields."""

    model_config = ConfigDict(frozen=True, extra="forbid")


VENDOR_ID_PATTERN = r"^[a-z][a-z0-9_]*$"

VendorId = Annotated[str, Field(pattern=VENDOR_ID_PATTERN)]
"""A vendor id: a built-in one (``cisco_ios``, ``huawei_vrp``, ...) or a plugin's own id."""

_LINE_BREAK = re.compile(r"\r\n|\r|\n")


def split_lines(text: str) -> list[str]:
    """Split ``text`` into lines the way every routerscope component numbers them.

    Only LF, CR and CRLF break lines (not form feed, ``\\x85`` or ``\\u2028`` as
    ``str.splitlines`` does), and a trailing line break does not add an empty last line.
    :class:`SourceRef` line numbers are 1-based indexes into this list.
    """
    lines = _LINE_BREAK.split(text)
    if lines and lines[-1] == "":
        lines.pop()
    return lines


Asn = Annotated[int, Field(ge=1, le=4294967295)]
"""A 32-bit autonomous system number (1..4294967295)."""

Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
"""A lowercase sha256 hex digest."""
