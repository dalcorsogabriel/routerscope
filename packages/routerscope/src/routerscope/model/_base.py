"""Shared pydantic base and validated scalar types for the neutral data model."""

from __future__ import annotations

from typing import Annotated

from netcmd_safety import VENDORS
from pydantic import AfterValidator, BaseModel, ConfigDict, Field


class Frozen(BaseModel):
    """Base for every model: immutable and rejecting unknown fields."""

    model_config = ConfigDict(frozen=True, extra="forbid")


def check_vendor(value: str) -> str:
    """Validate a vendor id against :data:`netcmd_safety.VENDORS`."""
    if value not in VENDORS:
        raise ValueError(f"unknown vendor id {value!r}; expected one of {', '.join(VENDORS)}")
    return value


VendorId = Annotated[str, AfterValidator(check_vendor)]
"""A vendor id known to netcmd-safety (``cisco_ios``, ``huawei_vrp``, ...)."""

Asn = Annotated[int, Field(ge=1, le=4294967295)]
"""A 32-bit autonomous system number (1..4294967295)."""

Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
"""A lowercase sha256 hex digest."""
