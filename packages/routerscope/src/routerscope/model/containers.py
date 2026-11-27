"""Containers returned by vendor parsers.

``ParsedConfig`` holds typed lists, one per object kind (a config snapshot has many of each).
``ParseResult`` holds the objects found in one command's output as a tuple of a discriminated
union (discriminator: ``kind``), because a command yields a heterogeneous, usually small set.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated, Self

from pydantic import Field, model_validator

from routerscope.model._base import VENDOR_ID_PATTERN, Frozen, Sha256Hex
from routerscope.model.objects import (
    ACL,
    IGP,
    LAG,
    VLAN,
    VRF,
    BGPPeer,
    Device,
    Interface,
    IPAddress,
    ParsedObject,
    ParsedObjectUnion,
    Policy,
    PrefixList,
    StaticRoute,
    Transceiver,
    Version,
)
from routerscope.model.provenance import SourceRef

_VENDOR_ID = VENDOR_ID_PATTERN


def _refs(obj: ParsedObject) -> Iterator[SourceRef]:
    """The object's own ref plus refs of nested parts (policy terms)."""
    yield obj.ref
    if isinstance(obj, Policy):
        yield from (term.ref for term in obj.terms if term.ref is not None)


class ParsedConfig(Frozen):
    """Everything a vendor parser extracted from one config snapshot.

    ``vendor`` is a plain id (not restricted to netcmd-safety vendors) so third-party
    plugins can report their own id.
    """

    snapshot_id: Sha256Hex
    vendor: str | None = Field(default=None, pattern=_VENDOR_ID)
    device: Device | None = None
    version: Version | None = None
    interfaces: tuple[Interface, ...] = ()
    ip_addresses: tuple[IPAddress, ...] = ()
    vrfs: tuple[VRF, ...] = ()
    bgp_peers: tuple[BGPPeer, ...] = ()
    policies: tuple[Policy, ...] = ()
    prefix_lists: tuple[PrefixList, ...] = ()
    acls: tuple[ACL, ...] = ()
    static_routes: tuple[StaticRoute, ...] = ()
    igps: tuple[IGP, ...] = ()
    lags: tuple[LAG, ...] = ()
    vlans: tuple[VLAN, ...] = ()
    transceivers: tuple[Transceiver, ...] = ()

    def iter_objects(self) -> Iterator[ParsedObject]:
        """Yield every contained object (device and version first, then each list in order)."""
        for single in (self.device, self.version):
            if single is not None:
                yield single
        for seq in (
            self.interfaces,
            self.ip_addresses,
            self.vrfs,
            self.bgp_peers,
            self.policies,
            self.prefix_lists,
            self.acls,
            self.static_routes,
            self.igps,
            self.lags,
            self.vlans,
            self.transceivers,
        ):
            yield from seq

    @model_validator(mode="after")
    def _refs_match_snapshot(self) -> Self:
        for obj in self.iter_objects():
            for ref in _refs(obj):
                if ref.snapshot_id != self.snapshot_id:
                    raise ValueError(
                        f"{obj.kind} ref points at snapshot {ref.snapshot_id[:12]}, "
                        f"not {self.snapshot_id[:12]}"
                    )
        return self


class ParseResult(Frozen):
    """Objects parsed from the output of one command."""

    snapshot_id: Sha256Hex
    command: str = Field(min_length=1)
    vendor: str | None = Field(default=None, pattern=_VENDOR_ID)
    objects: tuple[Annotated[ParsedObjectUnion, Field(discriminator="kind")], ...] = ()

    @model_validator(mode="after")
    def _refs_match_snapshot(self) -> Self:
        for obj in self.objects:
            if any(ref.snapshot_id != self.snapshot_id for ref in _refs(obj)):
                raise ValueError(f"{obj.kind} ref points at a different snapshot")
        return self
