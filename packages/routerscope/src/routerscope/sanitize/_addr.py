"""Address classification, span extraction and the block allocator used by the sanitizer."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

from netaddr_search import MatchKind, find_ips

VERSION_WORDS = ("version", "release", "build")

_V4_KEEP = tuple(
    IPv4Network(n)
    for n in (
        "0.0.0.0/8",
        "127.0.0.0/8",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "198.18.0.0/15",
    )
)
_V4_PRIVATE = tuple(
    IPv4Network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16")
)
V4_POOLS = tuple(
    IPv4Network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15")
)
_V6_GLOBAL = IPv6Network("2000::/3")
_V6_SAFE = (IPv6Network("2001:db8::/32"), IPv6Network("3fff::/20"))
_V6_ULA = IPv6Network("fc00::/7")
V6_POOLS = (IPv6Network("2001:db8::/32"),)


def is_mask_like(addr: IPv4Address) -> bool:
    """True for netmask-shaped (``255.255.255.0``) or wildcard-shaped (``0.0.0.255``) values."""
    v = int(addr)
    inv = v ^ 0xFFFFFFFF
    return (inv & (inv + 1)) == 0 or (v & (v + 1)) == 0


def classify_v4(addr: IPv4Address) -> str:
    """Return ``"public"``, ``"private"`` (RFC1918/CGNAT/link-local) or ``"keep"``."""
    if is_mask_like(addr) or any(addr in n for n in _V4_KEEP):
        return "keep"
    if any(addr in n for n in _V4_PRIVATE):
        return "private"
    return "public"


def classify_v6(addr: IPv6Address) -> str:
    """Return ``"public"`` (global unicast), ``"private"`` (ULA) or ``"keep"``."""
    if addr in _V6_ULA:
        return "private"
    if addr in _V6_GLOBAL and not any(addr in n for n in _V6_SAFE):
        return "public"
    return "keep"


@dataclass(frozen=True, slots=True)
class AddrSpan:
    """The address part of an IP match (without ``/len`` or a trailing mask/wildcard)."""

    start: int
    end: int
    address: IPv4Address | IPv6Address
    plen: int

    @property
    def v4(self) -> IPv4Address | None:
        """The IPv4 address, either native or embedded in an IPv4-mapped IPv6 address."""
        a = self.address
        if isinstance(a, IPv4Address):
            return a
        return a.ipv4_mapped

    @property
    def mapped(self) -> bool:
        return isinstance(self.address, IPv6Address) and self.address.ipv4_mapped is not None

    @property
    def v4_plen(self) -> int:
        if self.mapped:
            return 32 if self.plen >= 128 else max(self.plen - 96, 0)
        return self.plen

    def classify(self) -> str:
        v4 = self.v4
        if v4 is not None:
            return classify_v4(v4)
        assert isinstance(self.address, IPv6Address)
        return classify_v6(self.address)


def iter_addr_spans(text: str) -> Iterator[AddrSpan]:
    for m in find_ips(text, skip_after=VERSION_WORDS):
        if m.kind is MatchKind.PREFIX:
            end = m.start + m.text.index("/")
        elif m.kind in (MatchKind.MASK, MatchKind.WILDCARD):
            end = m.start + len(m.text.split(None, 1)[0])
        else:
            end = m.end
        plen = m.network.prefixlen
        if m.kind in (MatchKind.MASK, MatchKind.WILDCARD) and plen == 0:
            plen = 32  # "0.0.0.0 0.0.0.0" style default: address itself is what matters
        yield AddrSpan(m.start, end, m.address, plen)


def digest(salt: str, label: str, key: str) -> bytes:
    return hashlib.sha256(f"{salt}\0{label}\0{key}".encode()).digest()


class Allocator:
    """Assigns every original block an aligned slot in a pool of documentation space.

    A *block* is the prefix of length ``min(plen, block_len)`` that contains an address;
    blocks nested in a shorter block are merged into it. Slots are handed out first-fit in
    pool order, blocks ordered by (length, salted hash), so output depends only on the set of
    blocks and the salt. An address maps to ``slot + (address - block_base)``.
    """

    def __init__(
        self,
        *,
        width: int,
        pools: tuple[tuple[int, int], ...],
        block_len: int,
        min_len: int,
        salt: str,
        label: str,
    ) -> None:
        self.width = width
        self.pools = pools  # (base, prefixlen)
        self.block_len = block_len
        self.min_len = min_len
        self.salt = salt
        self.label = label
        self.blocks: dict[tuple[int, int], int] = {}
        self._lengths: list[int] = []
        self._used: list[tuple[int, int]] = []
        self._cursor: dict[int, int] = {}

    def _mask(self, length: int) -> int:
        return ((1 << length) - 1) << (self.width - length)

    def block_of(self, addr: int, plen: int) -> tuple[int, int] | None:
        if plen < self.min_len:
            return None
        length = min(plen, self.block_len)
        return addr & self._mask(length), length

    def reserve(self, addr: int, plen: int) -> None:
        """Mark the block of a kept (already safe) address as occupied."""
        block = self.block_of(addr, plen)
        if block is None:
            return
        base, length = block
        self._used.append((base, base + (1 << (self.width - length)) - 1))

    def _covered(self, base: int, length: int) -> bool:
        return any(
            ln <= length and (base & self._mask(ln), ln) in self.blocks for ln in self._lengths
        )

    def _slot(self, length: int, index: int) -> int | None:
        size = 1 << (self.width - length)
        for pbase, plen in self.pools:
            count = (1 << (self.width - plen)) // size
            if index < count:
                return pbase + index * size
            index -= count
        return None

    def _slot_count(self, length: int) -> int:
        size = 1 << (self.width - length)
        return sum(((1 << (self.width - p)) // size) for _, p in self.pools)

    def _free(self, start: int, end: int) -> bool:
        return all(end < a or start > b for a, b in self._used)

    def plan(self, items: list[tuple[int, int]]) -> None:
        """Allocate slots for the blocks of ``(address, plen)`` items not yet mapped."""
        found = {b for it in items if (b := self.block_of(*it)) is not None}
        fresh = sorted(b for b in found if not self._covered(*b))
        top: set[tuple[int, int]] = set()
        for base, length in sorted(fresh, key=lambda b: b[1]):
            if any((base & self._mask(ln), ln) in top for ln in {t[1] for t in top} if ln < length):
                continue
            top.add((base, length))
        order = sorted(top, key=lambda b: (b[1], digest(self.salt, self.label, f"{b[0]}/{b[1]}")))
        for base, length in order:
            self._allocate(base, length)

    def _allocate(self, base: int, length: int) -> None:
        size = 1 << (self.width - length)
        total = self._slot_count(length)
        target: int | None = None
        index = self._cursor.get(length, 0)
        while index < total:
            cand = self._slot(length, index)
            index += 1
            if cand is not None and self._free(cand, cand + size - 1):
                target = cand
                self._used.append((cand, cand + size - 1))
                break
        self._cursor[length] = index
        if target is None:
            # Space exhausted: wrap around deterministically (documented collision).
            h = int.from_bytes(digest(self.salt, self.label, f"{base}/{length}")[:8], "big")
            target = self._slot(length, h % total) if total else self._slot(self.min_len, 0)
            assert target is not None
        self.blocks[(base, length)] = target
        if length not in self._lengths:
            self._lengths.append(length)
            self._lengths.sort(reverse=True)

    def map(self, addr: int, plen: int) -> int:
        """Map an address; prefixes shorter than ``min_len`` map to the start of the first pool."""
        if self.block_of(addr, plen) is None:
            return self.pools[0][0] if self.label == "v6" else self.pools[-1][0]
        for length in self._lengths:
            base = addr & self._mask(length)
            if (base, length) in self.blocks:
                return self.blocks[(base, length)] + (addr - base)
        return self.pools[-1][0]  # pragma: no cover - plan() always runs first
