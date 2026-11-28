"""Semantic diff of parsed objects, matched by natural key.

Two collections of parsed objects (a :class:`~routerscope.model.ParsedConfig`, a
:class:`~routerscope.model.ParseResult` or any iterable of objects) are matched by a *natural key*
per object kind (an interface by its normalized name, a BGP peer by ``(vrf, peer)``, ...).
Objects present on one side only are ``added`` / ``removed``; objects on both sides are compared
field by field and reported as ``changed`` with ``old -> new`` for each differing field.

Rules that make the result useful rather than noisy:

* ``ref`` (line numbers, snapshot id) is never compared: moving a block is not a change.
* Each kind has a set of *volatile* fields (uptime, optical readings, ARP/MAC age, ...) that are
  ignored unless ``include_volatile=True``. Protocol state (e.g. BGP ``state``) is **not**
  volatile: a session going down is exactly what you want to see.
* Fields listed as ``unordered`` (route targets, member lists) are compared as sets.
* Kinds that contain sub-entries (prefix lists, ACLs, policies, IGP interfaces) get an
  entry-level diff keyed by sequence number (or by content when there is none).

Adding a kind is one call: ``register_kind("arp_entry", ("ip", "vrf"), volatile=("age",))``.
A kind that is not registered still works: a generic key is derived (see :func:`generic_key`).
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)
from typing import Any, Literal

from netaddr_search import normalize_interface
from pydantic import BaseModel

from routerscope.model import ParsedConfig, ParsedObject, ParseResult, SourceRef

__all__ = [
    "GENERIC_VOLATILE",
    "FieldChange",
    "ItemChange",
    "ItemSpec",
    "KindSpec",
    "ObjectChange",
    "ObjectSource",
    "SemanticDiff",
    "diff_objects",
    "generic_key",
    "register_kind",
    "registry",
]

Op = Literal["added", "removed", "changed"]
ObjectSource = ParsedConfig | ParseResult | Iterable[ParsedObject]
KeyFn = Callable[[Any], tuple[str, ...]]
ItemKeyFn = Callable[[Any, int], str]

GENERIC_VOLATILE = frozenset(
    {
        "uptime",
        "age",
        "expires",
        "last_flap",
        "last_change",
        "last_changed",
        "last_seen",
        "timestamp",
        "counters",
    }
)
"""Field names treated as volatile for kinds without a registered spec."""

_SKIP = frozenset({"kind", "ref"})
_PLAIN_TYPES = (IPv4Address, IPv6Address, IPv4Interface, IPv6Interface, IPv4Network, IPv6Network)


# --------------------------------------------------------------------------- results


def _swap(op: Op) -> Op:
    if op == "added":
        return "removed"
    return "added" if op == "removed" else "changed"


@dataclass(frozen=True, slots=True)
class FieldChange:
    """One field that differs: ``old`` and ``new`` are JSON-able values."""

    field: str
    old: object
    new: object

    def inverted(self) -> FieldChange:
        return FieldChange(self.field, self.new, self.old)

    def to_dict(self) -> dict[str, object]:
        return {"field": self.field, "old": self.old, "new": self.new}


@dataclass(frozen=True, slots=True)
class ItemChange:
    """An entry inside an object (prefix-list line, ACL entry, policy term, ...)."""

    op: Op
    key: str
    fields: tuple[FieldChange, ...] = ()
    old: dict[str, object] | None = None
    new: dict[str, object] | None = None

    def inverted(self) -> ItemChange:
        return ItemChange(
            _swap(self.op), self.key, tuple(f.inverted() for f in self.fields), self.new, self.old
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "op": self.op,
            "key": self.key,
            "fields": [f.to_dict() for f in self.fields],
            "old": self.old,
            "new": self.new,
        }


@dataclass(frozen=True, slots=True)
class ObjectChange:
    """An object that was added, removed or changed, with the refs of both sides."""

    kind: str
    key: tuple[str, ...]
    op: Op
    old_ref: SourceRef | None = None
    new_ref: SourceRef | None = None
    fields: tuple[FieldChange, ...] = ()
    items: tuple[ItemChange, ...] = ()
    old: dict[str, object] | None = None
    new: dict[str, object] | None = None

    @property
    def label(self) -> str:
        """Short human name, e.g. ``bgp_peer CUST/192.0.2.1``."""
        key = "/".join(part for part in self.key if part)
        return f"{self.kind} {key}".rstrip()

    def inverted(self) -> ObjectChange:
        return ObjectChange(
            self.kind,
            self.key,
            _swap(self.op),
            self.new_ref,
            self.old_ref,
            tuple(f.inverted() for f in self.fields),
            tuple(i.inverted() for i in self.items),
            self.new,
            self.old,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "key": list(self.key),
            "op": self.op,
            "old_ref": None if self.old_ref is None else self.old_ref.model_dump(),
            "new_ref": None if self.new_ref is None else self.new_ref.model_dump(),
            "fields": [f.to_dict() for f in self.fields],
            "items": [i.to_dict() for i in self.items],
            "old": self.old,
            "new": self.new,
        }


@dataclass(frozen=True, slots=True)
class SemanticDiff:
    """Result of :func:`diff_objects`, ordered by kind then key."""

    changes: tuple[ObjectChange, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not self.changes

    def of_op(self, op: Op) -> tuple[ObjectChange, ...]:
        return tuple(c for c in self.changes if c.op == op)

    @property
    def added(self) -> tuple[ObjectChange, ...]:
        return self.of_op("added")

    @property
    def removed(self) -> tuple[ObjectChange, ...]:
        return self.of_op("removed")

    @property
    def changed(self) -> tuple[ObjectChange, ...]:
        return self.of_op("changed")

    def of_kind(self, kind: str) -> tuple[ObjectChange, ...]:
        return tuple(c for c in self.changes if c.kind == kind)

    def inverted(self) -> SemanticDiff:
        """The diff of the same two collections with the sides swapped."""
        return SemanticDiff(tuple(c.inverted() for c in self.changes))

    def to_dict(self) -> dict[str, object]:
        return {
            "added": len(self.added),
            "removed": len(self.removed),
            "changed": len(self.changed),
            "changes": [c.to_dict() for c in self.changes],
        }

    def render_text(self) -> str:
        """One line per change (``+`` added, ``-`` removed, ``~`` changed), details indented."""
        out: list[str] = []
        sign = {"added": "+", "removed": "-", "changed": "~"}
        for change in self.changes:
            out.append(f"{sign[change.op]} {change.label}")
            for fc in change.fields:
                out.append(f"    {fc.field}: {_show(fc.old)} -> {_show(fc.new)}")
            for item in change.items:
                out.append(f"    {sign[item.op]} {item.key}")
                for fc in item.fields:
                    out.append(f"        {fc.field}: {_show(fc.old)} -> {_show(fc.new)}")
        return "\n".join(out)


def _show(value: object) -> str:
    return "-" if value is None else json.dumps(value, ensure_ascii=False, default=str)


# --------------------------------------------------------------------------- registry


@dataclass(frozen=True, slots=True)
class ItemSpec:
    """How to diff a tuple field of sub-entries.

    ``key(item, index)`` names an entry (stable across snapshots). With ``ordered=True`` a change
    in the relative order of entries whose key is not sequence-based (``"seq ..."``) is reported
    as a ``<field>_order`` field change.
    """

    field: str
    key: ItemKeyFn
    ordered: bool = False


@dataclass(frozen=True, slots=True)
class KindSpec:
    """Natural key and comparison rules for one object kind."""

    kind: str
    key: tuple[str, ...] | KeyFn
    volatile: frozenset[str] = frozenset()
    unordered: frozenset[str] = frozenset()
    items: tuple[ItemSpec, ...] = ()
    key_fields: frozenset[str] = frozenset()
    """Fields the key already covers (not compared again). Defaults to a tuple key's fields."""


def _s(value: object) -> str:
    return "" if value is None else str(value)


def _iface(name: object) -> str:
    try:
        return normalize_interface(str(name))
    except Exception:  # defensive: a key must never break a diff  # pragma: no cover
        return str(name)


def _seq_or(item: Any, text: str) -> str:
    seq = getattr(item, "seq", None)
    return f"seq {seq}" if seq is not None else text


def _prefix_entry_key(item: Any, _index: int) -> str:
    text = f"{item.action} {item.prefix}"
    if item.ge is not None:
        text += f" ge {item.ge}"
    if item.le is not None:
        text += f" le {item.le}"
    return _seq_or(item, text)


def _acl_entry_key(item: Any, _index: int) -> str:
    text = item.raw or " ".join(
        part for part in (item.action, item.protocol, item.source, item.destination) if part
    )
    return _seq_or(item, text)


def _term_key(item: Any, index: int) -> str:
    if item.seq is not None:
        return f"seq {item.seq}"
    return f"term {item.name}" if item.name else f"#{index + 1}"


def _static_route_key(obj: Any) -> tuple[str, ...]:
    return (
        _s(obj.vrf),
        str(obj.prefix),
        _s(obj.next_hop),
        _s(obj.interface),
        "blackhole" if obj.blackhole else "",
    )


_REGISTRY: dict[str, KindSpec] = {}


def register_kind(
    kind: str,
    key: tuple[str, ...] | KeyFn,
    *,
    volatile: Iterable[str] = (),
    unordered: Iterable[str] = (),
    items: Iterable[ItemSpec] = (),
    key_fields: Iterable[str] = (),
    replace: bool = False,
) -> KindSpec:
    """Register (or with ``replace=True`` overwrite) the diff rules of an object kind.

    ``key`` is a tuple of field names (values are stringified, ``None`` becomes ``""``) or a
    function ``obj -> tuple[str, ...]`` (then list the fields it reads in ``key_fields`` so they
    are not compared again). If a named field does not exist on an object, that
    object falls back to :func:`generic_key`.
    """
    if kind in _REGISTRY and not replace:
        raise ValueError(f"kind {kind!r} is already registered")
    covered = frozenset(key_fields) | (frozenset() if callable(key) else frozenset(key))
    spec = KindSpec(kind, key, frozenset(volatile), frozenset(unordered), tuple(items), covered)
    _REGISTRY[kind] = spec
    return spec


def registry() -> dict[str, KindSpec]:
    """A copy of the registered kinds, in canonical output order."""
    return dict(_REGISTRY)


register_kind("device", ())
register_kind("version", (), volatile=("uptime",))
register_kind("interface", ("name_normalized",))
register_kind(
    "ip_address",
    lambda o: (_iface(o.interface), str(o.address), _s(o.vrf)),
    key_fields=("interface", "address", "vrf"),
)
register_kind("vrf", ("name",), unordered=("import_targets", "export_targets", "interfaces"))
register_kind("bgp_peer", ("vrf", "peer"), unordered=("address_families",))
register_kind("policy", ("name",), items=(ItemSpec("terms", _term_key, ordered=True),))
register_kind(
    "prefix_list", ("name", "afi"), items=(ItemSpec("entries", _prefix_entry_key, ordered=True),)
)
register_kind("acl", ("name", "afi"), items=(ItemSpec("entries", _acl_entry_key, ordered=True),))
register_kind(
    "static_route",
    _static_route_key,
    key_fields=("vrf", "prefix", "next_hop", "interface", "blackhole"),
)
register_kind(
    "igp",
    ("protocol", "process", "vrf"),
    unordered=("areas", "levels"),
    items=(ItemSpec("interfaces", lambda i, _n: str(i.name)),),
)
register_kind("lag", ("name_normalized",), unordered=("members",))
register_kind("vlan", ("vlan_id",), unordered=("interfaces",))
register_kind(
    "transceiver",
    lambda o: (_iface(o.interface),),
    volatile=("rx_power_dbm", "tx_power_dbm", "temperature_c"),
    key_fields=("interface",),
)
# Kinds that are being added to the model; harmless until the classes exist.
register_kind("arp_entry", ("ip", "vrf"), volatile=("age", "expires", "uptime"))
register_kind("mac_entry", ("mac", "vlan"), volatile=("age", "expires", "uptime"))


def generic_key(obj: object) -> tuple[str, ...]:
    """Key for kinds without a spec: ``name``/``id`` (+ ``vrf``) if present, else the content.

    Without a natural key, any change shows up as one object removed and another added.
    """
    data = _dump(obj)
    if "name" in data or "id" in data:
        return tuple(_s(data[f]) for f in ("name", "id", "vrf") if f in data)
    content = {k: v for k, v in data.items() if k not in GENERIC_VOLATILE}
    return (json.dumps(content, sort_keys=True, default=str),)


# --------------------------------------------------------------------------- comparison


def _plain(value: object) -> object:
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, _PLAIN_TYPES):
        return str(value)
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, tuple | list | set | frozenset):
        return [_plain(v) for v in value]
    return str(value)


def _dump(obj: object) -> dict[str, object]:
    """Field name -> JSON-able value for a model (``ref`` and ``kind`` excluded)."""
    if isinstance(obj, BaseModel):
        return {
            name: _plain(getattr(obj, name)) for name in type(obj).model_fields if name not in _SKIP
        }
    return {k: _plain(v) for k, v in vars(obj).items() if k not in _SKIP}  # pragma: no cover


def _sort_key(value: object) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _kind_of(obj: object) -> str:
    return str(getattr(obj, "kind", type(obj).__name__.lower()))


def _key_of(obj: object, spec: KindSpec | None) -> tuple[str, ...]:
    if spec is None:
        return generic_key(obj)
    if callable(spec.key):
        try:
            return spec.key(obj)
        except AttributeError:
            return generic_key(obj)
    if any(not hasattr(obj, name) for name in spec.key):
        return generic_key(obj)
    return tuple(_s(getattr(obj, name)) for name in spec.key)


def _index(
    objects: Iterable[ParsedObject], specs: dict[str, KindSpec]
) -> dict[tuple[str, tuple[str, ...]], ParsedObject]:
    """Map ``(kind, key)`` to object; repeated keys get ``#2``, ``#3`` ... appended."""
    seen: Counter[tuple[str, tuple[str, ...]]] = Counter()
    out: dict[tuple[str, tuple[str, ...]], ParsedObject] = {}
    for obj in objects:
        kind = _kind_of(obj)
        key = _key_of(obj, specs.get(kind))
        seen[(kind, key)] += 1
        count = seen[(kind, key)]
        out[(kind, key if count == 1 else (*key, f"#{count}"))] = obj
    return out


def objects_of(source: ObjectSource) -> list[ParsedObject]:
    """The objects of a parsed config, a parse result or any iterable of objects."""
    if isinstance(source, ParsedConfig):
        return list(source.iter_objects())
    if isinstance(source, ParseResult):
        return list(source.objects)
    return list(source)


def _compare_fields(
    old: dict[str, object], new: dict[str, object], skip: frozenset[str], unordered: frozenset[str]
) -> tuple[FieldChange, ...]:
    out: list[FieldChange] = []
    for name in (*old, *(n for n in new if n not in old)):
        if name in skip:
            continue
        a, b = old.get(name), new.get(name)
        if name in unordered and isinstance(a, list) and isinstance(b, list):
            if sorted(a, key=_sort_key) != sorted(b, key=_sort_key):
                out.append(FieldChange(name, a, b))
        elif a != b:
            out.append(FieldChange(name, a, b))
    return tuple(out)


def _item_plain(item: object) -> dict[str, object]:
    data = _dump(item)
    if data.get("matches") or data.get("actions"):
        data.pop("raw_lines", None)  # the parsed clauses carry the meaning
    return data


def _index_items(items: Iterable[object], spec: ItemSpec) -> dict[str, dict[str, object]]:
    out: dict[str, dict[str, object]] = {}
    for index, item in enumerate(items):
        key = spec.key(item, index)
        base, n = key, 1
        while key in out:
            n += 1
            key = f"{base} #{n}"
        out[key] = _item_plain(item)
    return out


def _diff_items(
    old: object, new: object, spec: ItemSpec
) -> tuple[tuple[ItemChange, ...], FieldChange | None]:
    a = _index_items(getattr(old, spec.field, ()) or (), spec)
    b = _index_items(getattr(new, spec.field, ()) or (), spec)
    out: list[ItemChange] = []
    for key, value in a.items():
        if key not in b:
            out.append(ItemChange("removed", key, old=value))
        else:
            fields = _compare_fields(value, b[key], frozenset(), frozenset())
            if fields:
                out.append(ItemChange("changed", key, fields, value, b[key]))
    out.extend(ItemChange("added", key, new=value) for key, value in b.items() if key not in a)
    out.sort(key=lambda c: c.key)
    if spec.ordered:
        keys_a = [k for k in a if k in b and not k.startswith("seq ")]
        keys_b = [k for k in b if k in a and not k.startswith("seq ")]
        if keys_a != keys_b:
            return tuple(out), FieldChange(f"{spec.field}_order", keys_a, keys_b)
    return tuple(out), None


def _skipped(spec: KindSpec | None, include_volatile: bool) -> frozenset[str]:
    skip: set[str] = set()
    if spec is None:
        if not include_volatile:
            skip |= GENERIC_VOLATILE
        return frozenset(skip)
    skip.update(spec.key_fields)
    skip.update(i.field for i in spec.items)
    if not include_volatile:
        skip |= spec.volatile
    return frozenset(skip)


def _compare_objects(
    kind: str,
    key: tuple[str, ...],
    old: ParsedObject,
    new: ParsedObject,
    spec: KindSpec | None,
    include_volatile: bool,
) -> ObjectChange | None:
    skip = _skipped(spec, include_volatile)
    a, b = _dump(old), _dump(new)
    fields = list(_compare_fields(a, b, skip, spec.unordered if spec else frozenset()))
    items: list[ItemChange] = []
    for item_spec in spec.items if spec else ():
        changes, order = _diff_items(old, new, item_spec)
        items.extend(changes)
        if order is not None:
            fields.append(order)
    if not fields and not items:
        return None
    return ObjectChange(
        kind,
        key,
        "changed",
        old.ref,
        new.ref,
        tuple(fields),
        tuple(items),
        a,
        b,
    )


def _kind_rank(kind: str) -> tuple[int, str]:
    order = list(_REGISTRY)
    return (order.index(kind), "") if kind in _REGISTRY else (len(order), kind)


def diff_objects(
    old: ObjectSource,
    new: ObjectSource,
    *,
    include_volatile: bool = False,
    specs: dict[str, KindSpec] | None = None,
) -> SemanticDiff:
    """Diff two collections of parsed objects by natural key.

    ``include_volatile=True`` also compares the volatile fields (uptime, optical readings, ...).
    ``specs`` overrides the global registry (mostly for tests). Never raises on valid objects.
    """
    table = _REGISTRY if specs is None else specs
    a = _index(objects_of(old), table)
    b = _index(objects_of(new), table)
    changes: list[ObjectChange] = []
    for (kind, key), obj in a.items():
        other = b.get((kind, key))
        if other is None:
            changes.append(ObjectChange(kind, key, "removed", old_ref=obj.ref, old=_dump(obj)))
            continue
        change = _compare_objects(kind, key, obj, other, table.get(kind), include_volatile)
        if change is not None:
            changes.append(change)
    for (kind, key), obj in b.items():
        if (kind, key) not in a:
            changes.append(ObjectChange(kind, key, "added", new_ref=obj.ref, new=_dump(obj)))
    changes.sort(key=lambda c: (_kind_rank(c.kind), c.key))
    return SemanticDiff(tuple(changes))
