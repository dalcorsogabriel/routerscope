"""The over-time service end to end: real vendor plugins, in-memory store."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from routerscope.capture.importers.base import ImportItem
from routerscope.model import Source
from routerscope.services.diff import (
    ConfigDiff,
    LineDiff,
    changes,
    diff_device,
    diff_lines,
    diff_snapshots,
)
from routerscope.services.ingest import ingest
from routerscope.storage import Store
from routerscope.storage.errors import InvalidInputError, UnknownSnapshotError

T0 = datetime(2026, 11, 1, 8, 0, tzinfo=UTC)
SRC = Source(kind="paste", uri="memory://diff", importer="test")


def redact(text: str, vendor: str | None = None) -> str:
    return re.sub(r"(password 7 )\S+", r"\1<redacted>", text)


def cfg(description: str, *, clock: int = 1, extra: str = "") -> str:
    return f"""\
Building configuration...
!
hostname R1
!
interface GigabitEthernet0/0/1
 description {description}
 ip address 192.0.2.1 255.255.255.252
!
router bgp 64496
 neighbor 192.0.2.2 remote-as 64497
!
{extra}ntp clock-period {clock}
end
"""


def item(
    content: str,
    minutes: int,
    *,
    kind: str = "config",
    command: str | None = None,
    hostname: str = "R1",
    vendor: str | None = "cisco_ios",
) -> ImportItem:
    return ImportItem(
        content=content,
        kind=kind,  # type: ignore[arg-type]
        captured_at=T0 + timedelta(minutes=minutes),
        source=SRC,
        hostname=hostname,
        vendor=vendor,
        command=command,
    )


@pytest.fixture
def store() -> Iterator[Store]:
    with Store.open(":memory:", redactor=redact) as s:
        yield s


@pytest.fixture
def history(store: Store) -> dict[str, str]:
    """v1 -> v2 (description) -> v3 (only the volatile clock line) -> v4 (BGP neighbor added)."""
    texts = {
        "v1": cfg("uplink"),
        "v2": cfg("uplink to PE1"),
        "v3": cfg("uplink to PE1", clock=2),
        "v4": cfg("uplink to PE1", clock=3).replace(
            " neighbor 192.0.2.2 remote-as 64497\n",
            " neighbor 192.0.2.2 remote-as 64497\n neighbor 198.51.100.2 remote-as 64498\n",
        ),
    }
    report = ingest(store, [item(t, i * 10) for i, t in enumerate(texts.values())])
    assert report.errors == [] and report.parsed == 4
    ids = {name: sid for name, sid in zip(texts, report.snapshot_ids, strict=True)}
    return ids


def test_diff_snapshots_has_semantic_and_hierarchical_parts(
    store: Store, history: dict[str, str]
) -> None:
    result = diff_snapshots(store, history["v1"], history["v2"])
    assert isinstance(result.text, ConfigDiff)
    assert [c.text for c in result.text.changes()] == [
        "description uplink",
        "description uplink to PE1",
    ]
    assert result.text.changes()[0].path == ("interface GigabitEthernet0/0/1",)
    assert result.semantic is not None
    (change,) = result.semantic.changes
    assert change.kind == "interface" and change.op == "changed"
    assert [(f.field, f.old, f.new) for f in change.fields] == [
        ("description", "uplink", "uplink to PE1")
    ]
    assert change.old_ref is not None and change.new_ref is not None
    assert change.old_ref.snapshot_id == history["v1"]
    assert change.new_ref.snapshot_id == history["v2"]
    assert not result.is_empty
    text = result.render_text()
    assert text.startswith("--- 2026-11-01T08:00:00Z ")
    assert "+  description uplink to PE1" in text
    data = result.to_dict()
    json.dumps(data)
    assert data["text_kind"] == "config" and data["old"]["hostname"] == "R1"  # type: ignore[index]


def test_volatile_only_change_is_empty(store: Store, history: dict[str, str]) -> None:
    result = diff_snapshots(store, history["v2"], history["v3"])
    assert result.is_empty
    assert result.text.is_empty and result.semantic is not None and result.semantic.is_empty


def test_diff_device_defaults_to_previous_vs_latest(store: Store, history: dict[str, str]) -> None:
    result = diff_device(store, "r1")  # hostname matching is case-insensitive
    assert result is not None
    assert (result.old.id, result.new.id) == (history["v3"], history["v4"])
    assert result.semantic is not None
    assert [(c.kind, c.op) for c in result.semantic.changes] == [("bgp_peer", "added")]
    assert [c.op for c in result.text.changes()] == ["added"]  # type: ignore[union-attr]


def test_diff_device_at_until_since(store: Store, history: dict[str, str]) -> None:
    at = diff_device(store, "R1", at=T0 + timedelta(minutes=12))
    assert at is not None and (at.old.id, at.new.id) == (history["v1"], history["v2"])
    until = diff_device(store, "R1", until=T0 + timedelta(minutes=25))
    assert until is not None and (until.old.id, until.new.id) == (history["v2"], history["v3"])
    since = diff_device(store, "R1", since=T0 + timedelta(minutes=5))
    assert since is not None and (since.old.id, since.new.id) == (history["v1"], history["v4"])
    # nothing known at ``since``: the earliest version is the baseline
    early = diff_device(store, "R1", since=T0 - timedelta(days=1))
    assert early is not None and early.old.id == history["v1"]
    bounded = diff_device(
        store, "R1", since=T0 + timedelta(minutes=12), until=T0 + timedelta(minutes=25)
    )
    assert bounded is not None and (bounded.old.id, bounded.new.id) == (
        history["v2"],
        history["v3"],
    )
    # ``at`` before any capture, one version only
    assert diff_device(store, "R1", at=T0 - timedelta(minutes=1)) is None
    assert diff_device(store, "R1", at=T0 + timedelta(minutes=1)) is None
    assert diff_device(store, "R1", until=T0) is None


def test_diff_device_unknown_host_and_other_kinds(store: Store, history: dict[str, str]) -> None:
    assert diff_device(store, "nobody") is None
    assert diff_device(store, "R1", command="show version") is None
    with pytest.raises(InvalidInputError):
        diff_device(store, "")


def test_changes_timeline_skips_noise(store: Store, history: dict[str, str]) -> None:
    timeline = list(changes(store, "R1"))
    assert [(d.old.id, d.new.id) for d in timeline] == [
        (history["v1"], history["v2"]),
        (history["v3"], history["v4"]),
    ]
    everything = list(changes(store, "R1", include_empty=True))
    assert len(everything) == 3 and everything[1].is_empty
    since = list(changes(store, "R1", since=T0 + timedelta(minutes=15), include_empty=True))
    assert [(d.old.id, d.new.id) for d in since] == [
        (history["v2"], history["v3"]),
        (history["v3"], history["v4"]),
    ]
    until = list(changes(store, "R1", until=T0 + timedelta(minutes=15)))
    assert len(until) == 1
    late = list(changes(store, "R1", since=T0 + timedelta(days=1)))
    assert late == []
    early = list(changes(store, "R1", since=T0 - timedelta(days=1)))
    assert len(early) == 2
    assert list(changes(store, "nobody")) == []


def test_reobserved_and_reverted_content(store: Store) -> None:
    a, b = cfg("one"), cfg("two")
    ingest(store, [item(a, 0), item(a, 5), item(b, 10), item(a, 20), item(a, 30)])
    result = diff_device(store, "R1")
    assert result is not None
    # latest is A again (observed twice); the previous *different* version is B
    assert result.old.captured_at == T0 + timedelta(minutes=10)
    assert result.new.captured_at == T0 + timedelta(minutes=30)
    timeline = list(changes(store, "R1"))
    assert len(timeline) == 2  # A->B and B->A; the repeated observations are collapsed
    assert timeline[0].new.id == timeline[1].old.id


def test_semantic_is_none_without_parsed_data(store: Store) -> None:
    ingest(store, [item(cfg("a"), 0), item(cfg("b"), 10)], parse=False)
    result = diff_device(store, "R1")
    assert result is not None and result.semantic is None and not result.is_empty
    assert result.to_dict()["semantic"] is None
    # vendor unknown: no semantic either, and the diff falls back to indentation parsing
    ingest(
        store,
        [
            item("hostname X\n a\n", 0, hostname="X", vendor=None),
            item("hostname X\n b\n", 5, hostname="X", vendor=None),
        ],
        parse=False,
    )
    anon = diff_device(store, "X")
    assert anon is not None and anon.semantic is None


def test_command_output_uses_line_diff(store: Store) -> None:
    out1 = "Interface  Status\nGi0/0/1  up   uptime 1d\nGi0/0/2  down\n"
    out2 = "Interface  Status\nGi0/0/1  up   uptime 2d\nGi0/0/2  up\n"
    cmd = "show interfaces status"
    ingest(
        store,
        [
            item(out1, 0, kind="command_output", command=cmd),
            item(out2, 10, kind="command_output", command=cmd),
        ],
    )
    result = diff_device(store, "R1", command=cmd)
    assert result is not None and isinstance(result.text, LineDiff)
    assert result.semantic is None  # no stored parse result for this command
    assert [(c.op, c.text) for c in result.text.changes] == [
        ("removed", "Gi0/0/1  up   uptime 1d"),
        ("removed", "Gi0/0/2  down"),
        ("added", "Gi0/0/1  up   uptime 2d"),
        ("added", "Gi0/0/2  up"),
    ]
    quiet = diff_device(store, "R1", command=cmd, ignore_lines=[r"uptime \d+d"])
    assert quiet is not None
    assert [c.text for c in quiet.text.changes] == ["Gi0/0/2  down", "Gi0/0/2  up"]
    assert quiet.render_text().startswith("--- ")
    assert json.dumps(result.to_dict())
    assert result.to_dict()["text_kind"] == "lines"


def test_command_output_semantic_when_parse_result_exists(store: Store) -> None:
    """A plugin that parses a command yields a semantic diff for it."""
    from routerscope.model import Interface, ParseResult, Snapshot, SourceRef
    from routerscope.vendors import BaseVendorPlugin, VendorRegistry

    class Plugin(BaseVendorPlugin):
        id = "cisco_ios"
        name = "test"

        def parse_command(self, command: str, output: str, snapshot: Snapshot) -> ParseResult:
            ref = SourceRef(snapshot_id=snapshot.id, line_start=1, line_end=1)
            enabled = "up" in output
            return ParseResult(
                snapshot_id=snapshot.id,
                command=command,
                vendor=self.id,
                objects=(Interface(ref=ref, name="Gi0/0/1", enabled=enabled),),
            )

    registry = VendorRegistry()
    assert registry.register(Plugin())
    cmd = "show interfaces"
    ingest(
        store,
        [
            item("Gi0/0/1 down\n", 0, kind="command_output", command=cmd),
            item("Gi0/0/1 up\n", 5, kind="command_output", command=cmd),
        ],
        registry=registry,
    )
    result = diff_device(store, "R1", command=cmd)
    assert result is not None and result.semantic is not None
    (change,) = result.semantic.changes
    assert [(f.field, f.old, f.new) for f in change.fields] == [("enabled", False, True)]


def test_errors(store: Store, history: dict[str, str]) -> None:
    with pytest.raises(UnknownSnapshotError):
        diff_snapshots(store, "f" * 64, history["v1"])
    with pytest.raises(UnknownSnapshotError):
        diff_snapshots(store, history["v1"], "f" * 64)
    ingest(store, [item("out\n", 50, kind="command_output", command="show x")])
    other = store.history("R1", "command_output")[0].id
    with pytest.raises(ValueError, match="cannot diff"):
        diff_snapshots(store, history["v1"], other)


def test_session_snapshots_and_diff_lines_helper(store: Store) -> None:
    ingest(
        store,
        [
            item("R1# show clock\n10:00\nR1#\n", 0, kind="session"),
            item("R1# show clock\n10:05\nR1#\n", 5, kind="session"),
        ],
    )
    result = diff_device(store, "R1", kind="session")
    assert result is not None and isinstance(result.text, LineDiff)
    assert "+10:05" in result.render_text()


def test_line_diff_rendering_and_options() -> None:
    old = "\n".join(f"line {i}" for i in range(1, 21))
    new = old.replace("line 10", "line TEN")
    diff = diff_lines(old, new)
    text = diff.render_text(context=1)
    assert text.splitlines() == [
        "--- old",
        "+++ new",
        "...",
        " line 9",
        "-line 10",
        "+line TEN",
        " line 11",
        "...",
    ]
    assert diff.to_dict()["added"] == 1 and diff.to_dict()["removed"] == 1
    assert diff_lines("a  b\n", "a b \n").is_empty
    assert not diff_lines("a  b\n", "a b \n", ignore_whitespace=False).is_empty
    assert diff_lines("x\n", "x\n").render_text() == ""
    assert diff_lines("x\nignore me 1\n", "x\nignore me 2\n", ignore=["ignore me"]).is_empty
