from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from routerscope.capture.importers.base import Importer, ImportItem
from routerscope.model import Device, ParsedConfig, ParseResult, Snapshot, Source, SourceRef
from routerscope.services.ingest import ingest
from routerscope.storage import Store
from routerscope.vendors import BaseVendorPlugin, VendorRegistry

T0 = datetime(2026, 1, 1, tzinfo=UTC)
SRC = Source(kind="paste", uri="paste", importer="test")


def redact(text: str, vendor: str | None = None) -> str:
    return re.sub(r"(password 7 )\S+", r"\1<redacted>", text)


class FakeIOS(BaseVendorPlugin):
    id = "cisco_ios"
    name = "Fake IOS"

    def __init__(self) -> None:
        self.seen: list[str] = []

    def detect(self, text: str) -> float:
        return 1.0 if text.startswith("hostname ") else 0.0

    def parse_config(self, text: str, snapshot: Snapshot) -> ParsedConfig:
        self.seen.append(text)
        host = text.split()[1]
        ref = SourceRef(snapshot_id=snapshot.id, line_start=1, line_end=1)
        return ParsedConfig(
            snapshot_id=snapshot.id, vendor=self.id, device=Device(ref=ref, hostname=host)
        )

    def parse_command(self, command: str, output: str, snapshot: Snapshot) -> ParseResult | None:
        if command == "boom":
            raise RuntimeError("parser bug")
        return None


@pytest.fixture
def plugin() -> FakeIOS:
    return FakeIOS()


@pytest.fixture
def registry(plugin: FakeIOS) -> VendorRegistry:
    reg = VendorRegistry()
    assert reg.register(plugin)
    return reg


@pytest.fixture
def store() -> Iterator[Store]:
    with Store.open(":memory:", redactor=redact) as s:
        yield s


def item(content: str, kind: str = "config", **kw: object) -> ImportItem:
    return ImportItem(content=content, kind=kind, captured_at=T0, source=SRC, **kw)  # type: ignore[arg-type]


def test_config_is_stored_redacted_and_parsed(
    store: Store, registry: VendorRegistry, plugin: FakeIOS
) -> None:
    report = ingest(store, [item("hostname r1\n password 7 0822455D0A16\n")], registry=registry)
    assert (report.stored, report.parsed, report.errors) == (1, 1, [])
    (sid,) = report.snapshot_ids
    assert plugin.seen == ["hostname r1\n password 7 <redacted>\n"]  # parsers see redacted text
    parsed = store.get_parsed_config(sid, plugin="cisco_ios")
    assert parsed is not None and parsed.device is not None
    assert parsed.device.hostname == "r1"
    assert store.get_snapshot(sid).vendor == "cisco_ios"  # type: ignore[union-attr]


def test_plugin_failure_is_reported_not_raised(store: Store, registry: VendorRegistry) -> None:
    items = [
        item("show x output", kind="command_output", command="boom", vendor="cisco_ios"),
        item("other output", kind="command_output", command="show clock", vendor="cisco_ios"),
    ]
    report = ingest(store, items, registry=registry)
    assert report.stored == 2
    assert report.parsed == 0
    assert report.errors == ["item 1: plugin cisco_ios failed: RuntimeError"]


def test_sessions_unknown_vendors_and_parse_off_are_only_stored(
    store: Store, registry: VendorRegistry, plugin: FakeIOS
) -> None:
    items = [
        item("R1#show clock\n", kind="session"),
        item("no vendor here\n"),
        item("hostname r2\n", vendor="acme_os"),
    ]
    report = ingest(store, items, registry=registry)
    assert (report.stored, report.parsed) == (3, 0)
    assert ingest(store, [item("hostname r3\n")], registry=registry, parse=False).parsed == 0
    assert plugin.seen == []


def test_rejected_item_is_reported(store: Store, registry: VendorRegistry) -> None:
    report = ingest(store, [item("x\n", hostname="bad host")], registry=registry)
    assert report.stored == 0
    assert report.errors and report.errors[0].startswith("item 1: rejected:")


def test_bytes_content_is_stored_without_detection(store: Store, registry: VendorRegistry) -> None:
    report = ingest(store, [item(b"hostname r1\n")], registry=registry)  # type: ignore[arg-type]
    assert (report.stored, report.parsed) == (1, 0)


def test_import_item_validation() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        ImportItem(content="x", kind="config", captured_at=datetime(2026, 1, 1), source=SRC)
    with pytest.raises(ValueError, match="needs the command"):
        ImportItem(content="x", kind="command_output", captured_at=T0, source=SRC)
    assert ImportItem(content="x", kind="config", captured_at=T0 + timedelta(hours=1), source=SRC)


def test_importer_protocol() -> None:
    class ListImporter:
        name = "list"

        def items(self) -> Iterator[ImportItem]:
            yield item("hostname r1\n")

    assert isinstance(ListImporter(), Importer)
