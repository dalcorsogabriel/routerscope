from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from routerscope.capture.importers import Importer, ImportError_, PasteImporter, SessionLogImporter
from routerscope.capture.importers._common import config_hostname, decode_bytes, looks_like_config
from routerscope.services.ingest import ingest
from routerscope.storage import Redactor, Store

Stage = Callable[..., Path]
TZ = timezone(timedelta(hours=-3))
WHEN = datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC)


def test_paste_session(data_dir: Path) -> None:
    text = (data_dir / "securecrt.log").read_text(encoding="utf-8")
    items = list(PasteImporter(text, tz=TZ).items())
    assert items[0].kind == "session"
    assert [i.command for i in items[1:]] == [
        "display version",
        "display ip interface brief",
        "display bgp peer",
    ]
    assert {i.source.kind for i in items} == {"paste"}
    assert {i.source.importer for i in items} == {"paste"}
    assert items[1].captured_at == datetime(2026, 1, 5, 10, 22, 1, tzinfo=TZ)


def test_paste_session_overrides_and_default_time() -> None:
    items = list(
        PasteImporter("R1#show clock\n10:00:00 UTC\n", hostname="edge", vendor="x").items()
    )
    assert items[1].hostname == "edge"
    assert items[1].vendor == "x"
    assert abs(items[1].captured_at - datetime.now(UTC)) < timedelta(minutes=1)


def test_paste_config(data_dir: Path) -> None:
    text = (data_dir / "running-config.cfg").read_text(encoding="utf-8")
    (item,) = PasteImporter(text, captured_at=WHEN).items()
    assert item.kind == "config"
    assert item.hostname == "PE1"
    assert item.captured_at == WHEN
    assert item.command is None


def test_paste_command_output_needs_command() -> None:
    text = "Neighbor  AS  State\n192.0.2.2  64497  Established\n"
    with pytest.raises(ImportError_, match=r"command=\.\.\."):
        list(PasteImporter(text).items())
    with pytest.raises(ImportError_, match=r"command=\.\.\."):
        list(PasteImporter(text, kind="command_output").items())
    (item,) = PasteImporter(text, command="show bgp summary", hostname="PE1").items()
    assert (item.kind, item.command, item.hostname) == ("command_output", "show bgp summary", "PE1")


def test_paste_kind_forced() -> None:
    (item,) = PasteImporter("interface Gi0/0\n", kind="config", hostname="R1").items()
    assert item.kind == "config"
    (sess,) = PasteImporter("just notes", kind="session").items()
    assert sess.kind == "session"


def test_paste_cleans_ansi() -> None:
    (item,) = PasteImporter("\x1b[1mup\x1b[0m 192.0.2.1\r\n", command="show x").items()
    assert item.content == "up 192.0.2.1\n"


def test_paste_validation() -> None:
    with pytest.raises(ImportError_, match="empty"):
        list(PasteImporter("  \n").items())
    with pytest.raises(ValueError, match="unknown kind"):
        PasteImporter("x", kind="nope")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="timezone-aware"):
        PasteImporter("x", captured_at=datetime(2026, 1, 1))


def test_importers_satisfy_the_protocol(tmp_path: Path) -> None:
    assert isinstance(PasteImporter("x"), Importer)
    assert isinstance(SessionLogImporter(tmp_path / "a.log"), Importer)


def test_looks_like_config_and_hostnames() -> None:
    assert looks_like_config("hostname A\ninterface x\nrouter bgp 1\n")
    assert not looks_like_config("Name  Value\nfoo  bar\n")
    assert not looks_like_config("interface x\n")  # one line, no vendor recognises it
    assert looks_like_config("interface x\nCisco IOS Software, Version 17\n")
    assert config_hostname("sysname R2\n") == "R2"
    assert config_hostname("set system host-name PE1\n") == "PE1"
    assert config_hostname("system {\n    host-name PE9;\n}\n") == "PE9"
    assert config_hostname("/system identity\nset name=edge1\n") == "edge1"
    assert config_hostname("nothing here") is None


# -- encodings -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "encode",
    [
        lambda t: t.encode("utf-8"),
        lambda t: b"\xef\xbb\xbf" + t.encode("utf-8"),
        lambda t: b"\xff\xfe" + t.encode("utf-16-le"),
        lambda t: b"\xfe\xff" + t.encode("utf-16-be"),
        lambda t: t.encode("utf-16-le"),  # PowerShell 5.1 style without BOM
        lambda t: t.encode("utf-16-be"),
    ],
    ids=["utf8", "utf8-bom", "utf16-bom-le", "utf16-bom-be", "utf16-le", "utf16-be"],
)
def test_encodings_give_identical_items(
    encode: Callable[[str], bytes], stage: Stage, data_dir: Path
) -> None:
    text = (data_dir / "securecrt.log").read_text(encoding="utf-8").replace("\n", "\r\n")
    items = list(SessionLogImporter(stage("enc.log", encode(text)), tz=TZ).items())
    assert next(i.command for i in items[1:]) == "display version"
    assert items[0].content.startswith("<R1>display version\n")
    assert "\x00" not in items[0].content
    assert items[0].captured_at == datetime(2026, 1, 5, 10, 22, 1, tzinfo=TZ)


def test_invalid_utf8_is_replaced_with_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        assert decode_bytes(b"R1# caf\xe9\n") == "R1# caf�\n"
    assert "not valid UTF-8" in caplog.text


# -- end to end ------------------------------------------------------------------------------


def test_end_to_end_ingest_and_search(stage: Stage, redactor: Redactor) -> None:
    path = stage("securecrt.log")
    with Store.open(":memory:", redactor=redactor) as store:
        report = ingest(store, SessionLogImporter(path, tz=TZ).items())
        assert report.errors == []
        assert report.stored == 4
        hits = store.search_text("192.0.2.2", kind="command_output")
        assert len(hits) == 1
        assert hits[0].command == "display bgp peer"
        assert hits[0].hostname == "R1"
        assert hits[0].captured_at == datetime(2026, 1, 5, 10, 22, 11, tzinfo=TZ)
        assert store.search_text("Established", kind="session")
