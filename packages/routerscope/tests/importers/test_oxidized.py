from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from routerscope.capture.importers import Importer, ImportError_, OxidizedImporter
from routerscope.capture.importers.oxidized import parse_model_file
from routerscope.services.ingest import ingest
from routerscope.storage import Store

Make = Callable[[str], Any]
Cfg = Callable[..., str]


def test_single_repo_flat_and_grouped_files(cfg: Cfg, make_repo: Make) -> None:
    repo = make_repo("oxi")
    repo.write("edge-1", cfg("edge-1", 1))
    repo.write("core/core-1", cfg("core-1", 1))
    repo.write("bad name", cfg("x", 1))
    repo.write(".gitignore", "tmp\n")
    sha = repo.commit("2026-03-01T08:00:00+02:00")
    repo.write("edge-1", cfg("edge-1", 2))
    repo.commit("2026-03-02T08:00:00+02:00")
    importer = OxidizedImporter(repo.path)
    assert isinstance(importer, Importer)
    items = list(importer.items())
    assert [i.hostname for i in items] == [None, "core-1", "edge-1", "edge-1"]
    assert all(i.kind == "config" and i.vendor is None for i in items)
    first = items[1]
    assert first.captured_at == datetime(2026, 3, 1, 6, 0, tzinfo=UTC)
    assert first.source.kind == "oxidized"
    assert first.source.importer == "oxidized"
    assert first.source.git_commit == sha
    assert first.source.uri == str(repo.path.resolve())
    assert first.content == cfg("core-1", 1)


def test_group_layout_one_repo_per_group(cfg: Cfg, make_repo: Make, tmp_path: Path) -> None:
    core = make_repo("groups/core")
    core.write("c1", cfg("c1", 1))
    core.commit("2026-03-01T00:00:00+00:00")
    edge = make_repo("groups/edge")
    edge.write("e1", cfg("e1", 1))
    edge.commit("2026-03-01T00:00:00+00:00")
    bare = tmp_path / "groups" / "zeta.git"
    edge.git("clone", "-q", "--bare", str(edge.path), str(bare))
    (tmp_path / "groups" / "notes").mkdir()
    (tmp_path / "groups" / "file.txt").write_text("x", encoding="utf-8")
    items = list(OxidizedImporter(tmp_path / "groups", layout="group").items())
    assert [(i.hostname, Path(i.source.uri).name) for i in items] == [
        ("c1", "core"),
        ("e1", "edge"),
        ("e1", "zeta.git"),
    ]


def test_group_layout_errors(tmp_path: Path) -> None:
    with pytest.raises(ImportError_, match="not a directory"):
        list(OxidizedImporter(tmp_path / "nope", layout="group").items())
    with pytest.raises(ImportError_, match="no group repositories"):
        list(OxidizedImporter(tmp_path, layout="group").items())
    with pytest.raises(ValueError, match="layout"):
        OxidizedImporter(tmp_path, layout="other")  # type: ignore[arg-type]


def test_vendor_mapping(cfg: Cfg, make_repo: Make, tmp_path: Path) -> None:
    repo = make_repo("oxi")
    for name in ("r-ios", "R-XR", "r-vrp", "r-unknown", "r-vendor", "r-default"):
        repo.write(name, cfg(name, 1))
    repo.commit()
    model_file = tmp_path / "router.db"
    model_file.write_text(
        "# comment\nr-ios:ios\nr-xr;192.0.2.7;iosxr;core\nr-vrp,vrp\nr-unknown:frobnicator\n"
        "onlyname\n",
        encoding="utf-8",
    )
    importer = OxidizedImporter(
        repo.path,
        model_file=model_file,
        model_map={"r-vendor": "nokia_sros"},
        default_model="junos",
    )
    vendors = {i.hostname: i.vendor for i in importer.items()}
    assert vendors == {
        "r-ios": "cisco_ios",
        "R-XR": "cisco_xr",
        "r-vrp": "huawei_vrp",
        "r-unknown": None,  # listed with an unknown model: no vendor, ingestion detects
        "r-vendor": "nokia_sros",
        "r-default": "juniper_junos",
    }


def test_no_mapping_means_no_vendor(cfg: Cfg, make_repo: Make) -> None:
    repo = make_repo("oxi")
    repo.write("r1", cfg("r1", 1))
    repo.commit()
    assert [i.vendor for i in OxidizedImporter(repo.path, model_map={"r1": "x"}).items()] == [None]
    assert [i.vendor for i in OxidizedImporter(repo.path, model_map={"r1": ""}).items()] == [None]


def test_parse_model_file(tmp_path: Path) -> None:
    path = tmp_path / "m"
    path.write_text("a:ios\nb;c;vrp\n\n# x\nsolo\n", encoding="utf-8")
    assert parse_model_file(path) == {"a": "ios", "b": "vrp"}
    with pytest.raises(ImportError_, match="cannot read model file"):
        parse_model_file(tmp_path / "missing")


def test_filters(cfg: Cfg, make_repo: Make) -> None:
    repo = make_repo("oxi")
    for day in (1, 2, 3):
        repo.write("a", cfg("a", day))
        repo.write("b", cfg("b", day))
        repo.commit(f"2026-03-0{day}T00:00:00+00:00")
    items = OxidizedImporter(
        repo.path,
        since=datetime(2026, 3, 2, tzinfo=UTC),
        until=datetime(2026, 3, 2, tzinfo=UTC),
        paths=["a"],
    ).items()
    assert [(i.hostname, i.captured_at.day) for i in items] == [("a", 2)]


def test_end_to_end_history_in_time_order(cfg: Cfg, make_repo: Make) -> None:
    repo = make_repo("oxi")
    # commit order differs from nothing: three revisions at +02:00 and -05:00 offsets
    repo.write("edge-1", cfg("edge-1", 1))
    repo.commit("2026-04-01T10:00:00+02:00")
    repo.write("edge-1", cfg("edge-1", 2))
    repo.commit("2026-04-02T10:00:00-05:00")
    repo.write("edge-1", cfg("edge-1", 3))
    repo.commit("2026-04-03T10:00:00+00:00")
    with Store.open(":memory:", redactor=lambda text, vendor=None: text) as store:
        report = ingest(store, OxidizedImporter(repo.path).items())
        assert report.stored == 3
        assert report.errors == []
        history = store.history("edge-1")
        assert [s.captured_at for s in history] == sorted(s.captured_at for s in history)
        assert len(history) == 3
        assert all(s.source.kind == "oxidized" and s.source.git_commit for s in history)
        texts = [store.get_content(s.id) for s in history]
        assert texts == [cfg("edge-1", n) for n in (1, 2, 3)]
