from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from routerscope.capture.importers import Importer, ImportError_, RancidImporter
from routerscope.capture.importers.rancid import parse_router_db

Make = Callable[[str], Any]
Cfg = Callable[..., str]


def test_parse_router_db() -> None:
    text = "# hi\nr1;cisco;up\nr2:juniper:down\n\nbroken\n;x;up\nr3;;up\n"
    assert parse_router_db(text) == {"r1": "cisco", "r2": "juniper"}


def _group(repo: Any, cfg: Cfg) -> None:
    repo.write("router.db", "r1;cisco;up\nR2:huawei:up\nr3;mikrotik;up\nr4;unknowntype;up\n")
    repo.write("configs/r1", cfg("r1", 1))
    repo.write("configs/r2", "sysname r2\n")
    repo.write("configs/r3", "# RouterOS\n")
    repo.write("configs/r4", "hostname r4\n")
    repo.write("configs/.hidden", "x\n")


def test_group_directory_is_the_repository(cfg: Cfg, make_repo: Make) -> None:
    repo = make_repo("group")
    _group(repo, cfg)
    sha = repo.commit("2026-05-01T12:00:00+02:00")
    repo.write("configs/r1", "!RANCID-CONTENT-TYPE: cisco-xr\n!\n" + cfg("r1", 2))
    repo.commit("2026-05-02T12:00:00+02:00")
    importer = RancidImporter(repo.path)
    assert isinstance(importer, Importer)
    items = list(importer.items())
    seen = [(i.hostname, i.vendor) for i in items]
    assert seen == [
        ("r1", "cisco_ios"),
        ("r2", "huawei_vrp"),
        ("r3", "mikrotik_ros7"),
        ("r4", None),
        ("r1", "cisco_xr"),  # the header of that version wins over router.db
    ]
    assert items[0].source.kind == "rancid"
    assert items[0].source.git_commit == sha
    assert items[0].captured_at == datetime(2026, 5, 1, 10, 0, tzinfo=UTC)
    assert items[4].content.startswith("!RANCID-CONTENT-TYPE")  # kept as committed


def test_base_directory_with_groups_in_one_repo(cfg: Cfg, make_repo: Make) -> None:
    repo = make_repo("base")
    repo.write("core/router.db", "c1;juniper;up\n")
    repo.write("core/configs/c1", "set system host-name c1\n")
    repo.write("edge/router.db", "e1;nokia;up\n")
    repo.write("edge/configs/e1", "# TiMOS\n")
    repo.write("edge/configs/e1.new", "tmp\n")
    repo.commit()
    items = list(RancidImporter(repo.path).items())
    assert {(i.hostname, i.vendor) for i in items} == {
        ("c1", "juniper_junos"),
        ("e1", "nokia_sros"),
        ("e1.new", None),
    }
    assert {Path(i.source.uri).name for i in items} == {"core", "edge"}
    single = list(RancidImporter(repo.path / "core").items())
    assert [i.hostname for i in single] == ["c1"]


def test_non_utf8_config_is_kept_as_bytes(make_repo: Make) -> None:
    repo = make_repo("group")
    repo.write("router.db", "r1;cisco;up\n")
    repo.write("configs/r1", b"!RANCID-CONTENT-TYPE: juniper\ndescription caf\xe9\n")
    repo.commit()
    (item,) = RancidImporter(repo.path).items()
    assert item.content == b"!RANCID-CONTENT-TYPE: juniper\ndescription caf\xe9\n"
    assert item.vendor == "juniper_junos"


def test_filters(cfg: Cfg, make_repo: Make) -> None:
    repo = make_repo("group")
    repo.write("router.db", "r1;cisco;up\n")
    for day in (1, 2, 3):
        repo.write("configs/r1", cfg("r1", day))
        repo.commit(f"2026-05-0{day}T00:00:00+00:00")
    importer = RancidImporter(repo.path, since=datetime(2026, 5, 2, tzinfo=UTC))
    assert [i.captured_at.day for i in importer.items()] == [2, 3]


def test_cvs_and_svn_are_not_supported(tmp_path: Path) -> None:
    for marker in ("CVS", ".svn"):
        group = tmp_path / marker.strip(".") / "grp"
        (group / "configs").mkdir(parents=True)
        (group / "router.db").write_text("r1;cisco;up\n", encoding="utf-8")
        (group / marker).mkdir()
        with pytest.raises(ImportError_, match="CVS or Subversion"):
            list(RancidImporter(group).items())
    base = tmp_path / "cvsbase"
    (base / "CVSROOT").mkdir(parents=True)
    (base / "g").mkdir()
    (base / "g" / "router.db").write_text("r1;cisco;up\n", encoding="utf-8")
    with pytest.raises(ImportError_, match="CVS or Subversion"):
        list(RancidImporter(base).items())


def test_other_errors(tmp_path: Path) -> None:
    with pytest.raises(ImportError_, match="not a directory"):
        list(RancidImporter(tmp_path / "missing").items())
    with pytest.raises(ImportError_, match=r"no router\.db"):
        list(RancidImporter(tmp_path).items())
    group = tmp_path / "plain" / "g"
    group.mkdir(parents=True)
    (group / "router.db").write_text("r1;cisco;up\n", encoding="utf-8")
    with pytest.raises(ImportError_, match="not inside a git repository"):
        list(RancidImporter(group).items())
