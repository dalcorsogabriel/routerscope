from __future__ import annotations

import shutil
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from routerscope.capture.importers import ImportError_, walk_history
from routerscope.capture.importers import git_history as gh

Make = Callable[[str], Any]
Cfg = Callable[..., str]


def test_versions_oldest_first_with_committer_offsets(cfg: Cfg, make_repo: Make) -> None:
    repo = make_repo("r")
    repo.write("r1", cfg("r1", 1))
    first = repo.commit("2026-01-10T10:00:00+02:00")
    repo.write("r1", cfg("r1", 2))
    second = repo.commit("2026-01-11T09:30:00-05:00")
    versions = list(walk_history(repo.path))
    assert [v.commit for v in versions] == [first, second]
    assert [v.content for v in versions] == [cfg("r1", 1), cfg("r1", 2)]
    assert versions[0].committed_at == datetime(2026, 1, 10, 8, 0, tzinfo=UTC)
    assert versions[0].committed_at.utcoffset() == timedelta(hours=2)
    assert versions[1].committed_at.utcoffset() == timedelta(hours=-5)
    assert {v.path for v in versions} == {"r1"}


def test_deleted_renamed_and_binary_files(cfg: Cfg, make_repo: Make) -> None:
    repo = make_repo("r")
    repo.write("old", cfg("old", 1))
    repo.write("blob.bin", b"\x00\x01\x02binary")
    repo.commit("2026-01-01T00:00:00+00:00")
    repo.git("mv", "old", "new")
    repo.commit("2026-01-02T00:00:00+00:00")
    repo.remove("new")
    repo.commit("2026-01-03T00:00:00+00:00")
    # the rename is a new file; the deletion and the binary file yield nothing
    assert [v.path for v in walk_history(repo.path)] == ["old", "new"]


def test_symlink_and_submodule_entries_are_skipped(cfg: Cfg, make_repo: Make) -> None:
    repo = make_repo("r")
    repo.write("real", cfg("real", 1))
    blob = repo.git("hash-object", "-w", "real")
    repo.git("update-index", "--add", "--cacheinfo", f"100644,{blob},real")
    repo.git("update-index", "--add", "--cacheinfo", f"120000,{blob},link")
    repo.git("update-index", "--add", "--cacheinfo", f"160000,{'1' * 40},sub")
    repo.git("commit", "-q", "-m", "x", when="2026-01-01T00:00:00+00:00")
    assert [v.path for v in walk_history(repo.path)] == ["real"]


def test_unicode_and_space_names_and_byte_exact_content(make_repo: Make) -> None:
    repo = make_repo("r")
    crlf = "hostname x\r\nend\r\n"
    repo.write("área 1/roteador é.cfg", crlf)
    repo.commit()
    (version,) = walk_history(repo.path)
    assert version.path == "área 1/roteador é.cfg"
    assert version.content == crlf


def test_non_utf8_text_is_returned_as_bytes(make_repo: Make) -> None:
    repo = make_repo("r")
    repo.write("r1", b"description caf\xe9\n")
    repo.commit()
    (version,) = walk_history(repo.path)
    assert version.content == b"description caf\xe9\n"


def test_since_until_and_paths(cfg: Cfg, make_repo: Make) -> None:
    repo = make_repo("r")
    repo.fast_import(
        [
            (
                datetime(2026, 2, day, 12, tzinfo=UTC),
                {"a.cfg": cfg("a", day), "b.txt": cfg("b", day)},
            )
            for day in (1, 2, 3, 4)
        ]
    )
    got = [
        v.committed_at.day
        for v in walk_history(
            repo.path,
            since=datetime(2026, 2, 2, 12, 0, tzinfo=UTC),
            until=datetime(2026, 2, 3, 12, 0),  # naive means UTC
            paths=["*.cfg"],
        )
    ]
    assert got == [2, 3]


def test_empty_repository_yields_nothing(make_repo: Make) -> None:
    assert list(walk_history(make_repo("r").path)) == []


def test_head_pointing_nowhere_is_an_error(make_repo: Make, tmp_path: Path) -> None:
    repo = make_repo("r")
    repo.write("r1", "x\n")
    repo.commit()
    bare = tmp_path / "bare.git"
    repo.git("clone", "-q", "--bare", str(repo.path), str(bare))
    repo.git("--git-dir", str(bare), "symbolic-ref", "HEAD", "refs/heads/nope")
    with pytest.raises(ImportError_, match="HEAD"):
        list(walk_history(bare))
    assert [v.path for v in walk_history(bare, ref="main")] == ["r1"]


def test_bare_repository_and_ref(make_repo: Make, tmp_path: Path) -> None:
    repo = make_repo("r")
    repo.write("r1", "one\n")
    repo.commit()
    repo.git("tag", "v1")
    repo.write("r1", "two\n")
    repo.commit()
    bare = tmp_path / "bare.git"
    repo.git("clone", "-q", "--bare", str(repo.path), str(bare))
    assert len(list(walk_history(bare))) == 2
    assert [v.content for v in walk_history(bare, ref="v1")] == ["one\n"]


def test_merges_follow_first_parent(make_repo: Make) -> None:
    repo = make_repo("r")
    repo.write("a", "a1\n")
    repo.commit("2026-01-01T00:00:00+00:00")
    repo.git("checkout", "-q", "-b", "side")
    repo.write("b", "b1\n")
    repo.commit("2026-01-02T00:00:00+00:00", "side")
    repo.git("checkout", "-q", "main")
    repo.write("a", "a2\n")
    repo.commit("2026-01-03T00:00:00+00:00")
    repo.git("merge", "-q", "--no-ff", "side", "-m", "merge", when="2026-01-04T00:00:00+00:00")
    seen = [(v.path, v.committed_at.day) for v in walk_history(repo.path)]
    assert seen == [("a", 1), ("a", 3), ("b", 4)]  # b appears once, at the merge


def test_subdirectory_paths_are_relative(make_repo: Make) -> None:
    repo = make_repo("r")
    repo.write("grp/configs/r1", "x\n")
    repo.write("other/r2", "y\n")
    repo.commit()
    assert [v.path for v in walk_history(repo.path / "grp")] == ["configs/r1"]


def test_large_blob_skipped(make_repo: Make) -> None:
    repo = make_repo("r")
    repo.write("big", "x" * 200_000)
    repo.write("small", "y\n")
    repo.commit()
    assert [v.path for v in walk_history(repo.path, max_blob_bytes=1000)] == ["small"]


def test_early_close_stops_processes(cfg: Cfg, make_repo: Make) -> None:
    repo = make_repo("r")
    for i in range(3):
        repo.write("r1", cfg("r1", i))
        repo.commit(f"2026-01-0{i + 1}T00:00:00+00:00")
    it = walk_history(repo.path)
    next(it)
    it.close()


def test_errors(make_repo: Make, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(ImportError_, match="not a git repository"):
        list(walk_history(plain))
    with pytest.raises(ImportError_, match="not a directory"):
        list(walk_history(tmp_path / "missing"))
    repo = make_repo("r")
    repo.write("r1", "x\n")
    repo.commit()
    for bad in ("--output=evil", "-x", "a..b", "a b", ""):
        with pytest.raises(ImportError_, match="invalid git ref"):
            list(walk_history(repo.path, ref=bad))
    with pytest.raises(ImportError_, match="unknown git ref"):
        list(walk_history(repo.path, ref="nosuch"))
    assert not gh.is_git_repository(tmp_path / "missing")
    assert gh.is_git_repository(repo.path)
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(ImportError_, match="git executable"):
        list(walk_history(repo.path))


def test_git_cannot_be_started(make_repo: Make, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = make_repo("r")

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("nope")

    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(ImportError_, match="cannot run git"):
        list(walk_history(repo.path))


def test_log_failure_is_reported(make_repo: Make, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = make_repo("r")
    repo.write("r1", "x\n")
    repo.commit()
    real = gh._base_cmd
    calls = {"n": 0}

    def flaky(root: Path) -> list[str]:
        calls["n"] += 1
        cmd = real(root)
        # the third call builds the streaming `git log` command line: break it
        return [*cmd, "--bogus-option"] if calls["n"] == 3 else cmd

    monkeypatch.setattr(gh, "_base_cmd", flaky)
    with pytest.raises(ImportError_, match="git log failed"):
        list(walk_history(repo.path))


def test_read_blob_missing_object(make_repo: Make) -> None:
    repo = make_repo("r")
    repo.write("r1", "x\n")
    repo.commit()
    proc = subprocess.Popen(
        [*gh._base_cmd(repo.path), "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    try:
        assert gh._read_blob(proc, "1" * 40, 100) is None
    finally:
        assert proc.stdin and proc.stdout
        proc.stdin.close()
        proc.stdout.close()
        proc.wait()


def test_300_commits_smoke(cfg: Cfg, make_repo: Make) -> None:
    repo = make_repo("r")
    start = datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=-3)))
    repo.fast_import(
        [(start + timedelta(minutes=i), {f"r{i % 5}": cfg(f"r{i % 5}", i)}) for i in range(300)]
    )
    began = time.perf_counter()
    versions = list(walk_history(repo.path))
    assert len(versions) == 300
    assert versions[0].committed_at < versions[-1].committed_at
    assert versions[0].committed_at.utcoffset() == timedelta(hours=-3)
    assert versions[-1].content == cfg("r4", 299)
    assert time.perf_counter() - began < 30
