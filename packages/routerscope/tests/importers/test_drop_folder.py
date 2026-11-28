from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import pytest
from routerscope.capture.importers import DropFolder, Importer
from routerscope.capture.importers.base import ImportItem
from routerscope.capture.importers.drop_folder import STATE_FILE


@pytest.fixture
def drop(tmp_path: Path) -> Path:
    folder = tmp_path / "drop"
    folder.mkdir()
    return folder


def put(folder: Path, name: str, data: bytes | str, mtime: int | None = None) -> Path:
    path = folder / name
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    return path


def test_scan_imports_logs_and_configs_once(drop: Path, data_dir: Path) -> None:
    put(drop, "crt.log", (data_dir / "securecrt.log").read_bytes(), 1_767_000_000)
    put(drop, "pe1.cfg", (data_dir / "running-config.cfg").read_bytes(), 1_767_000_100)
    folder = DropFolder(drop)
    assert isinstance(folder, Importer)
    items = folder.scan()
    kinds = [i.kind for i in items]
    assert kinds == ["session", "command_output", "command_output", "command_output", "config"]
    assert {i.source.kind for i in items} == {"drop_folder"}
    assert items[0].source.importer == "securecrt"
    assert items[0].source.uri == str(drop / "crt.log")
    assert items[-1].source.importer == "drop_folder"
    assert items[-1].hostname == "PE1"
    assert items[-1].captured_at.utcoffset() is not None
    assert folder.scan() == []
    assert DropFolder(drop).scan() == []  # state survives a new instance


def test_state_file_contents_and_atomic_write(drop: Path) -> None:
    put(drop, "a.cfg", "hostname A\ninterface x\nrouter bgp 1\n")
    DropFolder(drop).scan()
    state = json.loads((drop / STATE_FILE).read_text(encoding="utf-8"))
    entry = state["files"]["a.cfg"]
    assert set(entry) == {"size", "mtime_ns", "sha256"}
    assert len(entry["sha256"]) == 64
    assert not (drop / (STATE_FILE + ".tmp")).exists()


def test_modified_file_is_imported_again_but_touch_is_not(drop: Path) -> None:
    path = put(drop, "a.cfg", "hostname A\ninterface x\nrouter bgp 1\n", 1_767_000_000)
    folder = DropFolder(drop)
    assert len(folder.scan()) == 1
    os.utime(path, (1_767_000_500, 1_767_000_500))  # touched only
    assert folder.scan() == []
    put(drop, "a.cfg", "hostname A\ninterface y\nrouter bgp 1\n", 1_767_001_000)
    items = folder.scan()
    assert len(items) == 1
    assert "interface y" in str(items[0].content)


def test_unrecognised_empty_and_ignored_files(drop: Path) -> None:
    put(drop, "notes.txt", "remember to buy cable\n")
    put(drop, "empty.log", "  \n")
    put(drop, ".hidden", "hostname A\ninterface x\nrouter bgp 1\n")
    put(drop, "x.part", "hostname A\ninterface x\nrouter bgp 1\n")
    (drop / "sub").mkdir()
    folder = DropFolder(drop)
    assert folder.scan() == []
    state = json.loads((drop / STATE_FILE).read_text(encoding="utf-8"))["files"]
    assert set(state) == {"notes.txt", "empty.log"}
    assert "neither a terminal log" in state["notes.txt"]["skipped"]
    assert folder.scan() == []  # not retried until it changes
    put(drop, "notes.txt", "hostname A\ninterface x\nrouter bgp 1\n")
    assert len(folder.scan()) == 1


def test_corrupt_state_is_ignored(drop: Path) -> None:
    (drop / STATE_FILE).write_text("{not json", encoding="utf-8")
    put(drop, "a.cfg", "hostname A\ninterface x\nrouter bgp 1\n")
    assert len(DropFolder(drop).scan()) == 1
    (drop / STATE_FILE).write_text('{"files": 3}', encoding="utf-8")
    assert len(DropFolder(drop).scan()) == 1


def test_unconsumed_items_are_not_marked(drop: Path) -> None:
    put(drop, "a.cfg", "hostname A\ninterface x\nrouter bgp 1\n")
    folder = DropFolder(drop)
    next(iter(folder.items()))  # taken but the generator is abandoned before the file ends
    assert len(folder.scan()) == 1


def test_min_age_skips_fresh_files(drop: Path) -> None:
    put(drop, "a.cfg", "hostname A\ninterface x\nrouter bgp 1\n")
    assert DropFolder(drop, min_age=3600).scan() == []
    put(drop, "old.cfg", "hostname B\ninterface x\nrouter bgp 1\n", int(time.time()) - 7200)
    assert len(DropFolder(drop, min_age=3600).scan()) == 1


def test_missing_folder_raises(tmp_path: Path) -> None:
    from routerscope.capture.importers import ImportError_

    with pytest.raises(ImportError_, match="cannot list"):
        DropFolder(tmp_path / "nope").scan()


def test_unreadable_file_is_retried(drop: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = put(drop, "a.cfg", "hostname A\ninterface x\nrouter bgp 1\n")
    real = Path.read_bytes

    def locked(self: Path) -> bytes:
        if self == path:
            raise PermissionError("locked")
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", locked)
    folder = DropFolder(drop)
    assert folder.scan() == []
    monkeypatch.setattr(Path, "read_bytes", real)
    assert len(folder.scan()) == 1


def test_watch_loop_with_stop_event(drop: Path) -> None:
    folder = DropFolder(drop)
    stop = threading.Event()
    seen: list[list[ImportItem]] = []

    def callback(items: list[ImportItem]) -> None:
        seen.append(items)
        if len(seen) == 2:
            stop.set()

    put(drop, "a.cfg", "hostname A\ninterface x\nrouter bgp 1\n")
    thread = threading.Thread(target=folder.watch, args=(callback, 0.02, stop))
    thread.start()
    deadline = time.time() + 5
    while len(seen) < 1 and time.time() < deadline:
        time.sleep(0.01)
    put(drop, "b.cfg", "hostname B\ninterface x\nrouter bgp 1\n")
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert [i[0].hostname for i in seen] == ["A", "B"]
    assert folder.scan() == []


def test_watch_returns_immediately_when_already_stopped(drop: Path) -> None:
    stop = threading.Event()
    stop.set()
    DropFolder(drop).watch(lambda items: None, 0.01, stop)


def test_failing_callback_is_retried_and_loop_survives(drop: Path) -> None:
    put(drop, "a.cfg", "hostname A\ninterface x\nrouter bgp 1\n")
    folder = DropFolder(drop)
    calls: list[int] = []

    def flaky(items: list[ImportItem]) -> None:
        calls.append(len(items))
        if len(calls) == 1:
            raise RuntimeError("store busy")

    assert folder.poll(flaky) == 0
    assert folder.poll(flaky) == 1
    assert folder.poll(flaky) == 0
    assert calls == [1, 1]


def test_file_with_mtime_slightly_in_the_future_is_imported(drop: Path) -> None:
    import time

    path = put(drop, "a.cfg", "hostname A\ninterface x\nrouter bgp 1\n")
    future = time.time() + 0.5  # Windows: a fresh file's mtime can be ahead of time.time()
    os.utime(path, (future, future))
    assert len(DropFolder(drop).scan()) == 1
