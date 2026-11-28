"""Helpers that build throwaway git repositories with the git CLI (never global config)."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

import pytest

GIT = shutil.which("git")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Skip every importer test when git is not installed."""
    if GIT is None:
        marker = pytest.mark.skip(reason="git is not installed")
        for item in items:
            if "importers" in item.path.parts:
                item.add_marker(marker)


NL = bytes([10])
NLS = chr(10)
T0 = "2026-01-10T10:00:00+02:00"


class Repo:
    """A repository in ``path``; commits get explicit dates with UTC offsets."""

    def __init__(self, path: Path, *, init: bool = True) -> None:
        self.path = path
        path.mkdir(parents=True, exist_ok=True)
        if init:
            self.git("init", "-q", "-b", "main")
            self.git("config", "core.autocrlf", "false")
            self.git("config", "core.safecrlf", "false")

    def git(self, *args: str, when: str | None = None) -> str:
        assert GIT is not None
        env = {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        }
        if when:
            env["GIT_AUTHOR_DATE"] = when
            env["GIT_COMMITTER_DATE"] = when
        done = subprocess.run(
            [GIT, "-C", str(self.path), *args],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
        return done.stdout.strip()

    def write(self, rel: str, data: str | bytes) -> None:
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)

    def remove(self, rel: str) -> None:
        (self.path / rel).unlink()

    def fast_import(self, commits: list[tuple[datetime, dict[str, str]]]) -> None:
        """Create many commits on ``main`` with one ``git fast-import`` process.

        Each item is (committer time with UTC offset, {path: content}).
        """
        assert GIT is not None
        out = bytearray()

        def data(raw: bytes) -> None:
            out.extend(b"data %d" % len(raw) + NL + raw + NL)

        for when, files in commits:
            offset = when.utcoffset() or timedelta(0)
            minutes = int(offset.total_seconds() // 60)
            sign = "+" if minutes >= 0 else "-"
            tz = f"{sign}{abs(minutes) // 60:02d}{abs(minutes) % 60:02d}"
            stamp = f"Test <test@example.com> {int(when.timestamp())} {tz}"
            out.extend(f"commit refs/heads/main{NLS}committer {stamp}{NLS}".encode())
            data(b"change")
            for path, content in files.items():
                out.extend(f"M 100644 inline {path}{NLS}".encode())
                data(content.encode("utf-8"))
        subprocess.run(
            [GIT, "-C", str(self.path), "fast-import", "--quiet"],
            input=bytes(out),
            check=True,
            capture_output=True,
        )

    def commit(self, when: str = T0, message: str = "change") -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message, when=when)
        return self.git("rev-parse", "HEAD")


@pytest.fixture
def make_repo(tmp_path: Path) -> Callable[[str], Repo]:
    def factory(name: str = "repo") -> Repo:
        return Repo(tmp_path / name)

    return factory


def _config(host: str, revision: int, extra: str = "") -> str:
    """A tiny synthetic IOS-style config (documentation addresses only)."""
    return (
        f"hostname {host}\n!\ninterface GigabitEthernet0/0\n"
        f" description rev{revision}\n ip address 192.0.2.{revision % 250 + 1} 255.255.255.0\n"
        f"!\n{extra}end\n"
    )


@pytest.fixture
def cfg() -> Callable[..., str]:
    return _config
