"""Shared fixtures for the importer tests (sibling imports do not work in importlib mode).

The git helpers build throwaway repositories with the git CLI (never global config).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from routerscope.capture.importers.base import ImportItem
from routerscope.storage import Redactor

DATA = Path(__file__).resolve().parents[1] / "data" / "importers"
FIXED_MTIME = 1_767_700_000  # 2026-01-06 11:06:40 UTC


def summarize(items: list[ImportItem]) -> list[dict[str, str | None]]:
    """The fields golden files pin: kind, hostname, vendor, command, captured_at, first line."""
    out: list[dict[str, str | None]] = []
    for item in items:
        text = item.content if isinstance(item.content, str) else item.content.decode()
        out.append(
            {
                "kind": item.kind,
                "hostname": item.hostname,
                "vendor": item.vendor,
                "command": item.command,
                "captured_at": item.captured_at.isoformat(),
                "importer": item.source.importer,
                "first_line": text.split("\n", 1)[0],
            }
        )
    return out


@pytest.fixture
def data_dir() -> Path:
    return DATA


@pytest.fixture
def fixed_mtime() -> int:
    return FIXED_MTIME


@pytest.fixture
def stage(tmp_path: Path) -> Callable[..., Path]:
    """Copy a data file (or write given bytes) into tmp_path with a fixed mtime."""

    def _stage(name: str, data: bytes | None = None) -> Path:
        path = tmp_path / name
        path.write_bytes(data if data is not None else (DATA / name).read_bytes())
        os.utime(path, (FIXED_MTIME, FIXED_MTIME))
        return path

    return _stage


@pytest.fixture
def check_golden() -> Callable[[list[ImportItem], str], None]:
    """Compare items with ``<name>.expected.json``; ROUTERSCOPE_UPDATE_GOLDEN=1 rewrites it."""

    def _check(items: list[ImportItem], name: str) -> None:
        expected = DATA / f"{name}.expected.json"
        actual = summarize(items)
        if os.environ.get("ROUTERSCOPE_UPDATE_GOLDEN") == "1":
            expected.write_text(json.dumps(actual, indent=2) + "\n", encoding="utf-8", newline="\n")
        assert actual == json.loads(expected.read_text(encoding="utf-8"))

    return _check


@pytest.fixture
def redactor() -> Redactor:
    def redact(text: str, vendor: str | None) -> str:
        return text.replace("secret-value", "<redacted>")

    return redact


# -- git repositories ----------------------------------------------------------------------

GIT = shutil.which("git")


GIT_TESTS = {"test_git_history.py", "test_oxidized.py", "test_rancid.py"}


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Skip the git history tests when git is not installed."""
    if GIT is None:
        marker = pytest.mark.skip(reason="git is not installed")
        for item in items:
            if item.path.name in GIT_TESTS:
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
