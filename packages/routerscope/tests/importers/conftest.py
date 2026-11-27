"""Shared fixtures for the importer tests (sibling imports do not work in importlib mode)."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
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
