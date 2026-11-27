from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from routerscope.model import Source
from routerscope.storage import Redactor, Store

SECRET_PATTERNS = (
    re.compile(r"(password 7 )\S+"),
    re.compile(r"\$9\$\S+"),
    re.compile(r"(secret=)\S+"),
)


def fake_redactor(text: str, vendor: str | None) -> str:
    """Stand-in for routerscope.sanitize.redact_secrets used only in tests."""
    out = SECRET_PATTERNS[0].sub(r"\1<redacted>", text)
    out = SECRET_PATTERNS[1].sub("<redacted>", out)
    return SECRET_PATTERNS[2].sub(r"\1<redacted>", out)


@pytest.fixture
def redactor() -> Redactor:
    return fake_redactor


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    with Store.open(tmp_path / "rs.db", redactor=fake_redactor) as s:
        yield s


@pytest.fixture
def src() -> Source:
    return Source(kind="paste", uri="memory://t", importer="test")
