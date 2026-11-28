"""Golden tests: each synthetic config under tests/data/configs parses to its .expected.json.

Regenerate after an intentional parser change with ``UPDATE_GOLDEN=1 uv run pytest <this file>``
and review the diff by hand.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from routerscope.model import Snapshot, Source, split_lines
from routerscope.vendors import get

DATA = Path(__file__).resolve().parent.parent / "data" / "configs"
FIXED_ID = "0" * 63 + "1"
CASES = sorted(DATA.glob("*/*.cfg"))


def _snapshot(text: str, vendor: str) -> Snapshot:
    return Snapshot(
        id=FIXED_ID,
        vendor=vendor,
        kind="config",
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
        source=Source(kind="file", uri="memory://golden", importer="test"),
        size=len(text.encode()),
        line_count=len(split_lines(text)),
    )


@pytest.mark.parametrize("path", CASES, ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_golden(path: Path) -> None:
    vendor = path.parent.name
    text = path.read_bytes().decode("utf-8")
    plugin = get(vendor)
    assert plugin is not None
    parsed = plugin.parse_config(text, _snapshot(text, vendor))
    actual = parsed.model_dump(mode="json", exclude_none=True)
    expected_path = path.with_suffix(".expected.json")
    if os.environ.get("UPDATE_GOLDEN"):
        expected_path.write_bytes((json.dumps(actual, indent=2) + "\n").encode())
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    assert actual == expected
    # every ref must point inside the file
    total = len(split_lines(text))
    for obj in parsed.iter_objects():
        assert 1 <= obj.ref.line_start <= obj.ref.line_end <= total


def test_cases_exist() -> None:
    assert {p.parent.name for p in CASES} == {
        "cisco_ios",
        "cisco_xr",
        "huawei_vrp",
        "ipinfusion_ocnos",
        "juniper_junos",
        "mikrotik_ros7",
        "nokia_sros",
    }
