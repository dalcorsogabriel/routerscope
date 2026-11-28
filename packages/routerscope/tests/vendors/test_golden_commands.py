"""Golden tests for state-command parsers.

Each ``tests/data/commands/<vendor>/<name>.txt`` is a synthetic command output, ``<name>.cmd``
holds the typed command and ``<name>.expected.json`` the ParseResult (``null`` when the output
must not be recognised). Regenerate after an intentional change with
``UPDATE_GOLDEN=1 uv run pytest <this file>`` and review the diff by hand.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from routerscope.model import Snapshot, Source, split_lines
from routerscope.vendors import get

DATA = Path(__file__).resolve().parent.parent / "data" / "commands"
FIXED_ID = "0" * 63 + "1"
CASES = sorted(DATA.glob("*/*.txt"))


def make_snapshot(text: str, vendor: str, command: str) -> Snapshot:
    return Snapshot(
        id=FIXED_ID,
        vendor=vendor,
        kind="command_output",
        command=command,
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
        source=Source(kind="paste", uri="memory://golden", importer="test"),
        size=len(text.encode()),
        line_count=len(split_lines(text)),
    )


@pytest.mark.parametrize("path", CASES, ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_golden(path: Path) -> None:
    vendor = path.parent.name
    text = path.read_bytes().decode("utf-8")
    command = path.with_suffix(".cmd").read_text(encoding="utf-8").strip()
    plugin = get(vendor)
    assert plugin is not None
    result = plugin.parse_command(command, text, make_snapshot(text, vendor, command))
    actual = None if result is None else result.model_dump(mode="json", exclude_none=True)
    expected_path = path.with_suffix(".expected.json")
    if os.environ.get("UPDATE_GOLDEN"):
        expected_path.write_bytes((json.dumps(actual, indent=2) + "\n").encode())
    assert actual == json.loads(expected_path.read_text(encoding="utf-8"))
    if result is not None:
        total = len(split_lines(text))
        for obj in result.objects:
            assert 1 <= obj.ref.line_start <= obj.ref.line_end <= total


def test_every_vendor_has_five_commands() -> None:
    from collections import defaultdict

    kinds: dict[str, set[str]] = defaultdict(set)
    for path in CASES:
        expected = json.loads(path.with_suffix(".expected.json").read_text(encoding="utf-8"))
        if expected:
            kinds[path.parent.name].update(o["kind"] for o in expected["objects"])
    assert len(kinds) == 7
    for vendor, found in kinds.items():
        assert {"bgp_peer", "interface", "arp_entry", "mac_entry", "version"} <= found, vendor
