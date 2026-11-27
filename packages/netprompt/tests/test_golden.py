"""Golden tests: synthetic sessions under tests/data/<vendor>/<name>.txt."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from netprompt import segment

DATA = Path(__file__).parent / "data"
SESSIONS = sorted(DATA.rglob("*.txt"))


def _ids() -> list[str]:
    return [p.relative_to(DATA).as_posix() for p in SESSIONS]


def test_sessions_exist_for_every_vendor() -> None:
    vendors = {p.parent.name for p in SESSIONS}
    assert {
        "cisco_ios",
        "cisco_xr",
        "huawei_vrp",
        "mikrotik_ros7",
        "juniper_junos",
        "nokia_sros",
        "ipinfusion_ocnos",
        "multi_device",
    } <= vendors


@pytest.mark.parametrize("path", SESSIONS, ids=_ids())
def test_golden(path: Path) -> None:
    text = path.read_bytes().decode()
    expected = json.loads(path.with_suffix(".expected.json").read_text(encoding="utf-8"))
    actual = []
    for seg in segment(text):
        out = seg.output
        actual.append(
            {
                "device": seg.device,
                "vendor": seg.prompt.vendor,
                "mode": str(seg.prompt.mode),
                "flags": sorted(seg.prompt.flags),
                "context": seg.prompt.context,
                "command": seg.command,
                "output_first_line": out.split("\n")[0] if out else "",
                "output_line_count": len(out.split("\n")) if out else 0,
            }
        )
    assert actual == expected
