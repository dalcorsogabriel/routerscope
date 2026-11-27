"""Table-driven tests from tests/cases/<vendor>.txt (see tests/cases/README.md)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from netcmd_safety import VENDORS, Mode, Verdict, classify

CASES_DIR = Path(__file__).parent / "cases"


@dataclass(frozen=True)
class Case:
    vendor: str
    verdict: Verdict
    mode: Mode | None
    command: str
    where: str


def load_cases() -> list[Case]:
    cases: list[Case] = []
    for path in sorted(CASES_DIR.glob("*.txt")):
        vendor = path.stem
        assert vendor in VENDORS, f"{path.name}: unknown vendor file"
        for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            verdict_s, _, rest = line.partition(" ")
            rest = rest.strip()
            mode: Mode | None = None
            if rest.startswith("@"):
                mode_s, _, rest = rest.partition(" ")
                mode = Mode(mode_s[1:])
            cases.append(Case(vendor, Verdict(verdict_s), mode, rest.strip(), f"{path.name}:{n}"))
    return cases


CASES = load_cases()


def test_every_vendor_has_cases() -> None:
    assert {c.vendor for c in CASES} == set(VENDORS)


@pytest.mark.parametrize("case", CASES, ids=[f"{c.where} {c.command}" for c in CASES])
def test_case(case: Case) -> None:
    result = classify(case.command, case.vendor, mode=case.mode)
    assert result.verdict is case.verdict, f"{case.where}: {result.reason}"


@pytest.mark.parametrize(
    "case",
    [c for c in CASES if c.verdict in (Verdict.CONFIG, Verdict.DESTRUCTIVE)],
    ids=lambda c: f"{c.where}",
)
def test_writes_are_never_collector_safe(case: Case) -> None:
    """Regression guard: a write command must never be sendable by the collector."""
    assert not classify(case.command, case.vendor, mode=case.mode).collector_safe
