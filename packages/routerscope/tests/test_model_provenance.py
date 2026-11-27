from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from routerscope.model import (
    Snapshot,
    Source,
    SourceRef,
    content_digest,
    make_snapshot,
    split_lines,
)


def test_make_snapshot_hashes_and_counts(source: Source) -> None:
    snap = make_snapshot(
        "a\nb\n",
        source=source,
        kind="command_output",
        command="show version",
        captured_at=datetime(2025, 1, 1, tzinfo=UTC),
    )
    assert snap.id == hashlib.sha256(b"a\nb\n").hexdigest() == content_digest("a\nb\n")
    assert (snap.size, snap.line_count) == (4, 2)
    assert snap.command == "show version"
    assert snap.vendor is None


def test_make_snapshot_from_bytes(source: Source) -> None:
    raw = b"x\xff\ny"
    snap = make_snapshot(raw, source=source, kind="session", captured_at=datetime.now(UTC))
    assert snap.id == content_digest(raw)
    assert (snap.size, snap.line_count) == (4, 2)


def test_captured_at_normalized_to_utc(source: Source) -> None:
    tz = timezone(timedelta(hours=-3))
    snap = make_snapshot(
        "x", source=source, kind="config", captured_at=datetime(2025, 1, 1, 12, tzinfo=tz)
    )
    assert snap.captured_at.utcoffset() == timedelta(0)
    assert snap.captured_at.hour == 15


def test_naive_datetime_rejected(source: Source) -> None:
    with pytest.raises(ValidationError):
        make_snapshot("x", source=source, kind="config", captured_at=datetime(2025, 1, 1))


def test_third_party_vendor_accepted_bad_id_rejected(source: Source) -> None:
    snap = make_snapshot(
        "x", source=source, kind="config", captured_at=datetime.now(UTC), vendor="acme_os"
    )
    assert snap.vendor == "acme_os"
    with pytest.raises(ValidationError):
        make_snapshot(
            "x", source=source, kind="config", captured_at=datetime.now(UTC), vendor="Acme OS"
        )


@pytest.mark.parametrize(
    ("text", "lines"),
    [
        ("", []),
        ("a", ["a"]),
        ("a\n", ["a"]),
        ("a\r\nb\rc\nd", ["a", "b", "c", "d"]),
        ("a\n\nb\n", ["a", "", "b"]),
        ("banner\x0cpage\u2028x\x85y", ["banner\x0cpage\u2028x\x85y"]),
    ],
)
def test_split_lines(text: str, lines: list[str]) -> None:
    assert split_lines(text) == lines


def test_line_count_matches_split_lines(source: Source) -> None:
    text = "a\r\nb\x0cc\u2028d\n"
    snap = make_snapshot(text, source=source, kind="config", captured_at=datetime.now(UTC))
    assert snap.line_count == len(split_lines(text)) == 2


def test_frozen_and_forbid_extra(snapshot: Snapshot, source: Source) -> None:
    with pytest.raises(ValidationError):
        snapshot.hostname = "other"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        Source(kind="file", uri="x", importer="y", bogus=1)  # type: ignore[call-arg]


def test_bad_id_and_kind(source: Source) -> None:
    with pytest.raises(ValidationError):
        Snapshot(
            id="ABC",
            kind="config",
            captured_at=datetime.now(UTC),
            source=source,
            size=0,
            line_count=0,
        )
    with pytest.raises(ValidationError):
        Source(kind="telepathy", uri="x", importer="y")  # type: ignore[arg-type]


def test_sourceref_validation(snapshot: Snapshot) -> None:
    assert SourceRef(snapshot_id=snapshot.id, line_start=3, line_end=3).line_end == 3
    with pytest.raises(ValidationError):
        SourceRef(snapshot_id=snapshot.id, line_start=0, line_end=1)
    with pytest.raises(ValidationError, match="line_end"):
        SourceRef(snapshot_id=snapshot.id, line_start=5, line_end=4)


def test_snapshot_json_roundtrip(snapshot: Snapshot) -> None:
    assert Snapshot.model_validate_json(snapshot.model_dump_json()) == snapshot
