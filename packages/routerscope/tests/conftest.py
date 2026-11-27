from __future__ import annotations

from datetime import UTC, datetime

import pytest
from routerscope.model import Snapshot, Source, SourceRef, make_snapshot

CONTENT = "hostname r1\ninterface Gi0/0\n description uplink\n"


@pytest.fixture
def source() -> Source:
    return Source(kind="paste", uri="memory://test", importer="test")


@pytest.fixture
def snapshot(source: Source) -> Snapshot:
    return make_snapshot(
        CONTENT,
        source=source,
        kind="config",
        captured_at=datetime(2025, 1, 2, 3, 4, 5, tzinfo=UTC),
        hostname="r1",
        vendor="cisco_ios",
    )


@pytest.fixture
def ref(snapshot: Snapshot) -> SourceRef:
    return SourceRef(snapshot_id=snapshot.id, line_start=1, line_end=2)
