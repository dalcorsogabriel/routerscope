"""The store with the real redactor from routerscope.sanitize."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from routerscope.model import BGPPeer, Device, Interface, ParsedConfig, Source, SourceRef
from routerscope.sanitize import redact_secrets
from routerscope.storage import Store
from routerscope.storage.errors import UnredactedDataError

CONFIG = (
    "hostname r1\n"
    "interface GigabitEthernet0/0/1\n"
    " description uplink password 7 0822455D0A16\n"
    "router bgp 64496\n"
    " neighbor 192.0.2.1 remote-as 64497\n"
    " neighbor 192.0.2.1 password 7 0822455D0A16\n"
)


def test_parsed_output_of_redacted_text_is_accepted_and_secrets_never_stored() -> None:
    with Store.open(":memory:", redactor=redact_secrets) as store:
        snap = store.add_snapshot(
            CONFIG,
            source=Source(kind="paste", uri="ftp://u:p@192.0.2.9/x", importer="test"),
            kind="config",
            captured_at=datetime.now(UTC),
            hostname="r1",
            vendor="cisco_ios",
        )
        stored = store.get_content(snap.id)
        assert "0822455D0A16" not in stored

        def ref(start: int, end: int) -> SourceRef:
            return SourceRef(snapshot_id=snap.id, line_start=start, line_end=end)

        description = stored.splitlines()[2].split("description ", 1)[1]
        parsed = ParsedConfig(
            snapshot_id=snap.id,
            vendor="cisco_ios",
            device=Device(ref=ref(1, 1), hostname="r1"),
            interfaces=(
                Interface(
                    ref=ref(2, 3),
                    name="GigabitEthernet0/0/1",
                    description=description,
                    vendor="cisco_ios",
                ),
            ),
            bgp_peers=(BGPPeer(ref=ref(5, 6), peer="192.0.2.1", remote_as=64497, local_as=64496),),
        )
        store.add_parsed(parsed, plugin="cisco_ios")
        assert store.get_parsed_config(snap.id, plugin="cisco_ios") == parsed

        leaky = parsed.model_copy(
            update={
                "interfaces": (
                    Interface(
                        ref=ref(2, 3),
                        name="Gi0/0/1",
                        description="uplink password 7 0822455D0A16",
                        vendor="cisco_ios",
                    ),
                )
            }
        )
        with pytest.raises(UnredactedDataError):
            store.add_parsed(leaky, plugin="cisco_ios")
        assert store.search_text("0822455D") == []
