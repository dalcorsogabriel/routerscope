from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from netaddr_search import MacStyle, find_macs, format_mac, normalize_mac

CANON = "aa:bb:cc:dd:ee:ff"


@pytest.mark.parametrize(
    "text",
    [
        "aa:bb:cc:dd:ee:ff",
        "AA:BB:CC:DD:EE:FF",
        "aa-bb-cc-dd-ee-ff",
        "aabb.ccdd.eeff",
        "AABB.CCDD.EEFF",
        "aabb-ccdd-eeff",
        "aabbccddeeff",
        "  AaBbCcDdEeFf\n",
    ],
)
def test_normalize_valid(text: str) -> None:
    assert normalize_mac(text) == CANON


@pytest.mark.parametrize(
    "text",
    [
        "",
        "aa:bb:cc:dd:ee",
        "aa:bb:cc:dd:ee:ff:00",
        "aa:bb:cc:dd:ee:gg",
        "aabb.ccdd",
        "aa:bb-cc:dd-ee:ff",
        "aabb.ccdd-eeff",
        "aabbccddeef",
        "2001:db8::1",
    ],
)
def test_normalize_invalid(text: str) -> None:
    assert normalize_mac(text) is None


def test_format_styles() -> None:
    assert format_mac(CANON, MacStyle.COLON) == CANON
    assert format_mac(CANON, MacStyle.HYPHEN) == "aa-bb-cc-dd-ee-ff"
    assert format_mac(CANON, MacStyle.CISCO) == "aabb.ccdd.eeff"
    assert format_mac(CANON, MacStyle.HUAWEI) == "aabb-ccdd-eeff"
    assert format_mac(CANON, MacStyle.BARE) == "aabbccddeeff"
    assert format_mac("aabb.ccdd.eeff", MacStyle.CISCO, upper=True) == "AABB.CCDD.EEFF"
    assert format_mac(CANON) == CANON


def test_format_invalid() -> None:
    with pytest.raises(ValueError, match="invalid MAC"):
        format_mac("nope")


_macs = st.binary(min_size=6, max_size=6).map(lambda b: ":".join(f"{x:02x}" for x in b))


@given(_macs, st.sampled_from(list(MacStyle)), st.booleans())
def test_mac_properties(mac: str, style: MacStyle, upper: bool) -> None:
    rendered = format_mac(mac, style, upper=upper)
    assert normalize_mac(rendered) == mac
    n = normalize_mac(rendered)
    assert n is not None
    assert normalize_mac(n) == n


def test_find_macs() -> None:
    text = "a aa:bb:cc:dd:ee:ff, b AABB.CCDD.EEFF; c 0011-2233-4455 d 00-11-22-33-44-55."
    got = list(find_macs(text))
    assert [m.mac for m in got] == [
        "aa:bb:cc:dd:ee:ff",
        "aa:bb:cc:dd:ee:ff",
        "00:11:22:33:44:55",
        "00:11:22:33:44:55",
    ]
    for m in got:
        assert text[m.start : m.end] == m.text


@pytest.mark.parametrize(
    "text",
    [
        "2001:db8::aa:bb:cc:dd:ee:ff",
        "aa:bb:cc:dd:ee:ff::1",
        "::aa:bb:cc:dd:ee:ff",
        "00:11:22:33:44:55:66:77",
        "aabbccddeeff",
        "aa:bb:cc:dd:ee",
        "xaa:bb:cc:dd:ee:ff",
        "192.0.2.1",
        "2001:db8::1",
    ],
)
def test_find_macs_negatives(text: str) -> None:
    assert list(find_macs(text)) == []
