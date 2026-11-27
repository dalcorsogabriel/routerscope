"""Property tests: never raises, output is clean, everything is idempotent."""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from routerscope.sanitize import Sanitizer, redact_secrets, scan

WORDS = [
    "password",
    "secret",
    "key",
    "7",
    "5",
    "cipher",
    "md5",
    "community",
    "snmp-server",
    "router",
    "bgp",
    "remote-as",
    "15169",
    "64496",
    "8.8.8.8",
    "1.1.1.0/24",
    "2a01:4f8::1",
    "aabb.ccdd.eeff",
    "hostname",
    "PE1",
    "description",
    "x@acme.net",
    "$1$abc$defgh",
    "%^%#a b%^%#",
    "=",
    '"',
    ";",
    "{",
    "}",
    "name=",
    "key=",
    "password=",
    "-----BEGIN KEY-----",
    "-----END KEY-----",
    "\r\n",
    "\n",
    "\r",
    " ",
    "  ",
    "\t",
    "<redacted>",
    "255.255.255.0",
    "route-target",
    "65001:100",
    "13335:5",
    "<PE1>",
    "PE1#",
    "authentication-key",
    "/user add",
]
texts = st.lists(st.sampled_from(WORDS), max_size=40).map(" ".join) | st.text(max_size=120)

CFG = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])


@CFG
@given(texts)
def test_redact_never_raises_is_idempotent_and_clean(text: str) -> None:
    out = redact_secrets(text)
    assert redact_secrets(out) == out
    assert [
        f for f in scan(out) if f.kind in {"secret", "pem", "certificate"} and not f.heuristic
    ] == []


@CFG
@given(texts)
def test_sanitize_never_raises_and_is_idempotent(text: str) -> None:
    out = Sanitizer(descriptions=True, remap_private=True).sanitize(text)
    again = Sanitizer(descriptions=True, remap_private=True).sanitize(out)
    assert again == out
    assert [f for f in scan(out) if not f.heuristic] == []


@CFG
@given(texts)
def test_sanitize_is_deterministic(text: str) -> None:
    assert Sanitizer("k").sanitize(text) == Sanitizer("k").sanitize(text)


@CFG
@given(st.text(alphabet="ab \t.0123456789-:", max_size=60))
def test_line_structure_preserved(text: str) -> None:
    out = Sanitizer().sanitize(text)
    assert out.count("\n") == text.count("\n")
