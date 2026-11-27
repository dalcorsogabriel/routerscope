"""Regression cases from the security review: every secret marker must disappear.

The case files hold one configuration line per line; every secret is a token starting with
``SECRET`` (or a known fake key blob). A line "leaks" if such a token survives sanitizing.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from routerscope.sanitize import Sanitizer, redact_secrets, scan

CASES = Path(__file__).parent / "cases"
MARKER = re.compile(r"SECRET\w+|AAAAB3\w+|060506324F41|WPAKEY")

# Junos ``community NAME {`` is only a secret inside ``snmp { }``; a lone line has no context
# (covered with context in test_secrets.py). ``## SECRET-DATA`` is Junos' own comment marker.
CONTEXT_ONLY = {"community SECRETJCOMM { authorization read-only; }", "community SECRETJCOMM2 {"}


def _case_lines() -> list[tuple[str, str]]:
    out = []
    for f in sorted(CASES.glob("secrets_*.txt")):
        for ln in f.read_text(encoding="utf-8").splitlines():
            if ln.strip() and not ln.startswith("#") and ln.strip() not in CONTEXT_ONLY:
                out.append((f.stem, ln))
    return out


LINES = _case_lines()


@pytest.mark.parametrize(("name", "line"), LINES, ids=[f"{n}:{ln.strip()[:50]}" for n, ln in LINES])
def test_no_secret_survives(name: str, line: str) -> None:
    out = redact_secrets(line)
    assert [t for t in MARKER.findall(line) if t in out] == []
    assert redact_secrets(out) == out  # idempotent
    if MARKER.search(line):
        assert scan(line) != []  # raw input is flagged
    assert not [t for t in MARKER.findall(out)]
    assert not [f for f in scan(out) if f.kind in {"secret", "pem", "certificate"}]


def test_whole_documents_are_clean_and_stable() -> None:
    for f in sorted(CASES.glob("secrets_*.txt")):
        text = f.read_text(encoding="utf-8")
        out = Sanitizer().sanitize(text)
        assert Sanitizer().sanitize(out) == out
        leaked = [t for t in MARKER.findall(out) if t not in {"SECRETJCOMM", "SECRETJCOMM2"}]
        assert leaked == []


def test_placeholder_never_sits_on_a_type_token() -> None:
    cases = {
        "snmp-server user u g v3 auth md5 encrypted AUTHPW priv aes 128 encrypted PRIVPW": (
            "snmp-server user u g v3 auth md5 encrypted <redacted> "
            "priv aes 128 encrypted <redacted>"
        ),
        "snmp-server user u g v3 auth sha AUTHPW priv aes-128 PRIVPW": (
            "snmp-server user u g v3 auth sha <redacted> priv aes-128 <redacted>"
        ),
        'ntp authentication-key 1 key "NTPKEY" hash2 type message-digest': (
            'ntp authentication-key 1 key "<redacted>" hash2 type message-digest'
        ),
        "ntp authentication-key 10 cmac-aes-128 NTPKEY": (
            "ntp authentication-key 10 cmac-aes-128 <redacted>"
        ),
        "key config-key password-encrypt MASTERKEY": "key config-key password-encrypt <redacted>",
        "set system ntp authentication-key 1 type md5 value NTPVAL": (
            "set system ntp authentication-key 1 type md5 value <redacted>"
        ),
        "snmp-server host 192.0.2.1 informs version 3 priv V3USER": (
            "snmp-server host 192.0.2.1 informs version 3 priv <redacted>"
        ),
    }
    for line, expected in cases.items():
        assert redact_secrets(line) == expected


def test_fail_closed_widening_swallows_the_next_token() -> None:
    # a keyword-only match followed by a value-looking token must not leave that token behind
    assert "REALVALUE" not in redact_secrets("pre-shared-key md5 REALVALUE")
    assert "REALVALUE" not in redact_secrets("authentication-key 7 REALVALUE")


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (
            "copy ftp://backup:p@ss!w0rd#x@backup.invalid-host.test/cfg flash:",
            "copy ftp://<redacted>:<redacted>@backup.invalid-host.test/cfg flash:",
        ),
        (
            "path tftp://u:PW1@192.0.2.3/cfg",
            "path tftp://<redacted>:<redacted>@192.0.2.3/cfg",
        ),
        (
            'on-event="/tool fetch url=ftp://u:PW2@192.0.2.4/x"',
            'on-event="/tool fetch url=ftp://<redacted>:<redacted>@192.0.2.4/x"',
        ),
        ("url sftp://onlyuser@192.0.2.5/", "url sftp://<redacted>@192.0.2.5/"),
        ("http://192.0.2.6:8080/path@x", "http://192.0.2.6:8080/path@x"),
        ("https://[2001:db8::1]:443/x", "https://[2001:db8::1]:443/x"),
    ],
)
def test_credentials_in_urls(line: str, expected: str) -> None:
    out = redact_secrets(line)
    assert out == expected
    assert redact_secrets(out) == out


def test_engine_id_keeps_the_enterprise_prefix() -> None:
    out = redact_secrets("snmp-server engineID local 800000090300A8BBCC000100")
    assert out == "snmp-server engineID local 80000009<redacted>"
    assert redact_secrets(out) == out
    out = redact_secrets("snmp-agent local-engineid 800007DB03AABBCCDDEEFF00")
    assert out == "snmp-agent local-engineid 800007DB<redacted>"
    assert (
        redact_secrets("snmp-server engineID remote 192.0.2.1 udp-port 162 800000090300112233")
        == "snmp-server engineID remote 192.0.2.1 udp-port 162 80000009<redacted>"
    )
