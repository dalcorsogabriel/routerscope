"""B: the scanner has its own noisy detectors, independent of the sanitizer's."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from routerscope.sanitize import Sanitizer, scan

CASES = Path(__file__).parent / "cases"


@pytest.mark.parametrize(
    ("raw", "kind"),
    [
        ("community SECRETJCOMM {", "secret"),
        ("some-new-vendor-cmd password hunter2", "secret"),
        ("frobnicate key abcdef123456", "secret"),
        ("fetch ftp://backup:hunter2@192.0.2.1/cfg", "credentials"),
        ("fetch ftp://backup@192.0.2.1/cfg", "credentials"),
        ("uplink to core-rj2.isp.net.br", "fqdn"),
        ("peer edge.acme-isp.com.br ok", "fqdn"),
        ("address is a8bb.cc00.0100", "mac"),
        ("address is A8:BB:CC:00:01:00", "mac"),
        ("address is a8-bb-cc-00-01-00", "mac"),
        ("fe80::a8bb:ccff:fe00:100", "eui64"),
        ("2001:db8:1:2:a8bb:ccff:fe00:100/64", "eui64"),
        ("Processor board ID FOC1234ABCD", "serial"),
        ("ESN: 2102351HQE10K8000123", "serial"),
        ("serial-number: A1B2C3D4E5F6", "serial"),
        (" description CLIENTE ACME", "freetext"),
        ('/ip address add comment="to ACME"', "freetext"),
        ("snmp-server location Rack 5", "freetext"),
        ("Contact: Joao NOC", "freetext"),
        ("banner motd ^C\nProperty of ACME\n^C\n", "freetext"),
    ],
)
def test_second_opinion_flags_what_the_sanitizer_never_saw(raw: str, kind: str) -> None:
    findings = scan(raw)
    assert kind in {f.kind for f in findings}, findings
    assert any(f.heuristic for f in findings if f.kind == kind)


@pytest.mark.parametrize(
    "clean",
    [
        "password 7 <redacted>",
        'username <redacted> password "<redacted>"',
        "snmp-server community <redacted> RO",
        "key chain K\n key 1\n  key-string 7 <redacted>",
        "service password-encryption",
        "crypto key generate rsa modulus 2048",
        "ftp://<redacted>:<redacted>@192.0.2.1/cfg",
        "host1.example.net example.com a.example.org x.invalid y.test localhost",
        "flash:/c2900-universalk9-mz.SPA.152-4.M3.bin copy show.txt remote.as=64496",
        "address is 0000.5e00.5300 01:00:5e:00:00:05 ff:ff:ff:ff:ff:ff",
        "fe80::200:5eff:fe00:5301 2001:db8::1",
        "Processor board ID SERIAL3\nESN: SERIAL4",
        " description desc-1\n/ip address add comment=desc-2\nbanner motd ^C\ndesc-3\n^C\n",
        "Press any key to continue (Q to quit)",
        "interface Serial0/0\n encapsulation ppp",
    ],
)
def test_second_opinion_accepts_sanitized_text(clean: str) -> None:
    assert scan(clean) == []


def test_every_regression_case_scans_clean_after_sanitizing_and_dirty_before() -> None:
    skipped = {"SECRETJCOMM", "SECRETJCOMM2"}  # Junos community outside an snmp block
    for f in sorted(CASES.glob("secrets_*.txt")):
        text = f.read_text(encoding="utf-8")
        out = Sanitizer().sanitize(text)
        rest = [x for x in scan(out) if not (skipped & set(re.findall(r"SECRET\w+", x.text)))]
        assert rest == [] or all("SECRETJCOMM" in out.splitlines()[x.line - 1] for x in rest), rest
        for line in text.splitlines():
            if re.search(r"SECRET\w+", line) and not line.startswith("#"):
                assert scan(line), line  # raw input is flagged


def test_heuristic_findings_are_marked_and_secret_values_never_echoed() -> None:
    f = scan("frobnicate key abcdef123456")[0]
    assert f.heuristic and f.sensitive
    url = next(x for x in scan("ftp://u:pw@192.0.2.1/") if x.kind == "credentials")
    assert url.sensitive


def test_allowlist_is_global_and_a_full_match_regex() -> None:
    text = "peer edge.acme-isp.com.br ok\nfrobnicate key abcdef123456\n"
    assert {f.kind for f in scan(text)} == {"fqdn", "secret"}
    assert {f.kind for f in scan(text, allow=["edge.acme-isp.com.br"])} == {"secret"}
    assert {f.kind for f in scan(text, allow=[r"edge\..*", "abcdef.*"])} == set()
    assert {f.kind for f in scan(text, allow=["edge"])} == {"fqdn", "secret"}  # not a full match
