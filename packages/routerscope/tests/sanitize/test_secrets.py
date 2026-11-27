"""Secret redaction per vendor. Secrets here are synthetic."""

from __future__ import annotations

import pytest

from routerscope.sanitize import PLACEHOLDER, redact_secrets, scan

P = PLACEHOLDER

CASES: list[tuple[str, str, str]] = [
    # (vendor, input line, expected line)
    ("cisco_ios", "enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0", f"enable secret 5 {P}"),
    ("cisco_ios", "enable secret 9 $9$abcdefgh$xyz", f"enable secret 9 {P}"),
    (
        "cisco_ios",
        "username bob privilege 15 password 7 0822455D0A16",
        f"username bob privilege 15 password 7 {P}",
    ),
    ("cisco_ios", "enable password level 5 hunter2", f"enable password level 5 {P}"),
    ("cisco_ios", " password cisco123", f" password {P}"),
    ("cisco_ios", "snmp-server community s3cr3t RO 10", f"snmp-server community {P} RO 10"),
    (
        "cisco_ios",
        "snmp-server host 192.0.2.9 version 2c commstr",
        f"snmp-server host 192.0.2.9 version 2c {P}",
    ),
    (
        "cisco_ios",
        "snmp-server user u g v3 auth sha AUTHPW priv aes 128 PRIVPW",
        f"snmp-server user u g v3 auth sha {P} priv aes 128 {P}",
    ),
    (
        "cisco_ios",
        "tacacs-server host 192.0.2.1 key 7 0822455D0A16",
        f"tacacs-server host 192.0.2.1 key 7 {P}",
    ),
    ("cisco_ios", "radius-server key topsecret", f"radius-server key {P}"),
    ("cisco_ios", " key 7 0822455D0A16", f" key 7 {P}"),
    ("cisco_ios", "  key-string 7 0822455D0A16", f"  key-string 7 {P}"),
    (
        "cisco_ios",
        " neighbor 192.0.2.2 password 7 0822455D0A16",
        f" neighbor 192.0.2.2 password 7 {P}",
    ),
    (
        "cisco_ios",
        " ip ospf message-digest-key 1 md5 7 0822455D0A16",
        f" ip ospf message-digest-key 1 md5 7 {P}",
    ),
    ("cisco_ios", " ip ospf authentication-key ospfpw", f" ip ospf authentication-key {P}"),
    ("cisco_ios", "ntp authentication-key 1 md5 ntpsecret", f"ntp authentication-key 1 md5 {P}"),
    (
        "cisco_ios",
        "crypto isakmp key vpnsecret address 192.0.2.5",
        f"crypto isakmp key {P} address 192.0.2.5",
    ),
    ("cisco_ios", " standby 1 authentication hsrppw", f" standby 1 authentication {P}"),
    ("cisco_ios", " authentication text vrrppw", f" authentication text {P}"),
    ("cisco_xr", " password encrypted 094F471A1A0A", f" password encrypted {P}"),
    ("cisco_xr", "username x secret 10 $6$abc$defghijk", f"username x secret 10 {P}"),
    (
        "cisco_xr",
        "  message-digest-key 1 md5 encrypted 1234ABCD",
        f"  message-digest-key 1 md5 encrypted {P}",
    ),
    ("cisco_xr", " key-string password 060506324F41584B56", f" key-string password {P}"),
    (
        "huawei_vrp",
        "local-user admin password irreversible-cipher $1c$abc$def$",
        f"local-user admin password irreversible-cipher {P}",
    ),
    (
        "huawei_vrp",
        " snmp-agent community read cipher %^%#a;b c%^%#",
        f" snmp-agent community read cipher {P}",
    ),
    (
        "huawei_vrp",
        " snmp-agent community write simple plainstring",
        f" snmp-agent community write simple {P}",
    ),
    (
        "huawei_vrp",
        " peer 192.0.2.2 password cipher %^%#xyz%^%#",
        f" peer 192.0.2.2 password cipher {P}",
    ),
    (
        "huawei_vrp",
        " ospf authentication-mode md5 1 cipher %^%#abc%^%#",
        f" ospf authentication-mode md5 1 cipher {P}",
    ),
    (
        "huawei_vrp",
        " ospf authentication-mode simple plain123",
        f" ospf authentication-mode simple {P}",
    ),
    ("huawei_vrp", " pre-shared-key cipher %^%#xyz%^%#", f" pre-shared-key cipher {P}"),
    (
        "huawei_vrp",
        "radius-server shared-key cipher %^%#xyz%^%#",
        f"radius-server shared-key cipher {P}",
    ),
    (
        "huawei_vrp",
        " snmp-agent usm-user v3 u authentication-mode sha cipher %^%#q%^%#",
        f" snmp-agent usm-user v3 u authentication-mode sha cipher {P}",
    ),
    (
        "huawei_vrp",
        "ssh server cipher aes256_ctr aes128_ctr",
        "ssh server cipher aes256_ctr aes128_ctr",
    ),
    (
        "mikrotik_ros7",
        "/user add name=bob group=full password=hunter2",
        f"/user add name=bob group=full password={P}",
    ),
    (
        "mikrotik_ros7",
        '/ip ipsec identity add peer=p secret="a b c"',
        f'/ip ipsec identity add peer=p secret="{P}"',
    ),
    (
        "mikrotik_ros7",
        '/interface wireguard add name=w private-key="AAAAbbbb="',
        f'/interface wireguard add name=w private-key="{P}"',
    ),
    (
        "mikrotik_ros7",
        "add allowed-address=::/0 preshared-key=KEY123 public-key=PUB",
        f"add allowed-address=::/0 preshared-key={P} public-key={P}",
    ),
    (
        "mikrotik_ros7",
        "/routing bgp connection add tcp-md5-key=abc",
        f"/routing bgp connection add tcp-md5-key={P}",
    ),
    ("mikrotik_ros7", "set auth-key=abc123", f"set auth-key={P}"),
    (
        "mikrotik_ros7",
        "/interface wifi security add passphrase=wifipw",
        f"/interface wifi security add passphrase={P}",
    ),
    (
        "juniper_junos",
        '        encrypted-password "$6$abc$defghijkl"; ## SECRET-DATA',
        f'        encrypted-password "{P}"; ## SECRET-DATA',
    ),
    ("juniper_junos", '    authentication-key "$9$abcDEF123";', f'    authentication-key "{P}";'),
    (
        "juniper_junos",
        '    secret "$9$abcDEF123"; ## SECRET-DATA',
        f'    secret "{P}"; ## SECRET-DATA',
    ),
    (
        "juniper_junos",
        "set system root-authentication encrypted-password $1$abcd$efghijk",
        f"set system root-authentication encrypted-password {P}",
    ),
    (
        "juniper_junos",
        "set snmp community public authorization read-only",
        f"set snmp community {P} authorization read-only",
    ),
    ("juniper_junos", "            key plain;", f"            key {P};"),
    ("juniper_junos", '                    key "$9$abc";', f'                    key "{P}";'),
    (
        "juniper_junos",
        '                pre-shared-key ascii-text "$9$abc"; ## SECRET-DATA',
        f'                pre-shared-key ascii-text "{P}"; ## SECRET-DATA',
    ),
    (
        "nokia_sros",
        '            authentication-key "abcDEF" hash2',
        f'            authentication-key "{P}" hash2',
    ),
    (
        "nokia_sros",
        '    user "admin" password "$2y$10$abc.DEFghi"',
        f'    user "admin" password "{P}"',
    ),
    ("nokia_sros", '        secret "abc" hash2', f'        secret "{P}" hash2'),
    (
        "ipinfusion_ocnos",
        "snmp-server community PUBLIC group network-operator",
        f"snmp-server community {P} group network-operator",
    ),
    (
        "ipinfusion_ocnos",
        "username admin role network-admin password encrypted $1$abc$defghi",
        f"username admin role network-admin password encrypted {P}",
    ),
    ("ipinfusion_ocnos", "radius-server key 0 plainkey", f"radius-server key 0 {P}"),
    (None, "Authorization: Bearer abcdef0123456789", f"Authorization: Bearer {P}"),
    (None, '{"password": "abc", "token": "xyz"}', f'{{"password": "{P}", "token": "{P}"}}'),
    (None, "api-token abcdef", f"api-token {P}"),
]


@pytest.mark.parametrize(("vendor", "line", "expected"), CASES)
def test_redaction(vendor: str | None, line: str, expected: str) -> None:
    out = redact_secrets(line, vendor)
    assert out == expected
    assert redact_secrets(out, vendor) == out  # idempotent
    assert scan(out) == []


@pytest.mark.parametrize(
    "line",
    [
        "key chain MYCHAIN",
        " key 1",
        " key 10",
        "ssh server cipher aes256_ctr",
        "service password-encryption",
        "Enable secret is set",
        "no enable password",
        "Password:",
        "authentication-type md5;",
        "                md5 1 {",
        "show running-config | include password",
        "interface GigabitEthernet0/0/1",
        "ip as-path access-list 10 permit ^$",
    ],
)
def test_not_redacted(line: str) -> None:
    assert redact_secrets(line) == line


def test_nokia_and_junos_snmp_community_blocks() -> None:
    junos = "snmp {\n    community public {\n        authorization read-only;\n    }\n}\n"
    assert f"community {P} {{" in redact_secrets(junos)
    nokia = 'snmp\n    community "pubstr" hash2 r version both\n'
    assert f'community "{P}" hash2' in redact_secrets(nokia)
    # outside an snmp block a policy community name is not a secret
    pol = 'policy-options\n    community "CUST-A" members "64496:1"\n'
    assert redact_secrets(pol) == pol


def test_routeros_snmp_community_name_only_in_that_section() -> None:
    text = "/snmp community\nset [ find default=yes ] name=pubby\n/system identity\nset name=Edge\n"
    out = redact_secrets(text)
    assert f"name={P}" in out
    assert "name=Edge" in out


def test_pem_blocks_and_certificates() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\ndefGHI\n-----END RSA PRIVATE KEY-----\nafter\n"
    out = redact_secrets(pem)
    assert out == f"-----BEGIN RSA PRIVATE KEY-----\n{P}\n-----END RSA PRIVATE KEY-----\nafter\n"
    crlf = pem.replace("\n", "\r\n")
    assert redact_secrets(crlf).count("\r\n") == 4
    assert redact_secrets("-----BEGIN CERTIFICATE-----abc-----END CERTIFICATE-----") == (
        f"-----BEGIN CERTIFICATE-----{P}-----END CERTIFICATE-----"
    )
    # truncated paste
    assert P in redact_secrets("-----BEGIN PRIVATE KEY-----\nMIIE")
    cisco = "crypto pki certificate chain T\n certificate 01\n  30820123 3082AABB\n  CCDD\n  quit\n"
    out = redact_secrets(cisco)
    assert out == f"crypto pki certificate chain T\n certificate 01\n  {P}\n  quit\n"


def test_line_endings_and_trailing_space_preserved() -> None:
    text = "hostname x \r\nenable secret 5 $1$abc$defgh  \r\n\r\nend"
    out = redact_secrets(text)
    assert out == f"hostname x \r\nenable secret 5 {P}  \r\n\r\nend"
    assert redact_secrets("a\rpassword x\r") == f"a\rpassword {P}\r"


def test_vendor_hint_gated_rules_do_not_leak_with_wrong_hint() -> None:
    line = "enable secret 5 abc"
    assert redact_secrets(line, "juniper_junos") == redact_secrets(line, None)
