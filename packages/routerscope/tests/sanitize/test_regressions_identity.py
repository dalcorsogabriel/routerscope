"""Regression cases from the security review: names, domains, identifiers, free text, addresses."""

from __future__ import annotations

import re

import pytest
from routerscope.sanitize import Sanitizer, scan


def san(text: str, **kw: object) -> str:
    out = Sanitizer(**kw).sanitize(text)  # type: ignore[arg-type]
    assert Sanitizer(**kw).sanitize(out) == out  # idempotent
    return out


# ------------------------------------------------------------------------------ A5 hostnames


def test_labelled_hostnames_keep_the_colon_and_the_value() -> None:
    out = san("System Name   : edge-sp1\nSystem Name : edge-sp2\nHostname : ocn-pe-9\n")
    assert out == "System Name   : R1\nSystem Name : R2\nHostname : R3\n"
    assert san("Hostname: mx204-pop3\nModel: mx204\n") == "Hostname: R1\nModel: mx204\n"
    assert san("Local system name: sw-core-1\nSystem Name: sw-core-1\n") == (
        "Local system name: R1\nSystem Name: R1\n"
    )


def test_uptime_line_and_case_insensitive_global_replacement() -> None:
    out = san("edge-sp1 uptime is 2 weeks\nhostname EDGE-SP1\nshow lldp  edge-sp1.isp.net.br\n")
    assert "edge-sp1" not in out.lower() and "isp.net.br" not in out
    assert out.startswith("R1 uptime is 2 weeks\nhostname R1\n")


def test_short_hostnames_from_statements_are_replaced_everywhere() -> None:
    out = san("hostname pe\nshow pe version\n")
    assert out == "hostname R1\nshow R1 version\n"


def test_routeros_identity_print_after_prompt() -> None:
    text = "[admin@MikroTik-POP7] > /system identity print\n  name: MikroTik-POP7\n"
    out = san(text)
    assert "MikroTik-POP7" not in out and "  name: R1" in out


# -------------------------------------------------------------------------------- A6 domains


def test_domain_names_map_consistently_and_keep_reserved_ones() -> None:
    text = (
        "ip domain name isp.net.br\nip domain-name isp.net.br\n"
        "ip host lab1 192.0.2.9\n"
        "traceroute\n  2 core-rj2.isp.net.br (192.0.2.5) 2 msec\n"
        "  dns-name: a1b2c3d4e5.sn.mynetname.net\n"
        "crypto pki trustpoint T\n subject-name CN=vpn.customer-x.com.br\n"
        "ok example.com www.example.org host.example.net name.example x.invalid y.test localhost\n"
    )
    out = san(text)
    for leaked in ("isp.net.br", "core-rj2", "mynetname", "customer-x", "lab1"):
        assert leaked not in out
    assert out.count("host1.example.net") == 2  # same name, same pseudonym
    assert "example.com www.example.org host.example.net name.example x.invalid y.test" in out


@pytest.mark.parametrize(
    "line",
    [
        "interface GigabitEthernet0/0.100",
        "interface ge-0/0/0.0",
        "Version 15.2.4 and 7.16.1",
        'System image file is "flash:/c2900-universalk9-mz.SPA.152-4.M3.bin"',
        "copy flash:config.cfg tftp:",
        "/routing bgp connection add remote.as=15169 remote.address=192.0.2.1 .id=x",
        "show.txt output.log",
        "ip.address and a.b",
    ],
)
def test_non_domains_are_left_alone(line: str) -> None:
    out = san(line, descriptions=False)
    assert re.sub(r"\d+", "N", out) == re.sub(r"\d+", "N", line)


def test_lldp_neighbour_table_device_ids() -> None:
    text = (
        "Device ID           Local Intf     Hold-time  Capability      Port ID\n"
        "sw-cliente-acme     Gi0/2          120        B               Fa0/1\n"
        "core-rj2.isp.net.br Gi0/1          120        R               Te0/0/1\n"
        "\nnext line stays\n"
    )
    out = san(text)
    assert "sw-cliente-acme" not in out and "core-rj2" not in out
    assert "Gi0/2" in out and out.endswith("next line stays\n")


# ------------------------------------------------------------------------------ A7 identifiers


def test_serial_numbers_and_esn_are_pseudonymised() -> None:
    text = (
        "Processor board ID FOC1234ABCD\nSystem serial number: FOC1234ABCD\n"
        "PID: ISR4331/K9, VID: V04, SN: FDO21520ABC\n"
        "     serial-number: A1B2C3D4E5F6\n  software-id: ABCD-1234\n"
        "ESN: 2102351HQE10K8000123\nDevice ESN: 2102351HQE10K8000123\n"
        "Chassis serial number: FOX1234ABCD\n"
        " Serial number   : NS1234567890\nSerial Number: ABC123456\n"
        "Chassis                                JN1234ABCDEF      MX204\n"
        "Routing Engine 0   REV 01   750-12345  CABC1234          RE-S-1X8\n"
    )
    out = san(text)
    for leaked in (
        "FOC1234ABCD",
        "FDO21520ABC",
        "A1B2C3D4E5F6",
        "ABCD-1234",
        "2102351HQE",
        "FOX1234ABCD",
        "NS1234567890",
        "ABC123456",
        "JN1234ABCDEF",
        "CABC1234",
    ):
        assert leaked not in out
    assert len(re.findall(r"SERIAL1\b", out)) == 2  # the same serial maps to the same name
    assert "ISR4331/K9" in out and "750-12345" in out and "RE-S-1X8" in out


def test_junos_hardware_table_with_header() -> None:
    text = (
        "Hardware inventory:\n"
        "Item             Version  Part number  Serial number     Description\n"
        "Chassis                                JN1234ABCDEF      MX204\n"
        "Midplane         REV 03   750-99999    ABCD1234          Backplane\n"
    )
    out = san(text)
    assert "JN1234ABCDEF" not in out and "ABCD1234" not in out and "750-99999" in out


def test_eui64_interface_ids_follow_the_mac_mapping() -> None:
    text = (
        "FE80::A8BB:CCFF:FE00:100\nfe80::a8bb:ccff:fe00:100%Gi0/0\n"
        "2001:4860:1:2:a8bb:ccff:fe00:100/64\nHardware is X, address is aabb.cc00.0100\n"
    )
    out = san(text)
    assert "a8bb" not in out.lower() and "fe00:100" not in out and "aabb" not in out.lower()
    first, second, third, fourth = out.splitlines()
    mac_tail = re.search(r"0000\.5e00\.(53[0-9a-f]{2})", fourth)
    assert mac_tail is not None
    iid_tail = mac_tail.group(1).lstrip("0")
    assert first.lower().endswith("fe00:" + iid_tail) and second.startswith("fe80::")
    assert third.startswith("2001:db8:") and third.endswith("/64")


def test_bare_mac_needs_a_mac_context_and_isis_net_system_id_is_remapped() -> None:
    out = san("mac-address=A8BBCC000100\nmac a8bbcc000100\nmac-address A8BBCC000100\n")
    assert "a8bb" not in out.lower()
    out = san("isis net 49.0001.2002.0100.0001.00\nNET: 49.0001.1921.6800.1001.00\n")
    assert "2002.0100.0001" not in out and "1921.6800.1001" in out  # private ID kept
    assert re.search(r"49\.0001\.19\d\d\.\d{4}\.\d{4}\.00", out.splitlines()[0])


# ----------------------------------------------------------------------------- A8 free text


def test_descriptions_are_on_by_default_and_can_be_kept() -> None:
    text = " description CLIENTE ACME LTDA - CNPJ 12.345.678/0001-90\n"
    assert san(text) == " description desc-1\n"
    assert Sanitizer(descriptions=False).sanitize(text) == text


def test_inline_descriptions_and_comments() -> None:
    text = (
        ' description "Uplink to X"; ## kept note\n description ACME; ## inline\n'
        '/interface ethernet set ether1 comment="ACME LTDA"\n'
        "/ip address add address=192.0.2.1/24 comment=ACME-4 interface=ether1\n"
        '/system note set note="Property of ACME"\n'
    )
    out = san(text)
    assert "ACME" not in out and "Uplink" not in out
    assert ' description "desc-1"; ## kept note' in out


def test_banners_snmp_text_and_junos_location() -> None:
    text = (
        "banner motd ^C\nProperty of ACME ISP - call 555-0100\n^C\n"
        "banner login #Welcome ACME#\n"
        "snmp-server location Rack 5 Sao Paulo\nsnmp-server contact Joao NOC\n"
        'snmp {\n    location "Rack 5 Sao Paulo DC";\n    contact "noc";\n}\n'
        'set system location building "ACME HQ"\n'
        "System Contact         : Joao NOC +55 11 1234\nSystem Location        : Equinix SP4\n"
        'header login information "Authorized ACME users only"\n'
    )
    out = san(text)
    for leaked in ("ACME", "Rack 5", "Joao", "Equinix", "555-0100", "Sao Paulo", "noc"):
        assert leaked not in out
    assert out.startswith("banner motd ^C\ndesc-1\n^C\nbanner login #desc-2#\n")


def test_user_names_become_user_n() -> None:
    text = (
        "username jsilva privilege 15 secret 9 $9$abc$defghijk\n"
        "local-user ops-bob password cipher %^%#abc%^%#\n"
        'set system login user maria authentication encrypted-password "$6$abc$defgh"\n'
        "system {\n    login {\n        user carlos {\n            class super-user;\n"
        "        }\n    }\n}\n"
        "/ppp secret add name=client123 password=PW profile=p service=pppoe\n"
        "/user add name=joao password=PW group=full\n"
        "/user group add name=g policy=local\n"
        " ppp chap hostname isp-user@acme.com.br\n ppp pap sent-username u1 password 7 ABC\n"
    )
    out = san(text)
    for leaked in ("jsilva", "ops-bob", "maria", "carlos", "client123", "joao", "isp-user", "u1 "):
        assert leaked not in out
    assert "name=g policy=local" in out  # a group name is not a user
    assert "username user1 privilege 15" in out


# ------------------------------------------------------------------------------- A9 addresses


@pytest.mark.parametrize(
    "line",
    [
        "tcp 200.1.2.4.179 200.1.2.5.50422 ESTAB",
        "tcp4 0 0 200.1.2.4.22 8.8.8.8.51000 ESTABLISHED",
        "peer 2001:4860:4860::8888.179",
        "200.001.002.003",
        "Version: 200.1.2.3",
        "release 200.1.2.3",
        "build 200.1.2.3 foo",
        "64:ff9b::200.1.2.15",
        "64:ff9b::c801:20f",
        "::200.1.2.3",
        "::ffff:200.1.2.3",
        "::ffff:c801:0203",
    ],
)
def test_address_forms_that_used_to_leak(line: str) -> None:
    out = san(line)
    assert not re.search(r"\b(?:200\.1|200\.001|8\.8\.8|2001:4860|c801)", out, re.IGNORECASE), out
    assert scan(out) == []


def test_version_numbers_and_masks_are_still_left_alone() -> None:
    text = "Image Version 7.16.1.0\nrelease 12.2.33.1\nmask 255.255.255.0 wildcard 0.0.0.255\n"
    assert san(text) == text


def test_private_addresses_are_kept_unless_asked() -> None:
    text = "ip address 10.1.1.1 255.255.255.0\npeer 100.64.1.1\n"
    assert san(text) == text
    assert "10.1.1.1" not in san(text, remap_private=True)


# ---------------------------------------------------------------------------------- A10 ASNs


@pytest.mark.parametrize(
    "line",
    [
        "bgp confederation peers 64512 15169 3356",
        "confederation peers 15169 3356",
        " members [ 28573:100 large:28573:1:2 ext:15169:5 ];",
        " as-path-prepend 28573 28573",
        " /routing bgp advertisements as-path=15169,3356 origin=igp",
        ' /routing filter rule add rule="if (bgp-as-path ~ \\"15169\\") { accept }"',
        " origin-as 15169",
        " Origin: 15169",
        " Aggregator: AS 28573, 200.1.2.3",
        " aggregator: 28573 200.1.2.3",
        " PeerAS 15169",
        " asn 15169",
        " AS 15169",
        " AS 15169 (Google)",
        " AS: 15169",
        " Origin AS: AS15169",
        " ip as-path access-list AS15169 permit _15169$",
        " route-map FROM-AS3356-IN permit 10",
        " neighbor AS15169-PEERS peer-group",
        " ip ip-prefix AS15169-IN index 10 permit 8.8.8.0 24",
        " neighbor 1.2.3.4 description Level3 IP transit AS3356",
        " local autonomous system number : 28573",
        " Path: 15169 I",
        " AS-PATH: [15169, 3356]",
        " if as-path originates-from '15169' then",
        " from-as 15169",
        " bgp-as 28573",
    ],
)
def test_asn_forms_that_used_to_leak(line: str) -> None:
    out = san(line)
    assert not re.search(r"(?<![\d.])(?:15169|28573|3356)(?![\d.:])|AS(?:15169|3356)", out), out
    assert not [f for f in scan(out) if f.kind == "asn"]


def test_as_sets_in_bgp_tables() -> None:
    text = (
        "   Network          Next Hop            Metric LocPrf Weight Path\n"
        " *>i 1.1.1.0/24       200.1.2.3                0    100      0 15169 {3356,28573} i\n"
    )
    out = san(text)
    assert not re.search(r"15169|3356|28573", out)


def test_the_word_as_alone_is_not_an_asn_context() -> None:
    text = "treat as 5 hops\nlast AS\nAS path is long\nclass 100\n"
    assert san(text) == text
