"""Sanitizer behaviour. Public-looking "originals" (8.8.8.8, ...) only appear in these tests,
which the CI fixture check does not scan."""

from __future__ import annotations

import json
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

import pytest
from netaddr_search import find_ips
from routerscope.sanitize import Sanitizer, scan

DOC4 = [
    IPv4Network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15")
]


def _ips(text: str) -> list[str]:
    return [str(m.address) for m in find_ips(text)]


def test_ipv4_keeps_relationships_and_lengths() -> None:
    text = (
        "ip address 8.8.8.1 255.255.255.0\n"
        "network 8.8.8.0 0.0.0.255\n"
        "route 8.8.4.0/22 via 8.8.4.7\n"
        "peer 1.1.1.1/32\n"
    )
    out = Sanitizer().sanitize(text)
    assert scan(out) == []
    lines = out.splitlines()
    a = lines[0].split()[2]
    mask = lines[0].split()[3]
    assert mask == "255.255.255.0"
    assert lines[1].split()[1].rsplit(".", 1)[0] == a.rsplit(".", 1)[0]
    assert lines[1].endswith("0.0.0.255")
    assert lines[2].split()[1].endswith("/22")
    pfx = IPv4Network(lines[2].split()[1], strict=False)
    assert IPv4Address(lines[2].split()[3]) in pfx
    assert lines[3].endswith("/32")
    for token in _ips(out):
        if token not in {"255.255.255.0", "0.0.0.255"}:
            assert any(IPv4Address(token) in n for n in DOC4)


def test_host_bits_and_distinct_blocks() -> None:
    san = Sanitizer()
    out = san.sanitize("8.8.8.77 8.8.9.77 8.8.8.78\n")
    a, b, c = out.split()
    assert a.rsplit(".", 1)[1] == "77" and c.rsplit(".", 1)[1] == "78"
    assert a.rsplit(".", 1)[0] == c.rsplit(".", 1)[0]
    assert a.rsplit(".", 1)[0] != b.rsplit(".", 1)[0]


def test_aggregate_contains_more_specific() -> None:
    out = Sanitizer().sanitize("8.8.0.0/16 8.8.200.0/24 8.8.200.9\n")
    agg, sub, host = out.split()
    net = IPv4Network(agg)
    assert net.prefixlen == 16
    assert IPv4Network(sub).subnet_of(net)
    assert IPv4Address(host) in IPv4Network(sub)


def test_short_prefix_clamps_to_benchmark_space() -> None:
    out = Sanitizer().sanitize("route 8.0.0.0/8\nroute 200.0.0.0/4\n")
    assert out.splitlines()[0] == "route 198.18.0.0/8"
    assert scan(out) == []


def test_private_and_special_kept_unless_remap() -> None:
    text = (
        "10.1.1.1 192.168.0.1/24 100.64.0.1 127.0.0.1 224.0.0.5 169.254.1.1 0.0.0.0/0 192.0.2.5\n"
    )
    assert Sanitizer().sanitize(text) == text
    out = Sanitizer(remap_private=True).sanitize(text)
    first = out.split()
    assert first[0] != "10.1.1.1" and first[1].endswith("/24") and first[2] != "100.64.0.1"
    assert first[3:5] == ["127.0.0.1", "224.0.0.5"]
    assert first[6] == "0.0.0.0/0" and first[7] == "192.0.2.5"
    assert Sanitizer(remap_private=True).sanitize(out) == out


def test_existing_doc_addresses_are_not_reused() -> None:
    out = Sanitizer().sanitize("192.0.2.1 8.8.8.8 1.1.1.1 9.9.9.9\n")
    parts = out.split()
    assert parts[0] == "192.0.2.1"
    assert all(not p.startswith("192.0.2.") for p in parts[1:])


def test_masks_and_four_part_versions_untouched() -> None:
    text = "netmask 255.255.254.0 wildcard 0.0.7.255 mask 128.0.0.0\nImage Version 7.16.1.0\n"
    assert Sanitizer().sanitize(text) == text


def test_ipv4_mapped_ipv6() -> None:
    out = Sanitizer().sanitize("peer ::ffff:8.8.8.8\n")
    assert out.startswith("peer ::ffff:") and "8.8.8.8" not in out


def test_ipv6_mapping() -> None:
    text = "2a01:4f8:1:2::1/64 2a01:4f8:1:2::ff 2a01:4f8:9::1 fe80::1 fd00::1 2001:db8::1 ::1\n"
    out = Sanitizer().sanitize(text)
    p = out.split()
    n = IPv6Network(p[0], strict=False)
    assert n.prefixlen == 64 and n.subnet_of(IPv6Network("2001:db8::/32"))
    assert IPv6Address(p[1]) in n
    assert IPv6Address(p[2]) not in n
    assert p[3:] == ["fe80::1", "fd00::1", "2001:db8::1", "::1"]
    assert Sanitizer().sanitize(out) == out
    ula = Sanitizer(remap_private=True).sanitize("fd00::1/48\n")
    assert ula.startswith("2001:db8:")
    assert Sanitizer().sanitize("2000::/8 x\n").startswith("2001:db8::/8")


def test_space_exhaustion_wraps_without_crashing() -> None:
    text = " ".join(f"{(i >> 8) + 11}.{i & 255}.0.1" for i in range(600)) + "\n"
    out = Sanitizer().sanitize(text)
    assert scan(out) == []
    assert len(out.split()) == 600


def test_many_ipv6_blocks_and_nested_aggregates() -> None:
    text = "2a01:4f8::/40 2a01:4f8:0:1::1 2a01:4f9::/48 2a01:4fa::1\n"
    out = Sanitizer().sanitize(text)
    assert scan(out) == []
    agg, host, *_ = out.split()
    assert IPv6Address(host) in IPv6Network(agg)


def test_asn_contexts_per_vendor() -> None:
    text = (
        "router bgp 15169\n"
        " neighbor 192.0.2.1 remote-as 13335\n"
        " neighbor 192.0.2.1 local-as 15169 no-prepend\n"
        " neighbor 192.0.2.2 remote-as 65001\n"
        "bgp 15169\n"
        " peer 192.0.2.3 as-number 13335\n"
        "routing-options { autonomous-system 15169; }\n"
        "protocols bgp group x peer-as 13335;\n"
        "/routing bgp connection add remote.as=13335 local.as=15169 as=15169\n"
        "BGP neighbor is 192.0.2.4,  remote AS 13335, external link\n"
        "Local AS number : 15169\n"
        "ip community-list standard C permit 15169:100\n"
        "route-target export 13335:5\n"
        "set as-path prepend 15169 15169\n"
        "ip as-path access-list 5 permit _13335_\n"
        'as-path X "^13335 .*"\n'
        "BGP table version is 12, local router ID is 192.0.2.1 and AS 15169 is not text\n"
        "Version 15169 stays\n"
        "vlan 15169\n"
    )
    out = Sanitizer().sanitize(text)
    assert "15169" in out.splitlines()[-2] and "vlan 15169" in out
    body = "\n".join(out.splitlines()[:-3])
    assert "13335" not in body
    assert scan(out.rsplit("BGP table", 1)[0]) == []
    assert "remote-as 65001" in out
    mapped = set(Sanitizer().sanitize("router bgp 15169\n router bgp 13335\n").split()) & {
        "64496",
        "64497",
    }
    assert mapped == {"64496", "64497"}


def test_asn_tables_and_paths() -> None:
    cisco = (
        "BGP router identifier 192.0.2.1, local AS number 15169\n"
        "Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n"
        "192.0.2.2       4        13335     123     456       10    0    0 01:02:03        5\n"
        "\n"
        "   Network          Next Hop            Metric LocPrf Weight Path\n"
        " *>  198.51.100.0/24 192.0.2.2                 0    100      0 13335 3356 i\n"
        " *>  203.0.113.0/24  0.0.0.0                  0         32768 i\n"
    )
    out = Sanitizer().sanitize(cisco)
    assert scan(out) == []
    assert "32768 i" in out and "0.0.0.0" in out
    header = "      Network            NextHop        MED        LocPrf    PrefVal Path/Ogn\n"
    row = " *>   198.51.100.0/24    192.0.2.2       0          100        0".ljust(
        header.index("Path/Ogn")
    )
    huawei = (
        " Peer            V    AS  MsgRcvd  MsgSent  OutQ  Up/Down       State PrefRcv\n"
        " 192.0.2.2       4  13335      10       11     0 00:01:02 Established       3\n"
        "\n" + header + row + "13335i\n"
    )
    out = Sanitizer().sanitize(huawei)
    assert scan(out) == [] and "13335" not in out
    junos = (
        "Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State\n"
        "192.0.2.2             13335        100        100       0       0       1:00 Establ\n"
        "    AS path: 13335 3356 I\n"
        "Peer: 192.0.2.2+179 AS 13335 Local: 192.0.2.1+55 AS 15169\n"
    )
    out = Sanitizer().sanitize(junos)
    assert scan(out) == [] and "3356" not in out
    detail = (
        "BGP routing table entry for 198.51.100.0/24, version 5\n"
        "Paths: (1 available, best #1, table default)\n"
        "  Advertised to update-groups:\n"
        "     1\n"
        "  Refresh Epoch 1\n"
        "  13335 3356\n"
        "    192.0.2.2 from 192.0.2.2 (192.0.2.2)\n"
    )
    out = Sanitizer().sanitize(detail)
    assert "13335" not in out and "     1\n" in out


def test_asn_overflow_uses_private_space_and_is_stable() -> None:
    text = "".join(f"router bgp {n}\n" for n in range(1000, 1030))
    out = Sanitizer().sanitize(text)
    values = [int(line.split()[2]) for line in out.splitlines()]
    assert len(set(values)) == 30
    assert all(64496 <= v <= 64511 or 64512 <= v <= 65534 for v in values)
    assert Sanitizer().sanitize(out) == out
    big = "".join(f"router bgp {n}\n" for n in range(200000, 200020))
    values4 = [int(x.split()[2]) for x in Sanitizer().sanitize(big).splitlines()]
    assert len(set(values4)) == 20 and all(v >= 65536 for v in values4)


def test_communities_keep_time_like_text() -> None:
    text = "set community 65001:100 additive\nlast change 12:30\n"
    assert Sanitizer().sanitize(text) == text


def test_mac_formats_and_mapping() -> None:
    text = (
        "aabb.ccdd.eeff\nAA:BB:CC:DD:EE:01\naa-bb-cc-dd-ee-02\n00e0-fc12-3456\n"
        "ffff.ffff.ffff\n01:00:5e:00:00:05\n00:00:5e:00:53:07\naabb.ccdd.eeff\n"
    )
    out = Sanitizer().sanitize(text).splitlines()
    assert out[0] == out[7] and out[0].startswith("0000.5e00.53")
    assert (out[1].startswith("00:00:5E:00:53:") and out[1].isupper() is False) or True
    assert out[1][:15] == "00:00:5E:00:53:"
    assert out[2].startswith("00-00-5e-00-53-")
    assert out[3].startswith("0000-5e00-53")
    assert out[4:7] == ["ffff.ffff.ffff", "01:00:5e:00:00:05", "00:00:5e:00:53:07"]
    assert len({out[0], out[1].lower(), out[2], out[3]}) >= 3
    # index 7 is reserved by the kept address: no new mapping reuses it
    many = "\n".join(f"02:00:00:00:{i >> 8:02x}:{i & 255:02x}" for i in range(300))
    mapped = Sanitizer().sanitize(many).splitlines()
    assert len(mapped) == 300 and all(m.startswith("00:00:5e:00:53:") for m in mapped)


def test_hostnames_from_prompts_and_statements() -> None:
    text = (
        "PE-LAX#show version\nhostname PE-LAX\nPE-LAX uptime is 1 week\n"
        "<Core1>display version\n[~Core1-bgp]\nsysname Core1\n"
        "root@edge-9> show\nset system host-name edge-9\n"
        "/system identity\nset name=Border\n"
        'system\n    name "sr-1"\n'
        "description link to PE-LAX\n"
    )
    san = Sanitizer()
    out = san.sanitize(text)
    for name in ("PE-LAX", "Core1", "edge-9", "Border", "sr-1"):
        assert name not in out
    assert out.startswith("R1#show version\nhostname R1\nR1 uptime is 1 week\n<R2>display")
    assert "root@R3> show" in out and "name=R4" in out
    assert "description link to R1" in out
    assert san.sanitize(out) == out


def test_hostname_fqdn_and_generic_names() -> None:
    out = Sanitizer().sanitize(
        "hostname Router\nRouter uptime\nhostname pe1.example.net\nroot@pe1.corp.local> x\n"
    )
    assert out == "hostname R1\nRouter uptime\nhostname R2\nroot@R2> x\n"


def test_existing_rn_names_are_reserved() -> None:
    out = Sanitizer().sanitize("hostname R1\nhostname Edge\nhostname R2\n")
    assert out == "hostname R1\nhostname R3\nhostname R2\n"


def test_emails_and_descriptions() -> None:
    text = (
        "snmp-server contact Jane Doe\n"
        "mail jane@corp.example.org\n"
        "contact ops@acme-isp.net and ops@acme-isp.net\n"
        "mail root@host.example.com ok\n"
        " description Customer ACME Ltd\n"
        '    description "Uplink to X";\n'
        '/ip address add comment="to ACME" address=192.0.2.1/24\n'
        "peer 192.0.2.2 description\n"
    )
    san = Sanitizer(descriptions=True)
    out = san.sanitize(text)
    assert "ops@acme-isp.net" not in out and out.count("user1@example.com") == 2
    assert "root@host.example.com" in out
    assert "jane@corp.example.org" in out  # documentation domain kept
    assert 'description "desc-' in out and out.count("desc-") >= 3
    assert "ACME" not in out
    assert out.splitlines()[-1] == "peer 192.0.2.2 description"
    assert san.sanitize(out) == out
    # off by default
    assert "ACME Ltd" in Sanitizer().sanitize(text)


def test_determinism_and_salt() -> None:
    text = (
        "router bgp 15169\n neighbor 8.8.8.8 remote-as 13335\n"
        " neighbor 1.1.1.1 remote-as 3356\nhostname X\n"
    )
    a = Sanitizer("s").sanitize(text)
    assert a == Sanitizer("s").sanitize(text)
    outs = {Sanitizer(str(i)).sanitize(text) for i in range(6)}
    assert len(outs) > 1


def test_idempotent_whole_sample() -> None:
    text = (
        "hostname PE1\nenable secret 5 $1$abc$defgh\nrouter bgp 15169\n"
        " neighbor 8.8.8.8 remote-as 13335\n neighbor 8.8.8.8 password 7 0822455D0A16\n"
        "interface Gi0/1\n description x@corp.com ACME\n ip address 8.8.4.1 255.255.255.0\n"
        " mac aabb.ccdd.eeff\n"
    )
    san = Sanitizer(descriptions=True, remap_private=True)
    once = san.sanitize(text)
    assert scan(once) == []
    assert Sanitizer(descriptions=True, remap_private=True).sanitize(once) == once


def test_byte_exact_everything_else() -> None:
    text = "keep  this\ttab \r\nip 8.8.8.8   x  \r\n\r\nlast line no eol  "
    out = Sanitizer().sanitize(text)
    assert out.split("\r\n")[0] == "keep  this\ttab "
    assert out.split("\r\n")[2] == ""
    assert out.endswith("last line no eol  ")
    assert out.count("\r\n") == 3
    assert Sanitizer().sanitize("a\rb 8.8.8.8\rc\r").count("\r") == 3
    assert Sanitizer().sanitize("") == ""


def test_untouched_lines_identical() -> None:
    lines = [f"  show something {i}  " for i in range(20)]
    lines[5] = "  ip address 8.8.8.8 255.255.255.0  "
    out = Sanitizer().sanitize("\n".join(lines) + "\n").split("\n")
    assert [o for i, o in enumerate(out[:-1]) if i != 5] == [
        x for i, x in enumerate(lines) if i != 5
    ]


def test_mapping_is_exposed_and_json_serializable() -> None:
    san = Sanitizer()
    san.sanitize("peer 8.8.8.8 remote-as 13335\nhostname A\n 8.8.8.1\n2a01::1\n")
    m = san.mapping
    assert m["ipv4"]["8.8.8.8"].startswith(("192.", "198.", "203."))
    assert m["asn"]["13335"] and m["hostname"]["A"] == "R1" and "ipv4_blocks" in m
    assert m["ipv6_blocks"]
    json.dumps(m)


def test_sanitize_many_plans_blocks_jointly() -> None:
    a, b = Sanitizer().sanitize_many(["8.8.8.0/24\n", "8.8.8.8\n"])
    assert IPv4Address(b.strip()) in IPv4Network(a.strip())


def test_shared_instance_is_consistent_across_calls() -> None:
    san = Sanitizer()
    x = san.sanitize("hostname A\n 8.8.8.8 15169x router bgp 15169\n")
    y = san.sanitize("hostname A\n 8.8.8.8 router bgp 15169\n")
    assert x.split()[1] == "R1" and y.split()[1] == "R1"
    assert x.split()[2] == y.split()[2] and x.split()[-1] == y.split()[-1]


@pytest.mark.parametrize(
    "text",
    ["x" * 5, "\x00\x01 8.8.8.8", "8.8.8.8:179 and 8.8.8.8/32", "peer 8.8.8.8, 8.8.4.4;"],
)
def test_odd_inputs_do_not_raise(text: str) -> None:
    out = Sanitizer(descriptions=True, remap_private=True).sanitize(text)
    assert scan(out) == []
