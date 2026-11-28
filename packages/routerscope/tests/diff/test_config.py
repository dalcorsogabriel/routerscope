# ruff: noqa: E501
"""Hierarchical config diff: per-vendor behaviour, reordering, whitespace, volatile lines."""

from __future__ import annotations

import json

import pytest
from routerscope.services.diff import (
    ConfigDiffOptions,
    diff_config,
)


def flat(diff_text_a: str, diff_text_b: str, vendor: str | None, **kw: bool) -> list[str]:
    """``op path :: text`` for each top-most change."""
    options = ConfigDiffOptions(**kw)
    out = diff_config(diff_text_a, diff_text_b, vendor, options=options)
    return [
        f"{c.op[0]} {' > '.join(c.path)} :: {c.text}" if c.path else f"{c.op[0]} :: {c.text}"
        for c in out.changes()
    ]


# --------------------------------------------------------------------------- IOS


IOS_A = """\
Building configuration...

Current configuration : 2048 bytes
!
! Last configuration change at 10:00:00 UTC Mon Nov 2 2026 by admin
!
hostname R1
!
interface GigabitEthernet0/0/1
 description uplink
 ip address 192.0.2.1 255.255.255.252
!
interface Loopback0
 ip address 192.0.2.255 255.255.255.255
!
router bgp 64496
 neighbor 192.0.2.2 remote-as 64497
 neighbor 192.0.2.2 description PEER-A
!
ip access-list extended EDGE-IN
 permit tcp any host 192.0.2.1 eq 22
 deny ip any any
!
ip prefix-list CUST permit 198.51.100.0/24
ip prefix-list CUST permit 203.0.113.0/24
ntp clock-period 17179869
end
"""

IOS_B = """\
Building configuration...

Current configuration : 2100 bytes
!
! Last configuration change at 11:30:00 UTC Tue Nov 3 2026 by admin
!
hostname R1
!
interface Loopback0
 ip address 192.0.2.255 255.255.255.255
!
interface GigabitEthernet0/0/1
 description uplink to PE1
 ip address 192.0.2.1 255.255.255.252
 ip ospf cost 10
!
router bgp 64496
 neighbor 192.0.2.2 description PEER-A
 neighbor 192.0.2.2 remote-as 64497
 neighbor 203.0.113.9 remote-as 64498
!
ip access-list extended EDGE-IN
 permit tcp any host 192.0.2.1 eq 22
 deny ip any any
!
ip prefix-list CUST permit 198.51.100.0/24
ip prefix-list CUST permit 203.0.113.0/24
ntp clock-period 17179999
end
"""


def test_ios_shows_changes_under_parent_and_ignores_noise_and_reordering() -> None:
    diff = diff_config(IOS_A, IOS_B, "cisco_ios")
    assert flat(IOS_A, IOS_B, "cisco_ios") == [
        "r interface GigabitEthernet0/0/1 :: description uplink",
        "a interface GigabitEthernet0/0/1 :: description uplink to PE1",
        "a interface GigabitEthernet0/0/1 :: ip ospf cost 10",
        "a router bgp 64496 :: neighbor 203.0.113.9 remote-as 64498",
    ]
    assert diff.stats == {"added": 3, "removed": 1}
    assert diff.ignored_volatile_old == 3 and diff.ignored_volatile_new == 3
    assert not diff.is_empty


def test_ios_render_text_and_line_numbers() -> None:
    diff = diff_config(IOS_A, IOS_B, "cisco_ios")
    text = diff.render_text()
    assert text.splitlines()[:2] == ["--- old", "+++ new"]
    assert (
        " interface GigabitEthernet0/0/1\n-  description uplink\n+  description uplink to PE1"
        in text
    )
    numbered = diff.render_text(line_numbers=True, old_label="a", new_label="b")
    assert "--- a" in numbered
    # old line 10 (description) / new line 13
    assert "    10        -  description uplink" in numbered
    assert "          13 +  description uplink to PE1" in numbered


def test_ios_json_structure() -> None:
    data = diff_config(IOS_A, IOS_B, "cisco_ios").to_dict()
    json.dumps(data)
    assert data["vendor"] == "cisco_ios"
    assert data["old_format"] == "indent"
    change = data["changes"][0]  # type: ignore[index]
    assert change["path"] == ["interface GigabitEthernet0/0/1"]
    assert change["old_lines"] == [10, 10] and change["new_lines"] is None
    tree = data["tree"][0]  # type: ignore[index]
    assert tree["status"] == "context" and tree["old_lines"][0] == 9
    assert {c["status"] for c in tree["children"]} == {"added", "removed"}


def test_identical_and_reorder_only_is_empty() -> None:
    assert diff_config(IOS_A, IOS_A, "cisco_ios").is_empty
    a = "interface A\n description x\n mtu 1500\ninterface B\n shutdown\n"
    b = "interface B\n shutdown\ninterface A\n mtu 1500\n description x\n"
    diff = diff_config(a, b, "cisco_ios")
    assert diff.is_empty and diff.render_text() == ""


def test_added_and_removed_blocks_carry_their_subtree() -> None:
    a = "hostname R1\n"
    b = "hostname R1\ninterface Loopback9\n description x\n ip address 192.0.2.9 255.255.255.255\n"
    diff = diff_config(a, b, "cisco_ios")
    (change,) = diff.changes()
    assert change.op == "added" and change.statements == 3 and change.new_lines == (2, 4)
    back = diff_config(b, a, "cisco_ios")
    assert [c.op for c in back.changes()] == ["removed"] and back.stats["removed"] == 3
    assert "-interface Loopback9\n-  description x" in back.render_text()


def test_whitespace_only_changes_ignored_by_default() -> None:
    a = 'interface A\n description   "two  spaces"\n ip address 192.0.2.1 255.255.255.0 \n'
    b = 'interface A\n description "two  spaces"\n ip	address 192.0.2.1  255.255.255.0\n'
    # inner whitespace runs (and tabs) are collapsed
    assert diff_config(a, b, "cisco_ios").is_empty
    shown = flat(a, b, "cisco_ios", show_whitespace=True)
    assert shown == [
        'r interface A :: description   "two  spaces"',
        "r interface A :: ip address 192.0.2.1 255.255.255.0",
        'a interface A :: description "two  spaces"',
        "a interface A :: ip	address 192.0.2.1  255.255.255.0",
    ]
    # whitespace inside quotes is a real change
    c = 'interface A\n description "two spaces"\n'
    d = 'interface A\n description "two  spaces"\n'
    assert not diff_config(c, d, "cisco_ios").is_empty


def test_squeeze_keeps_quoted_text_and_escapes() -> None:
    a = 'x   "a \\" b"   y\n'
    b = 'x "a \\" b" y\n'
    assert diff_config(a, b, "cisco_ios").is_empty
    assert not diff_config('x "a  b"\n', 'x "a b"\n', "cisco_ios").is_empty
    # banners keep their line structure
    banner_a = "banner motd ^C\nline  one\nline two\n^C\n"
    banner_b = "banner motd ^C\nline one\nline two\n^C\n"
    assert diff_config(banner_a, banner_b, "cisco_ios").is_empty
    banner_c = "banner motd ^C\nline one\nline three\n^C\n"
    text = diff_config(banner_a, banner_c, "cisco_ios").render_text(line_numbers=True)
    assert "-banner motd ^C" in text and "+banner motd ^C" in text
    assert "line three" in text


def test_ios_ordered_sections() -> None:
    reordered = IOS_B.replace(
        " permit tcp any host 192.0.2.1 eq 22\n deny ip any any\n",
        " deny ip any any\n permit tcp any host 192.0.2.1 eq 22\n",
    )
    changes = flat(IOS_B, reordered, "cisco_ios")
    assert any(c.startswith("a ip access-list extended EDGE-IN :: ") for c in changes)
    assert any(c.startswith("r ip access-list extended EDGE-IN :: ") for c in changes)
    # numbered ACL entries carry their own order: reordering is not a change
    n1 = "ip access-list extended X\n 10 permit ip any any\n 20 deny ip any any\n"
    n2 = "ip access-list extended X\n 20 deny ip any any\n 10 permit ip any any\n"
    assert diff_config(n1, n2, "cisco_ios").is_empty
    # prefix lists without seq are ordered, with seq are not
    p1 = "ip prefix-list P permit 192.0.2.0/24\nip prefix-list P deny 0.0.0.0/0 le 32\n"
    p2 = "ip prefix-list P deny 0.0.0.0/0 le 32\nip prefix-list P permit 192.0.2.0/24\n"
    assert not diff_config(p1, p2, "cisco_ios").is_empty
    s1 = (
        "ip prefix-list P seq 5 permit 192.0.2.0/24\nip prefix-list P seq 10 deny 0.0.0.0/0 le 32\n"
    )
    s2 = (
        "ip prefix-list P seq 10 deny 0.0.0.0/0 le 32\nip prefix-list P seq 5 permit 192.0.2.0/24\n"
    )
    assert diff_config(s1, s2, "cisco_ios").is_empty
    # unordered siblings next to ordered ones are still unordered
    assert diff_config(
        "access-list 10 permit any\nhostname A\n",
        "hostname A\naccess-list 10 permit any\n",
        "cisco_ios",
    ).is_empty
    acl_a = "access-list 10 permit 192.0.2.0 0.0.0.255\naccess-list 10 deny any\n"
    acl_b = "access-list 10 deny any\naccess-list 10 permit 192.0.2.0 0.0.0.255\n"
    assert not diff_config(acl_a, acl_b, "cisco_ios").is_empty
    # policy-map: class order matters
    pm_a = (
        "policy-map QOS\n class VOICE\n  priority percent 10\n class DATA\n  bandwidth percent 50\n"
    )
    pm_b = (
        "policy-map QOS\n class DATA\n  bandwidth percent 50\n class VOICE\n  priority percent 10\n"
    )
    assert not diff_config(pm_a, pm_b, "cisco_ios").is_empty


def test_ios_volatile_filter_options() -> None:
    a = "hostname R1\nntp clock-period 1\nsnmp-server location lab-1\n"
    b = "hostname R1\nntp clock-period 2\nsnmp-server location lab-2\n"
    assert flat(a, b, "cisco_ios") == [
        "r :: snmp-server location lab-1",
        "a :: snmp-server location lab-2",
    ]
    assert len(flat(a, b, "cisco_ios", ignore_volatile_lines=False)) == 4
    extra = ConfigDiffOptions(extra_volatile_lines=(r"snmp-server location .*",))
    assert diff_config(a, b, "cisco_ios", options=extra).is_empty
    # unknown vendor: no built-in filter, but extras still apply
    assert len(flat(a, b, None)) == 4
    assert diff_config(a, b, None, options=extra).stats == {"added": 1, "removed": 1}
    # a block that merely starts like a volatile line is never dropped
    blk = "Building configuration...\n x\n"
    assert not diff_config(blk, "", "cisco_ios").is_empty


# --------------------------------------------------------------------------- OcNOS


OCNOS_A = """\
!
hostname PE1
!
interface xe1
 description core
 ip address 192.0.2.1/30
!
router bgp 64496
 neighbor 192.0.2.2 remote-as 64497
!
"""
OCNOS_B = OCNOS_A.replace("description core", "description core-1").replace(
    " neighbor 192.0.2.2 remote-as 64497\n",
    " neighbor 192.0.2.2 remote-as 64497\n neighbor 192.0.2.2 shutdown\n",
)


def test_ocnos() -> None:
    assert flat(OCNOS_A, OCNOS_B, "ipinfusion_ocnos") == [
        "r interface xe1 :: description core",
        "a interface xe1 :: description core-1",
        "a router bgp 64496 :: neighbor 192.0.2.2 shutdown",
    ]
    assert diff_config(
        "ip prefix-list A permit 192.0.2.0/24\nip prefix-list A deny any\n",
        "ip prefix-list A deny any\nip prefix-list A permit 192.0.2.0/24\n",
        "ipinfusion_ocnos",
    ).stats == {"added": 1, "removed": 1}


# --------------------------------------------------------------------------- XR


XR_A = """\
Mon Nov  2 10:00:00.123 UTC
Building configuration...
!! IOS XR Configuration 7.9.1
!! Last configuration change at Mon Nov  2 09:59:00 2026 by admin
!
hostname PE1
interface TenGigE0/0/0/1
 description to-P1
 ipv4 address 192.0.2.1 255.255.255.252
!
prefix-set CUST
  198.51.100.0/24,
  203.0.113.0/24
end-set
!
route-policy PASS
  if destination in CUST then
    pass
  else
    drop
  endif
end-policy
!
router bgp 64496
 neighbor 192.0.2.2
  remote-as 64497
  address-family ipv4 unicast
   route-policy PASS in
  !
 !
!
end
"""
XR_B = XR_A.replace("Mon Nov  2 10:00:00.123 UTC", "Tue Nov  3 11:11:11.999 UTC").replace(
    "Last configuration change at Mon Nov  2 09:59:00",
    "Last configuration change at Tue Nov  3 11:10:00",
)


def test_xr_volatile_header_lines_ignored() -> None:
    diff = diff_config(XR_A, XR_B, "cisco_xr")
    assert diff.is_empty
    assert diff.ignored_volatile_old == 3  # timestamp, Building configuration..., !! Last change


def test_xr_route_policy_body_is_ordered_and_nested() -> None:
    swapped = XR_A.replace("    pass\n  else\n    drop\n", "    drop\n  else\n    pass\n")
    changes = flat(XR_A, swapped, "cisco_xr")
    assert changes
    assert all(" route-policy PASS" in c or "route-policy PASS" in c for c in changes)
    edited = XR_A.replace(" description to-P1", " description to-P2")
    assert flat(XR_A, edited, "cisco_xr") == [
        "r interface TenGigE0/0/0/1 :: description to-P1",
        "a interface TenGigE0/0/0/1 :: description to-P2",
    ]
    nested = XR_A.replace("route-policy PASS in", "route-policy BLOCK in")
    assert flat(XR_A, nested, "cisco_xr") == [
        "r router bgp 64496 > neighbor 192.0.2.2 > address-family ipv4 unicast :: route-policy PASS in",
        "a router bgp 64496 > neighbor 192.0.2.2 > address-family ipv4 unicast :: route-policy BLOCK in",
    ]
    acl_a = "ipv4 access-list X\n 10 permit ipv4 any any\n 20 deny ipv4 any any\n"
    acl_b = "ipv4 access-list X\n 20 deny ipv4 any any\n 10 permit ipv4 any any\n"
    assert diff_config(acl_a, acl_b, "cisco_xr").is_empty
    bare_a = "ipv4 access-list X\n permit ipv4 any any\n deny ipv4 any any\n"
    bare_b = "ipv4 access-list X\n deny ipv4 any any\n permit ipv4 any any\n"
    assert not diff_config(bare_a, bare_b, "cisco_xr").is_empty


# --------------------------------------------------------------------------- VRP


VRP_A = """\
!Software Version V800R021C10SPC100
!Last configuration was updated at 2026-11-02 10:00:00+00:00
!Last configuration was saved at 2026-11-02 10:00:05+00:00
#
 sysname PE1
#
interface GigabitEthernet0/0/1
 description to-P1
 ip address 192.0.2.1 255.255.255.252
#
acl number 3000
 rule 5 permit ip source 192.0.2.0 0.0.0.255
 rule 10 deny ip
#
acl name EDGE advance
 rule permit tcp destination-port eq 22
 rule deny ip
#
bgp 64496
 peer 192.0.2.2 as-number 64497
#
return
"""


def test_vrp_header_lines_and_acl_rules() -> None:
    b = (
        VRP_A.replace("V800R021C10SPC100", "V800R021C10SPC200")
        .replace("10:00:00", "12:00:00")
        .replace("10:00:05", "12:00:05")
    )
    diff = diff_config(VRP_A, b, "huawei_vrp")
    assert diff.is_empty and diff.ignored_volatile_old == 3
    renumbered = VRP_A.replace(
        " rule 5 permit ip source 192.0.2.0 0.0.0.255\n rule 10 deny ip\n",
        " rule 10 deny ip\n rule 5 permit ip source 192.0.2.0 0.0.0.255\n",
    )
    assert diff_config(VRP_A, renumbered, "huawei_vrp").is_empty
    bare = VRP_A.replace(
        " rule permit tcp destination-port eq 22\n rule deny ip\n",
        " rule deny ip\n rule permit tcp destination-port eq 22\n",
    )
    assert not diff_config(VRP_A, bare, "huawei_vrp").is_empty
    edited = VRP_A.replace("peer 192.0.2.2 as-number 64497", "peer 192.0.2.2 as-number 64498")
    assert flat(VRP_A, edited, "huawei_vrp") == [
        "r bgp 64496 :: peer 192.0.2.2 as-number 64497",
        "a bgp 64496 :: peer 192.0.2.2 as-number 64498",
    ]


# --------------------------------------------------------------------------- Junos


JUNOS_BRACE_A = """\
## Last commit: 2026-11-02 10:00:00 UTC by admin
version 20.4R3.8;
system {
    host-name PE1;
}
interfaces {
    ge-0/0/0 {
        description "to P1";
        unit 0 {
            family inet {
                address 192.0.2.1/30;
            }
        }
    }
}
policy-options {
    policy-statement EXPORT {
        term T1 {
            from protocol static;
            then accept;
        }
        term T2 {
            then reject;
        }
    }
    prefix-list CUST {
        198.51.100.0/24;
        203.0.113.0/24;
    }
}
protocols {
    bgp {
        group EBGP {
            neighbor 192.0.2.2 {
                peer-as 64497;
            }
        }
    }
}
"""


def test_junos_brace_changes_and_noise() -> None:
    b = (
        JUNOS_BRACE_A.replace("10:00:00", "12:00:00")
        .replace('description "to P1"', 'description "to P2"')
        .replace(
            "                peer-as 64497;\n",
            "                peer-as 64498;\n                inactive: description x;\n",
        )
    )
    assert flat(JUNOS_BRACE_A, b, "juniper_junos") == [
        'r interfaces > ge-0/0/0 :: description "to P1"',
        'a interfaces > ge-0/0/0 :: description "to P2"',
        "r protocols > bgp > group EBGP > neighbor 192.0.2.2 :: peer-as 64497",
        "a protocols > bgp > group EBGP > neighbor 192.0.2.2 :: peer-as 64498",
        "a protocols > bgp > group EBGP > neighbor 192.0.2.2 :: inactive: description x",
    ]
    # reordering sibling blocks and prefix-list members is not a change
    c = JUNOS_BRACE_A.replace(
        "        198.51.100.0/24;\n        203.0.113.0/24;\n",
        "        203.0.113.0/24;\n        198.51.100.0/24;\n",
    )
    assert diff_config(JUNOS_BRACE_A, c, "juniper_junos").is_empty


def test_junos_policy_terms_are_ordered() -> None:
    swapped = JUNOS_BRACE_A.replace(
        "        term T1 {\n            from protocol static;\n            then accept;\n        }\n"
        "        term T2 {\n            then reject;\n        }\n",
        "        term T2 {\n            then reject;\n        }\n"
        "        term T1 {\n            from protocol static;\n            then accept;\n        }\n",
    )
    changes = flat(JUNOS_BRACE_A, swapped, "juniper_junos")
    assert changes and all("policy-statement EXPORT" in c for c in changes)
    then_a = "policy-options {\n policy-statement P {\n term T {\n then {\n community add X;\n accept;\n }\n }\n }\n}\n"
    then_b = then_a.replace("community add X;\n accept;", "accept;\n community add X;")
    assert not diff_config(then_a, then_b, "juniper_junos").is_empty
    from_a = then_a.replace("then {", "from {").replace(
        "community add X;\n accept;", "protocol bgp;\n route-filter 192.0.2.0/24 exact;"
    )
    from_b = from_a.replace(
        "protocol bgp;\n route-filter 192.0.2.0/24 exact;",
        "route-filter 192.0.2.0/24 exact;\n protocol bgp;",
    )
    assert diff_config(from_a, from_b, "juniper_junos").is_empty


JUNOS_SET = """\
set version 20.4R3.8
set system host-name PE1
set interfaces ge-0/0/0 description "to P1"
set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/30
set protocols bgp group EBGP neighbor 192.0.2.2 peer-as 64497
"""


def test_junos_set_form() -> None:
    b = JUNOS_SET.replace("peer-as 64497", "peer-as 64498")
    assert flat(JUNOS_SET, b, "juniper_junos") == [
        "r protocols > bgp > group EBGP > neighbor 192.0.2.2 :: peer-as 64497",
        "a protocols > bgp > group EBGP > neighbor 192.0.2.2 :: peer-as 64498",
    ]
    off = flat(JUNOS_SET, JUNOS_SET + "deactivate protocols bgp group EBGP\n", "juniper_junos")
    assert off[-1].startswith("a protocols > bgp :: inactive: group EBGP")
    assert diff_config(JUNOS_SET, JUNOS_SET, "juniper_junos").old_format == "set"


def test_junos_set_vs_brace_compared_by_flat_paths() -> None:
    brace = """\
version 20.4R3.8;
system {
    host-name PE1;
}
interfaces {
    ge-0/0/0 {
        description "to P1";
        unit 0 {
            family inet {
                address 192.0.2.1/30;
            }
        }
    }
}
protocols {
    bgp {
        group EBGP {
            neighbor 192.0.2.2 {
                peer-as 64497;
            }
        }
    }
}
"""
    diff = diff_config(brace, JUNOS_SET, "juniper_junos")
    assert diff.is_empty, diff.render_text()
    assert (diff.old_format, diff.new_format) == ("brace->flat", "set->flat")
    edited = JUNOS_SET.replace("peer-as 64497", "peer-as 64499")
    assert flat(brace, edited, "juniper_junos") == [
        "r protocols > bgp > group EBGP > neighbor 192.0.2.2 :: peer-as 64497",
        "a protocols > bgp > group EBGP > neighbor 192.0.2.2 :: peer-as 64499",
    ]
    assert diff_config(JUNOS_SET, brace, "juniper_junos").is_empty
    # inactive statements survive the conversion
    inactive_set = JUNOS_SET + "deactivate protocols bgp group EBGP\n"
    assert flat(brace, inactive_set, "juniper_junos") == [
        "r protocols > bgp > group EBGP > neighbor 192.0.2.2 :: peer-as 64497",
        "a protocols > bgp > group EBGP > neighbor 192.0.2.2 :: inactive: peer-as 64497",
    ]
    protected = JUNOS_SET + "protect system host-name\n"
    assert not diff_config(brace, protected, "juniper_junos").is_empty


def test_inactive_and_protected_flags_are_visible() -> None:
    a = "interfaces {\n ge-0/0/0 {\n description x;\n }\n}\n"
    b = "interfaces {\n inactive: ge-0/0/0 {\n description x;\n }\n}\n"
    changes = flat(a, b, "juniper_junos")
    assert changes == [
        "r interfaces :: ge-0/0/0",
        "a interfaces :: inactive: ge-0/0/0",
    ]
    c = "interfaces {\n protect: ge-0/0/0 {\n description x;\n }\n}\n"
    assert flat(a, c, "juniper_junos")[1] == "a interfaces :: protect: ge-0/0/0"


# --------------------------------------------------------------------------- SR OS


SROS_CLASSIC_A = """\
# TiMOS-B-20.10.R2 both/x86_64 Nokia 7750 SR Copyright (c) 2000-2026 Nokia.
# Generated THU NOV 02 10:00:00 2026 UTC
echo "System Configuration"
    system
        name "PE1"
    exit
echo "Router (Network Side) Configuration"
    router Base
        interface "to-P1"
            address 192.0.2.1/30
            port 1/1/1
        exit
        bgp
            group "EBGP"
                neighbor 192.0.2.2
                    peer-as 64497
                exit
            exit
        exit
    exit
exit all
"""


def test_sros_classic() -> None:
    b = SROS_CLASSIC_A.replace("10:00:00", "11:11:11").replace("peer-as 64497", "peer-as 64498")
    assert flat(SROS_CLASSIC_A, b, "nokia_sros") == [
        'r router Base > bgp > group "EBGP" > neighbor 192.0.2.2 :: peer-as 64497',
        'a router Base > bgp > group "EBGP" > neighbor 192.0.2.2 :: peer-as 64498',
    ]


SROS_MDCLI_A = """\
# TiMOS-B-24.3.R1 both/x86_64 Nokia 7750 SR Copyright (c) 2000-2026 Nokia.
# Generated 2026-11-02T10:00:00.0Z
configure {
    system {
        name "PE1"
    }
    router "Base" {
        interface "to-P1" {
            port 1/1/c1/1
            ipv4 {
                primary {
                    address 192.0.2.1
                    prefix-length 30
                }
            }
        }
    }
}
"""
SROS_MDCLI_FLAT = """\
/configure system name "PE1"
/configure router "Base" interface "to-P1" port 1/1/c1/1
/configure router "Base" interface "to-P1" ipv4 primary address 192.0.2.1
/configure router "Base" interface "to-P1" ipv4 primary prefix-length 30
"""


def test_sros_mdcli_brace_and_flat() -> None:
    b = SROS_MDCLI_A.replace("prefix-length 30", "prefix-length 31").replace("10:00:00", "11:00:00")
    changes = flat(SROS_MDCLI_A, b, "nokia_sros")
    assert changes == [
        'r configure > router "Base" > interface "to-P1" > ipv4 > primary :: prefix-length 30',
        'a configure > router "Base" > interface "to-P1" > ipv4 > primary :: prefix-length 31',
    ]
    flat_b = SROS_MDCLI_FLAT.replace("prefix-length 30", "prefix-length 31")
    assert flat(SROS_MDCLI_FLAT, flat_b, "nokia_sros")
    assert diff_config(SROS_MDCLI_FLAT, SROS_MDCLI_FLAT, "nokia_sros").old_format == "set"
    # same configuration in both MD-CLI forms: no difference
    mixed = diff_config(SROS_MDCLI_A, SROS_MDCLI_FLAT, "nokia_sros")
    assert mixed.is_empty, mixed.render_text()
    assert mixed.old_format == "brace->flat"
    # classic vs MD-CLI are simply different (no crash)
    assert not diff_config(SROS_CLASSIC_A, SROS_MDCLI_A, "nokia_sros").is_empty


# --------------------------------------------------------------------------- RouterOS


ROS_A = """\
# 2026-11-02 10:00:00 by RouterOS 7.12
# software id = ABCD-1234
# model = RB5009
/interface bridge
add name=bridge1
/ip address
add address=192.0.2.1/24 interface=bridge1
/ip firewall filter
add action=accept chain=input protocol=icmp
add action=drop chain=input comment="drop rest"
/ip firewall address-list
add address=198.51.100.0/24 list=CUST
add address=203.0.113.0/24 list=CUST
/system identity
set name=R1
"""


def test_routeros_sections_ordering_and_noise() -> None:
    b = ROS_A.replace("10:00:00", "11:00:00").replace("name=R1", "name=R2")
    assert flat(ROS_A, b, "mikrotik_ros7") == [
        "r /system identity :: set name=R1",
        "a /system identity :: set name=R2",
    ]
    lists = ROS_A.replace(
        "add address=198.51.100.0/24 list=CUST\nadd address=203.0.113.0/24 list=CUST\n",
        "add address=203.0.113.0/24 list=CUST\nadd address=198.51.100.0/24 list=CUST\n",
    )
    assert diff_config(ROS_A, lists, "mikrotik_ros7").is_empty
    rules = ROS_A.replace(
        'add action=accept chain=input protocol=icmp\nadd action=drop chain=input comment="drop rest"\n',
        'add action=drop chain=input comment="drop rest"\nadd action=accept chain=input protocol=icmp\n',
    )
    changes = flat(ROS_A, rules, "mikrotik_ros7")
    assert changes and all("/ip firewall filter" in c for c in changes)
    continued = ROS_A.replace(
        "add address=192.0.2.1/24 interface=bridge1",
        "add address=192.0.2.1/24 \\\n    interface=bridge1",
    )
    assert diff_config(ROS_A, continued, "mikrotik_ros7").is_empty
    export_a = "/ip route add dst-address=0.0.0.0/0 gateway=192.0.2.254\n"
    export_b = "/ip route add dst-address=0.0.0.0/0 gateway=192.0.2.253\n"
    assert flat(export_a, export_b, "mikrotik_ros7") == [
        "r /ip route :: add dst-address=0.0.0.0/0 gateway=192.0.2.254",
        "a /ip route :: add dst-address=0.0.0.0/0 gateway=192.0.2.253",
    ]


# --------------------------------------------------------------------------- misc


def test_unknown_vendor_and_empty_inputs() -> None:
    assert diff_config("", "", None).is_empty
    diff = diff_config("", "a\n b\n", "no_such_vendor")
    assert diff.stats == {"added": 2, "removed": 0}
    assert diff_config("", "", "cisco_ios").render_text() == ""


def test_deep_nesting_does_not_hit_recursion_limits() -> None:
    deep = "".join(" " * i + f"n{i}\n" for i in range(300))
    other = deep + " " * 300 + "extra\n"
    diff = diff_config(deep, other, "cisco_ios")
    assert diff.stats["added"] == 1
    assert diff.render_text().count("\n") > 200
    json.dumps(diff.to_dict())
    assert diff_config(deep, "", "cisco_ios").stats["removed"] >= 200


@pytest.mark.parametrize(
    "vendor",
    [
        "cisco_ios",
        "cisco_xr",
        "huawei_vrp",
        "ipinfusion_ocnos",
        "juniper_junos",
        "mikrotik_ros7",
        "nokia_sros",
    ],
)
def test_every_vendor_handles_garbage(vendor: str) -> None:
    junk = '{{{ ]]] "unterminated\n\x00\x01\n set  \n/ \n}}}\n'
    diff_config(junk, IOS_A, vendor)
    diff_config(IOS_A, junk, vendor)


def test_squeeze_with_quotes_keeps_line_breaks() -> None:
    a = 'banner motd ^C\nsay "hi   there"   now\nsecond   line\n^C\n'
    b = 'banner motd ^C\nsay "hi   there" now\nsecond line\n^C\n'
    assert diff_config(a, b, "cisco_ios").is_empty
    c = 'banner motd ^C\nsay "hi   there" now\nsecond line two\n^C\n'
    assert not diff_config(a, c, "cisco_ios").is_empty
