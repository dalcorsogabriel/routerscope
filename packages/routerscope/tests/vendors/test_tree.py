"""Unit and property tests for the shared configuration tree parsers."""

from __future__ import annotations

import re

from hypothesis import given, settings
from hypothesis import strategies as st
from routerscope.model import split_lines
from routerscope.vendors._tree import (
    ConfigNode,
    looks_like_set,
    parse_brace,
    parse_command,
    parse_indented,
    parse_routeros,
    parse_set,
    split_tokens,
    split_words,
    unquote,
)


def texts(root: ConfigNode) -> list[str]:
    return [n.text for n in root.walk()]


# ----------------------------------------------------------------------------- words


def test_split_tokens_keeps_quotes_and_lists() -> None:
    assert split_tokens('comment="a b" mtu=1500') == ['comment="a b"', "mtu=1500"]
    assert split_tokens('policy ["A" "B"]') == ["policy", "[", '"A"', '"B"', "]"]
    assert split_tokens("as-path [0-9]+") == ["as-path", "[0-9]+"]
    assert split_tokens('x "unterminated y') == ["x", '"unterminated y']
    assert split_tokens('say "a \\" b"') == ["say", '"a \\" b"']


def test_unquote() -> None:
    assert unquote("plain") == "plain"
    assert unquote('k="a \\"b\\" \\n"') == 'k=a "b" \n'
    assert split_words('description "two words"') == ["description", "two words"]


# ----------------------------------------------------------------------------- node API


def test_node_api() -> None:
    root = parse_indented("interface Gi0\n description x\n ip address 192.0.2.1 255.255.255.0\n")
    iface = root.children[0]
    leaf = iface.children[1]
    assert leaf.path() == ("interface Gi0", "ip address 192.0.2.1 255.255.255.0")
    assert leaf.depth == 2 and iface.depth == 1 and root.depth == 0
    assert leaf.flat_words == ("interface", "Gi0", "ip", "address", "192.0.2.1", "255.255.255.0")
    assert [n.text for n in root.walk(include_self=False)] == texts(root)
    assert len(list(root.walk(include_self=True))) == 4
    assert root.find(r"interface\b") == [iface]
    assert root.find("description", recursive=False) == []
    assert iface.find("description", recursive=False)[0].text == "description x"
    assert iface.child("description") is iface.children[0]
    assert iface.child("nothing") is None
    assert root.is_root and not iface.is_root
    assert root.path() == ()
    assert "Gi0" in repr(iface)


# ----------------------------------------------------------------------------- indent


def test_ios_banner_comments_certificate_crlf() -> None:
    text = (
        "hostname R1\r\n!\r\nbanner motd ^C\r\nline one\r\n^C\r\n"
        "banner login #one-liner#\r\n"
        "crypto pki certificate chain T\r\n certificate 01\r\n  3082 0102\r\n  quit\r\n"
        "interface Gi0\r\n\tdescription tab\r\n\tshutdown\r\nend\r\n"
    )
    root = parse_indented(text)
    names = [n.text for n in root.children]
    assert names[0] == "hostname R1"
    assert names[1] == "banner motd ^C\nline one\n^C"
    assert root.children[1].line_start == 3 and root.children[1].line_end == 5
    assert names[2] == "banner login #one-liner#"
    cert = root.children[3].children[0]
    assert cert.text.endswith("quit") and cert.line_end == 10
    iface = root.children[4]
    assert [c.text for c in iface.children] == ["description tab", "shutdown"]
    assert root.children[-1].text == "end"


def test_unterminated_banner_and_certificate_are_plain_lines() -> None:
    root = parse_indented("banner motd ^C\nnever closed\n")
    assert root.children[0].text == "banner motd ^C"
    root = parse_indented("certificate 01\n not hex here\n")
    assert root.children[0].text == "certificate 01"


def test_xr_terminators_are_part_of_block() -> None:
    text = (
        "route-policy P\n  if x then\n    pass\n  endif\nend-policy\n!\n"
        "prefix-set S\n  192.0.2.0/24,\n  198.51.100.0/24\nend-set\n!\nend-set\n"
    )
    root = parse_indented(text, "xr")
    policy, pset, stray = root.children
    assert (policy.line_start, policy.line_end) == (1, 5)
    assert (pset.line_start, pset.line_end) == (7, 10)
    assert stray.text == "end-set"
    assert len(pset.children) == 2


def test_vrp_hash_separators() -> None:
    root = parse_indented(
        "#\nsysname R1\n#\ninterface G0/0/1\n ip address 192.0.2.1 24\n#\nreturn\n", "vrp"
    )
    assert texts(root) == ["sysname R1", "interface G0/0/1", "ip address 192.0.2.1 24", "return"]


def test_sros_exit_and_echo() -> None:
    text = (
        'echo "x"\n    router Base\n        interface "a"\n            address 192.0.2.1/31\n'
        "        exit\n    exit\nexit all\n"
    )
    root = parse_indented(text, "sros")
    assert [n.text for n in root.children] == ['echo "x"', "router Base", "exit all"]
    router = root.children[1]
    assert (router.line_start, router.line_end) == (2, 6)
    assert router.children[0].line_end == 5


def test_sros_stray_exit_is_a_node() -> None:
    root = parse_indented("exit\n", "sros")
    assert texts(root) == ["exit"]


# ----------------------------------------------------------------------------- brace


def test_junos_brace_features() -> None:
    text = (
        "/* header\n   comment */\n## annotation\n"
        "interfaces {\n"
        "    inactive: ge-0/0/0 {\n"
        '        description "a { b; c }";\n'
        "        protect: unit 0 {\n"
        "            family inet { address 192.0.2.1/31; }\n"
        "        }\n"
        "    }\n"
        "}\n"
        "policy-options { community X members [ 64496:1 64496:2 ]; }\n"
    )
    root = parse_brace(text)
    iface = root.children[0].children[0]
    assert iface.text == "ge-0/0/0" and iface.inactive
    assert iface.children[0].text == 'description "a { b; c }"'
    unit = iface.children[1]
    assert unit.protected and unit.text == "unit 0"
    assert unit.children[0].children[0].text == "address 192.0.2.1/31"
    comm = root.children[1].children[0]
    assert comm.words == ["community", "X", "members", "[", "64496:1", "64496:2", "]"]
    assert (iface.line_start, iface.line_end) == (5, 10)


def test_junos_multiline_statement_and_unbalanced() -> None:
    root = parse_brace("a b\n  c d;\nx {\n  y;\n")
    assert root.children[0].text == "a b c d"
    assert (root.children[0].line_start, root.children[0].line_end) == (1, 2)
    x = root.children[1]
    assert x.line_end >= 4
    root = parse_brace("}\n}\nlone\n")
    assert texts(root) == ["lone"]
    assert parse_brace("/* never closed").children == []


def test_mdcli_newline_terminated() -> None:
    text = (
        '# comment\nconfigure {\n    router "Base" {\n        port 1/1/1\n'
        '        import [\n "A"\n ]\n    }\n}\n'
    )
    root = parse_brace(text, "mdcli")
    router = root.children[0].children[0]
    assert router.text == 'router "Base"'
    assert router.children[0].text == "port 1/1/1"
    assert router.children[1].words == ["import", "[", "A", "]"]


# ----------------------------------------------------------------------------- set style


def test_set_style_matches_brace_flat_words() -> None:
    brace = parse_brace(
        "interfaces { ge-0/0/0 { unit 0 { family inet { address 192.0.2.1/31; } } } }\n"
        "protocols { bgp { group G { neighbor 192.0.2.2 { peer-as 64496; } } } }\n"
    )
    flat = parse_set(
        "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/31\n"
        "set protocols bgp group G neighbor 192.0.2.2 peer-as 64496\n"
    )

    def leaves(root: ConfigNode) -> set[tuple[str, ...]]:
        return {n.flat_words for n in root.walk() if not n.children}

    assert leaves(brace) == leaves(flat)


def test_set_style_deactivate_protect_and_noise() -> None:
    root = parse_set(
        "set interfaces ge-0/0/0 disable\ndeactivate interfaces ge-0/0/0\n"
        "protect system\ndelete foo\n# comment\nset a\n\nactivate x\n"
    )
    iface = root.children[0].children[0]
    assert iface.inactive
    assert root.children[1].protected
    assert looks_like_set("set a b", "junos") and not looks_like_set("a { b; }", "junos")
    assert looks_like_set("/configure x y", "mdcli")


def test_mdcli_set_style_chunks() -> None:
    root = parse_set(
        '/configure router "Base" static-routes route 0.0.0.0/0 route-type unicast '
        'next-hop "192.0.2.1" preference 5\nnot a set line\n',
        "mdcli",
    )
    leaf = next(n for n in root.walk() if not n.children)
    assert leaf.flat_words[:4] == ("configure", "router", "Base", "static-routes")
    assert leaf.parent is not None and leaf.parent.text == "route 0.0.0.0/0"


# ----------------------------------------------------------------------------- RouterOS


def test_routeros_continuations_and_sections() -> None:
    text = (
        "# comment\n/ip address\n"
        "add address=192.0.2.1/24 \\\n    interface=ether1 \\\n    comment=x\n"
        "/ip route add dst-address=0.0.0.0/0 gateway=192.0.2.2\n:global x 1\n/\nadd name=late\n"
    )
    root = parse_routeros(text)
    section = root.children[0]
    cmd = section.children[0]
    assert section.text == "/ip address"
    assert cmd.text == "add address=192.0.2.1/24 interface=ether1 comment=x"
    assert (cmd.line_start, cmd.line_end) == (3, 5)
    assert cmd.own_lines == [3, 4, 5]
    assert root.children[1].text == "/ip route"
    assert root.children[1].children[0].text.startswith("add dst-address")
    assert root.children[1].children[1].text == ":global x 1"
    assert root.children[2].text == "add name=late"


def test_routeros_dangling_continuation() -> None:
    root = parse_routeros("/ip address\nadd address=192.0.2.1/24 \\")
    assert root.children[0].children[0].text == "add address=192.0.2.1/24"


def test_ros_command_decoding() -> None:
    cmd = parse_command('set [ find default-name=ether1 ] comment="a b \\"c\\"" mtu=1500 blackhole')
    assert cmd.verb == "set"
    assert cmd.selector == "find default-name=ether1"
    assert cmd.params == {"comment": 'a b "c"', "mtu": "1500"}
    assert cmd.positional == ["blackhole"]
    assert parse_command("").verb == ""


# ----------------------------------------------------------------------------- properties

ALPHABET = st.sampled_from(list(" \t\n\r{};[]\"'#!/\\*:=-.0123456789abcdefABCDEF"))
ARBITRARY = st.text(ALPHABET, max_size=300) | st.text(max_size=200)
CLI_LINES = st.lists(
    st.tuples(
        st.integers(0, 6),
        st.sampled_from(
            ["interface Gi0", "ip address 192.0.2.1 255.255.255.0", "!", "#", "exit", "", "x y z"]
        ),
    ),
    max_size=40,
).map(lambda rows: "\n".join(" " * i + t for i, t in rows))

PARSERS = [
    lambda t: parse_indented(t, "ios"),
    lambda t: parse_indented(t, "xr"),
    lambda t: parse_indented(t, "vrp"),
    lambda t: parse_indented(t, "sros"),
    lambda t: parse_brace(t, "junos"),
    lambda t: parse_brace(t, "mdcli"),
    lambda t: parse_set(t, "junos"),
    lambda t: parse_set(t, "mdcli"),
    parse_routeros,
]


def check_invariants(root: ConfigNode, text: str) -> None:
    total = len(split_lines(text))
    claimed: set[int] = set()
    for node in root.walk(include_self=True):
        assert node.line_start <= node.line_end or node.is_root
        if not node.is_root:
            assert node.line_start >= 1 and node.line_end <= max(total, 1)
            assert node.parent is not None
            assert node.depth == node.parent.depth + 1
            if not node.parent.is_root:
                assert node.parent.line_start <= node.line_start
                assert node.line_end <= node.parent.line_end
        for line in node.own_lines:
            assert 1 <= line <= total
        claimed.update(node.own_lines)
    # every physical line is accounted for: owned by a node or left to the root (trivia)
    assert claimed == set(range(1, total + 1))


@settings(max_examples=150, deadline=None)
@given(ARBITRARY)
def test_parsers_never_raise_and_cover_every_line(text: str) -> None:
    for parse in PARSERS:
        check_invariants(parse(text), text)


@settings(max_examples=150, deadline=None)
@given(CLI_LINES)
def test_indented_round_trip_and_nesting(text: str) -> None:
    lines = split_lines(text)
    for dialect in ("ios", "xr", "vrp", "sros"):
        root = parse_indented(text, dialect)  # type: ignore[arg-type]
        check_invariants(root, text)
        # round trip: all lines, in order, from node-owned lines plus root trivia
        owned = sorted(n for node in root.walk(include_self=True) for n in node.own_lines)
        assert [lines[n - 1] for n in owned] == lines
        # siblings are ordered and do not overlap
        for node in root.walk(include_self=True):
            for first, second in zip(node.children, node.children[1:], strict=False):
                assert first.line_end < second.line_start
        # trivia lines are blank or comments
        for n in root.own_lines:
            stripped = lines[n - 1].strip()
            assert stripped == "" or stripped[0] in "!#"


@settings(max_examples=100, deadline=None)
@given(
    st.lists(
        st.sampled_from(["a b;", "c {", "}", "# note", "/* x */", "d [ e f ];", ""]), max_size=30
    )
)
def test_brace_blocks_nest(rows: list[str]) -> None:
    text = "\n".join(rows)
    root = parse_brace(text)
    check_invariants(root, text)
    for node in root.walk(include_self=True):
        for first, second in zip(node.children, node.children[1:], strict=False):
            assert first.line_end <= second.line_start or first.line_start == second.line_start


def test_text_is_not_stripped_of_content() -> None:
    # every word typed in an indented config survives in some node
    text = "interface X\n description a b c\n shutdown\n"
    joined = " ".join(texts(parse_indented(text)))
    assert re.sub(r"\s+", " ", joined) == "interface X description a b c shutdown"
