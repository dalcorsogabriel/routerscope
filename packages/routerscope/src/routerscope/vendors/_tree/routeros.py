"""RouterOS ``/export`` parser: ``/path`` sections with ``add``/``set`` command lines."""

from __future__ import annotations

from dataclasses import dataclass, field

from routerscope.model import split_lines
from routerscope.vendors._tree.indent import _finalize
from routerscope.vendors._tree.node import ConfigNode
from routerscope.vendors._tree.words import split_tokens, unquote

VERBS = frozenset(
    {"add", "set", "remove", "enable", "disable", "print", "unset", "move", "export", "get"}
)


def _continues(logical: str) -> bool:
    """True if the line ends with an odd number of backslashes (a line continuation)."""
    stripped = logical.rstrip()
    count = len(stripped) - len(stripped.rstrip("\\"))
    return count % 2 == 1


def parse_routeros(text: str) -> ConfigNode:
    """Parse a RouterOS ``/export`` into section nodes (``/ip address``) holding command nodes.

    Physical lines ending in a backslash are joined into one command whose node spans all of
    them (the node text is the joined logical line). ``#`` lines and blank lines are not nodes.
    A one-line form such as ``/ip address add address=...`` becomes a section plus a command.
    Never raises.
    """
    lines = split_lines(text)
    root = ConfigNode("", 1, max(len(lines), 1))
    section: ConfigNode | None = None
    i = 0
    total = len(lines)
    while i < total:
        number = i + 1
        stripped = lines[i].strip()
        i += 1
        if not stripped or stripped.startswith("#"):
            continue
        own = [number]
        logical = stripped
        while _continues(logical) and i < total:
            logical = logical.rstrip()[:-1].rstrip() + " " + lines[i].strip()
            i += 1
            own.append(i)
        logical = logical.rstrip()
        if logical.endswith("\\"):
            logical = logical[:-1].rstrip()
        end = own[-1]
        if logical.startswith("/"):
            tokens = split_tokens(logical)
            split = next((k for k, tok in enumerate(tokens) if k > 0 and tok in VERBS), None)
            if split is None:
                section = ConfigNode(" ".join(tokens), number, end, own_lines=list(own))
                root.add_child(section)
                continue
            section = ConfigNode(" ".join(tokens[:split]), number, number)
            root.add_child(section)
            command = ConfigNode(" ".join(tokens[split:]), number, end, own_lines=list(own))
            section.add_child(command)
            continue
        command = ConfigNode(logical, number, end, own_lines=list(own))
        (section or root).add_child(command)
    return _finalize(root, total)


@dataclass
class RosCommand:
    """A decoded RouterOS command line."""

    verb: str = ""
    selector: str = ""
    params: dict[str, str] = field(default_factory=dict)
    positional: list[str] = field(default_factory=list)


def parse_command(text: str) -> RosCommand:
    """Decode ``add name=x comment="a b"`` / ``set [ find default-name=ether1 ] mtu=1500``.

    Values are unquoted and unescaped. A ``[ ... ]`` selector is returned as its inner text.
    Bare words (``blackhole``, a numeric id) go to ``positional``.
    """
    cmd = RosCommand()
    tokens = split_tokens(text)
    k = 0
    if tokens:
        cmd.verb = tokens[0]
        k = 1
    while k < len(tokens):
        tok = tokens[k]
        if tok == "[":
            depth = 1
            inner: list[str] = []
            k += 1
            while k < len(tokens):
                if tokens[k] == "[":
                    depth += 1
                elif tokens[k] == "]":
                    depth -= 1
                    if depth == 0:
                        break
                inner.append(tokens[k])
                k += 1
            cmd.selector = " ".join(inner)
        elif "=" in tok:
            key, _, value = tok.partition("=")
            cmd.params[key] = unquote(value)
        else:
            cmd.positional.append(unquote(tok))
        k += 1
    return cmd
