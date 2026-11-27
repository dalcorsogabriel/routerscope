"""MikroTik RouterOS 7.

A RouterOS command is a menu path, one verb and its arguments
(``/ip/address/print detail where interface=ether1``, ``/ip address print``, or just
``print`` inside a menu). Menu names and verbs can be abbreviated.

A line is READ only when it parses as known menu names, then a read verb, then
arguments that verb accepts. Anything else is at best UNKNOWN; to rank how dangerous
it is, every word is also checked against the list of mutating verbs. Scripting syntax
and backslashes fail closed.
"""

from __future__ import annotations

import re
from collections.abc import Collection

from .._engine import Result
from .._model import Mode, Verdict, worst
from .._tokens import Token, balanced_quotes, has_unquoted, split_unquoted, tokenize

# Known menu segments. A path word that is not one of these (or an unambiguous
# abbreviation of one) makes the line UNKNOWN. Extend the set when adding read cases.
MENUS: frozenset[str] = frozenset(
    {
        "active", "address", "address-list", "area", "arp", "bfd", "bgp", "bonding", "bridge",
        "cache", "certificate", "clock", "community", "connection", "console", "dhcp-client",
        "dhcp-relay", "dhcp-server", "disk", "dns", "eoip", "ethernet", "filter", "firewall",
        "gre", "group", "health", "history", "host", "identity", "instance", "interface",
        "interface-template", "ip", "ipip", "ipsec", "ipv6", "l2tp-client", "l2tp-server",
        "lease", "license", "list", "ldp", "log", "logging", "lsa", "lte", "mangle", "member",
        "mpls", "nat", "nd", "neighbor", "ntp", "client", "ospf", "package", "peer", "peers",
        "policy", "pool", "port", "ppp", "pppoe-client", "pppoe-server", "profile", "proposal",
        "queue", "radius", "raw", "resource", "route", "routerboard", "routing", "rpki", "rule",
        "secret", "server", "service", "session", "settings", "simple", "snmp", "static",
        "system", "table", "template", "tree", "user", "vlan", "vrrp", "vxlan", "wireguard",
        "wifi", "wireless",
    }
)  # fmt: skip

# Read verbs and the bare flags each accepts. Named parameters are in `_READ_KEYS`;
# `where` (print/export) starts a filter expression checked by `_filter_ok`.
_READ_VERBS: dict[str, frozenset[str]] = {
    "print": frozenset(
        {
            "detail", "terse", "brief", "without-paging", "follow", "follow-only",
            "count-only", "stats", "stats-detail", "status", "value-list", "as-value",
            "all", "oid", "proplist", "show-ids",
        }
    ),
    "export": frozenset({"compact", "terse", "verbose", "show-sensitive", "hide-sensitive"}),
    # monitor verbs take item names (interfaces) as positional arguments.
    "monitor": frozenset(),
    "monitor-traffic": frozenset(),
}  # fmt: skip
_POSITIONAL_ITEMS = frozenset({"monitor", "monitor-traffic"})
_WHERE_VERBS = frozenset({"print", "export"})

# Named parameters a read verb may take, by exact name only: RouterOS accepts
# abbreviated parameter names, so `fi=x` would silently mean `file=x`.
_READ_KEYS: dict[str, frozenset[str]] = {
    "print": frozenset({"proplist", "interval", "from", "value-list"}),
    "export": frozenset(),
    "monitor": frozenset({"interval", "duration"}),
    "monitor-traffic": frozenset({"interface", "interval", "duration", "aggregate"}),
}
_MONITOR_FLAGS = frozenset({"once"})

# Parameters that write to flash. Any abbreviation of them (`f=`, `fi=`, `fil=`) counts.
_WRITING_KEYS = ("file", "append", "dst-path")

# `where` filter expressions: properties, comparisons, values and boolean operators.
_FILTER_TOKEN = re.compile(r"^!?\(*[\w.:/,-]*(?:(?:!=|<=|>=|=|~|<|>|in)[\w.:/,\"*~^$-]*)?\)*$")
_FILTER_WORDS = frozenset({"and", "or", "not", "in", "!"})

_WRITE_VERBS: dict[str, Verdict] = {
    "add": Verdict.CONFIG,
    "set": Verdict.CONFIG,
    "edit": Verdict.CONFIG,
    "enable": Verdict.CONFIG,
    "comment": Verdict.CONFIG,
    "move": Verdict.CONFIG,
    "unset": Verdict.CONFIG,
    "remove": Verdict.DESTRUCTIVE,
    "disable": Verdict.DESTRUCTIVE,
    "reset": Verdict.DESTRUCTIVE,
    "reset-counters": Verdict.DESTRUCTIVE,
    "reset-counters-all": Verdict.DESTRUCTIVE,
    "reset-configuration": Verdict.DESTRUCTIVE,
    "reboot": Verdict.DESTRUCTIVE,
    "shutdown": Verdict.DESTRUCTIVE,
    "import": Verdict.DESTRUCTIVE,
    "run": Verdict.DESTRUCTIVE,
    "install": Verdict.DESTRUCTIVE,
    "upgrade": Verdict.DESTRUCTIVE,
    "downgrade": Verdict.DESTRUCTIVE,
    "uninstall": Verdict.DESTRUCTIVE,
    "apply": Verdict.DESTRUCTIVE,
    "flush": Verdict.DESTRUCTIVE,
}

_READ_MIN_ABBREV = 2


def _unique_prefix(word: str, names: Collection[str]) -> str | None:
    if word in names:
        return word
    candidates = [n for n in names if n.startswith(word)]
    if len(candidates) == 1 and len(word) >= _READ_MIN_ABBREV:
        return candidates[0]
    return None


def _writing_key(word: str) -> bool:
    """True for `key=value` (or `"key"=value`) whose key abbreviates a writing parameter."""
    if "=" not in word:
        return False
    key = word.partition("=")[0].strip('"!(').lower()
    return bool(key) and any(k.startswith(key) for k in _WRITING_KEYS)


def _menu_words(tokens: list[Token]) -> tuple[list[str], list[Token]] | None:
    """Split the leading menu path (`/ip/address`, `ip address`) from the rest."""
    path: list[str] = []
    for i, tok in enumerate(tokens):
        if tok.quoted:
            return None
        parts = [p.lower() for p in tok.text.split("/") if p]
        for j, part in enumerate(parts):
            if _unique_prefix(part, _READ_VERBS) is not None:
                if j != len(parts) - 1:
                    return None  # a verb in the middle of a path
                return [*path, part], tokens[i + 1 :]
            path.append(part)
    return path, []


def _filter_ok(tokens: list[Token]) -> bool:
    depth = 0
    for tok in tokens:
        text = tok.text
        if _writing_key(text):
            return False
        if text.lower() not in _FILTER_WORDS and not _FILTER_TOKEN.match(text):
            return False
        depth += text.count("(") - text.count(")")
        if depth < 0:
            return False
    return depth == 0 and balanced_quotes(" ".join(t.text for t in tokens))


def _parse_read(tokens: list[Token]) -> str | None:
    """Return the read verb if the line is `menu* verb args`, else None."""
    split = _menu_words(tokens)
    if split is None or not split[0]:
        return None
    words, args = split
    *menus, verb_word = words
    verb = _unique_prefix(verb_word, _READ_VERBS)
    if verb is None or any(_unique_prefix(m, MENUS) is None for m in menus):
        return None
    for i, tok in enumerate(args):
        text = tok.text.lower()
        if text == "where" and verb in _WHERE_VERBS:
            return verb if _filter_ok(args[i + 1 :]) else None
        if tok.quoted or _writing_key(text):
            return None
        if "=" in text:
            if text.partition("=")[0] not in _READ_KEYS[verb]:
                return None
            continue
        if text in _READ_VERBS[verb] or (verb in _POSITIONAL_ITEMS and text in _MONITOR_FLAGS):
            continue
        if verb in _POSITIONAL_ITEMS and re.fullmatch(r"[\w.,-]+", text):
            continue  # item names (interfaces)
        return None
    return verb


def _severity(tokens: list[Token]) -> tuple[Verdict, str]:
    """Rank a line that is not a plain read by the most dangerous word in it."""
    verdicts: list[Verdict] = [Verdict.UNKNOWN]
    reasons: list[str] = ["not a recognized read command"]
    for tok in tokens:
        if _writing_key(tok.text):
            verdicts.append(Verdict.DESTRUCTIVE)
            reasons.append("writes a file")
            continue
        if tok.quoted:
            continue
        for word in (p.lower() for p in tok.text.split("/") if p):
            if "=" in word:
                key, _, value = word.partition("=")
                if key == "disabled" and value in ("yes", "true"):
                    verdicts.append(Verdict.DESTRUCTIVE)
                    reasons.append("disables an item (disabled=yes)")
                continue
            candidates = (
                [word] if word in _WRITE_VERBS else [v for v in _WRITE_VERBS if v.startswith(word)]
            )
            if candidates:
                verdicts.append(worst([_WRITE_VERBS[c] for c in candidates]))
                reasons.append(f"verb '{candidates[0] if len(candidates) == 1 else word}'")
    verdict = worst(verdicts)
    return verdict, next(r for v, r in zip(verdicts, reasons, strict=True) if v is verdict)


def _classify_one(command: str) -> tuple[Verdict, str]:
    text = command.strip()
    if not text:
        return Verdict.SESSION, "empty line"
    if text in ("..", "/", "/quit", "quit"):
        return Verdict.SESSION, "menu navigation"
    tokens = tokenize(text)
    if has_unquoted(text, "[]{}$") or text.startswith(":") or "\\" in text:
        verdict, reason = _severity(tokens)
        if verdict.severity > Verdict.UNKNOWN.severity:
            return verdict, reason
        return Verdict.UNKNOWN, "scripting syntax"
    if not balanced_quotes(text):
        return worst([_severity(tokens)[0], Verdict.UNKNOWN]), "unbalanced quotes"
    verb = _parse_read(tokens)
    if verb is not None:
        return Verdict.READ, f"verb '{verb}'"
    return _severity(tokens)


def classify_routeros(command: str, mode: Mode | None) -> Result:
    """Classify a RouterOS line; ``;`` separates several commands."""
    # A backslash may escape a quote, so quotes cannot be trusted to hide a `;`.
    parts = split_unquoted(command, ";", quotes="\\" not in command)
    results = [_classify_one(part) for part in parts]
    verdict = worst([v for v, _ in results])
    reason = next(r for v, r in results if v is verdict)
    return Result(verdict, reason, mode)
