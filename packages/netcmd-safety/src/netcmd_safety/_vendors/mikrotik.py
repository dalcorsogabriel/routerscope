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

from collections.abc import Collection

from .._engine import Result
from .._model import Mode, Verdict, worst
from .._tokens import Token, has_unquoted, split_unquoted, tokenize

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

# Read verbs and the bare flags each accepts. `key=value` arguments are always allowed
# except `file=`; `where` (print/export) starts a free filter expression.
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


def _words(tokens: list[Token]) -> list[tuple[str, bool]]:
    """Unquoted tokens are split on `/` (menu paths); quoted tokens stay whole."""
    out: list[tuple[str, bool]] = []
    for tok in tokens:
        if tok.quoted:
            out.append((tok.text, True))
        else:
            out.extend((p.lower(), False) for p in tok.text.split("/") if p)
    return out


def _parse_read(words: list[tuple[str, bool]]) -> str | None:
    """Return the read verb if the line is `menu* verb args`, else None."""
    i = 0
    while i < len(words):
        word, quoted = words[i]
        if quoted:
            return None
        verb = _unique_prefix(word, _READ_VERBS)
        if verb is not None:
            break
        if _unique_prefix(word, MENUS) is None:
            return None
        i += 1
    else:
        return None
    allowed = _READ_VERBS[verb]
    for word, quoted in words[i + 1 :]:
        if word == "where" and verb in _WHERE_VERBS:
            return verb
        if "=" in word:
            if word.partition("=")[0] == "file":
                return None
            continue
        if quoted or word in allowed or verb in _POSITIONAL_ITEMS:
            continue
        return None
    return verb


def _severity(words: list[tuple[str, bool]]) -> tuple[Verdict, str]:
    """Rank a line that is not a plain read by the most dangerous word in it."""
    verdicts: list[Verdict] = [Verdict.UNKNOWN]
    reasons: list[str] = ["not a recognized read command"]
    for word, quoted in words:
        if quoted:
            continue
        if word == "where":
            break
        if "=" in word:
            key, _, value = word.partition("=")
            if key == "file":
                verdicts.append(Verdict.DESTRUCTIVE)
                reasons.append("writes a file (file=)")
            elif key == "disabled" and value in ("yes", "true"):
                verdicts.append(Verdict.DESTRUCTIVE)
                reasons.append("disables an item (disabled=yes)")
            continue
        candidates = [v for v in _WRITE_VERBS if v.startswith(word)]
        if word in _WRITE_VERBS:
            candidates = [word]
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
    words = _words(tokenize(text))
    if has_unquoted(text, "[]{}$") or text.startswith(":") or "\\" in text:
        verdict, reason = _severity(words)
        return worst([verdict, Verdict.UNKNOWN]), (
            reason if verdict.severity > Verdict.UNKNOWN.severity else "scripting syntax"
        )
    if text.count('"') % 2:
        return worst([_severity(words)[0], Verdict.UNKNOWN]), "unbalanced quotes"
    verb = _parse_read(words)
    if verb is not None:
        return Verdict.READ, f"verb '{verb}'"
    return _severity(words)


def classify_routeros(command: str, mode: Mode | None) -> Result:
    """Classify a RouterOS line; ``;`` separates several commands."""
    # A backslash may escape a quote, so quotes cannot be trusted to hide a `;`.
    parts = split_unquoted(command, ";", quotes="\\" not in command)
    results = [_classify_one(part) for part in parts]
    verdict = worst([v for v, _ in results])
    reason = next(r for v, r in results if v is verdict)
    return Result(verdict, reason, mode)
