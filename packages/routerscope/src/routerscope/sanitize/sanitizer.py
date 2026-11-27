"""Deterministic fixture sanitizer.

Phases run in this order on the whole text: secrets, descriptions (optional), hostnames,
e-mails, MAC addresses, AS numbers, IP addresses. Each phase scans first and rewrites
second, so the mapping only depends on the set of values in the text and on the salt.

Alignment note: replacements can change the width of a token, so columns of tables may shift.
Everything outside the replaced tokens (line endings, trailing spaces, other lines) is kept
byte-for-byte.

IP algorithm (IPv4; IPv6 is identical with /48 blocks inside ``2001:db8::/32``):

1. Every public address (and, with ``remap_private``, RFC1918/CGNAT/link-local) belongs to a
   block: its /24, or the prefix itself when it is shorter than /24 but at least /15.
2. Blocks nested in another block are merged into it; blocks are sorted by
   (length, sha256(salt, block)).
3. Each block takes the first free aligned slot of 192.0.2.0/24, 198.51.100.0/24,
   203.0.113.0/24, then 198.18.0.0/15. Slots holding already-safe addresses in the text are
   skipped.
4. An address becomes ``slot + (address - block)``: prefix lengths and host bits are kept.
5. Prefixes shorter than /15 map to ``198.18.0.0`` with their written length; when the space is
   exhausted (more than ~515 /24 blocks) slots wrap and distinct networks may collide.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from ipaddress import IPv4Address, IPv6Address

from netaddr_search import MacStyle, find_macs, format_mac
from netprompt import detect_prompt

from routerscope.sanitize._addr import (
    V4_POOLS,
    V6_POOLS,
    AddrSpan,
    Allocator,
    digest,
    iter_addr_spans,
)
from routerscope.sanitize._asn import is_public_asn, iter_asn_spans
from routerscope.sanitize._lines import Rule, apply_edits, rule, split_lines
from routerscope.sanitize.redaction import redact_secrets

EMAIL_RE = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
SAFE_EMAIL_DOMAIN = re.compile(
    r"(?:example\.(?:com|net|org)|[\w.-]+\.(?:example|invalid|test))$", re.I
)

_NAME = r'"?(?P<v>[^\s";]+)"?'
_HOST_RULES: tuple[Rule, ...] = (
    rule("hostname", rf"^\s*hostname\s+{_NAME}"),
    rule("sysname", rf"^\s*sysname\s+{_NAME}"),
    rule("host-name", rf"(?<![\w-])host-name\s+{_NAME}"),
    rule("system-name", rf"(?<![\w-])system\s+name\s+{_NAME}"),
    rule("sros-name", rf"^\s*name\s+{_NAME}", ctx=r"^system\b", parent_only=True),
    rule(
        "ros-identity",
        r'(?<![\w.-])name=(?P<v>"[^"]*"|[^\s"]+)',
        ctx=r"^/system[ /]+identity\b",
        ros=True,
    ),
)
_GENERIC_NAMES = frozenset(
    {
        *("router", "switch", "host", "localhost", "mikrotik", "huawei", "cisco", "juniper"),
        *("nokia", "routeros", "junos", "ios", "vrp", "sros", "ocnos", "system", "admin"),
        *("default", "test", "ubuntu", "linux", "bgp", "ospf", "isis", "none", "user"),
        *("hostname", "sysname", "host-name", "name", "password", "secret", "description"),
        *("interface", "address", "neighbor", "community", "version", "redacted"),
    }
)
_DONE_NAME = re.compile(r"R\d+$")
_DONE_DESC = re.compile(r"desc-\d+$")
_DONE_EMAIL = re.compile(r"user\d+@example\.com$")

_DESC_RULES: tuple[Rule, ...] = (
    rule(
        "description",
        r"(?<![\w.-])(?:description|remark|(?:snmp-server\s+|snmp\s+|snmp-agent\s+sys-info\s+)"
        r"(?:contact|location))(?:[ \t]*:[ \t]*|[ \t]+)"
        r"(?P<v>\"[^\"]*\"|[^\s;\"](?:[^;]*[^\s;])?)(?=\s*;?\s*$)",
    ),
    rule(
        "comment-assign", r'(?<![\w.-])(?:comment|description|contact|location)=(?P<v>"[^"]*"|\S+)'
    ),
)


def _unquote(value: str) -> str:
    return value[1:-1] if len(value) >= 2 and value[0] == value[-1] == '"' else value


def _requote(original: str, new: str) -> str:
    return f'"{new}"' if len(original) >= 2 and original[0] == original[-1] == '"' else new


class Sanitizer:
    """Deterministic sanitizer; the same input and ``salt`` always give the same output.

    One instance keeps its mappings across calls, so sanitizing several files with the same
    instance maps equal values equally. Relationships between networks are only guaranteed
    within one call (use :meth:`sanitize_many` for related files). Documentation addresses,
    private ASNs and already-sanitized names are kept, so sanitizing twice changes nothing.
    """

    def __init__(
        self, salt: str = "", *, remap_private: bool = False, descriptions: bool = False
    ) -> None:
        self.salt = salt
        self.remap_private = remap_private
        self.descriptions = descriptions
        self._v4 = Allocator(
            width=32,
            pools=tuple((int(n.network_address), n.prefixlen) for n in V4_POOLS),
            block_len=24,
            min_len=15,
            salt=salt,
            label="v4",
        )
        self._v6 = Allocator(
            width=128,
            pools=tuple((int(n.network_address), n.prefixlen) for n in V6_POOLS),
            block_len=48,
            min_len=32,
            salt=salt,
            label="v6",
        )
        self._maps: dict[str, dict[str, str]] = {
            k: {} for k in ("ipv4", "ipv6", "asn", "mac", "hostname", "email", "description")
        }
        self._asn_reserved: set[int] = set()
        self._asn_cursor = {2: 0, 4: 0}
        self._mac_next = 0
        self._mac_used: set[int] = set()
        self._counters = {"hostname": 0, "description": 0, "email": 0}
        self._taken: dict[str, set[int]] = {"hostname": set(), "description": set(), "email": set()}

    @property
    def mapping(self) -> dict[str, dict[str, str]]:
        """Original -> sanitized values per kind. Sensitive: never commit it."""
        out = {k: dict(v) for k, v in self._maps.items()}
        for alloc, key, cls in (
            (self._v4, "ipv4_blocks", IPv4Address),
            (self._v6, "ipv6_blocks", IPv6Address),
        ):
            out[key] = {f"{cls(b)}/{ln}": f"{cls(t)}/{ln}" for (b, ln), t in alloc.blocks.items()}
        return out

    # ------------------------------------------------------------------ public API

    def sanitize(self, text: str, vendor: str | None = None) -> str:
        """Sanitize one document."""
        return self.sanitize_many([text], vendor)[0]

    def sanitize_many(self, texts: Iterable[str], vendor: str | None = None) -> list[str]:
        """Sanitize several documents planning IP blocks jointly (keeps relationships)."""
        docs = [redact_secrets(t, vendor) for t in texts]
        if self.descriptions:
            docs = [self._descriptions(t) for t in docs]
        docs = self._hostnames(docs)
        docs = [self._emails(t) for t in docs]
        docs = [self._macs(t) for t in docs]
        docs = self._asns(docs)
        return self._ips(docs)

    # ------------------------------------------------------------------ counters

    def _next_name(self, kind: str, prefix: str) -> int:
        taken = self._taken[kind]
        n = self._counters[kind] + 1
        while n in taken:
            n += 1
        self._counters[kind] = n
        taken.add(n)
        return n

    # ------------------------------------------------------------------ descriptions, e-mail

    def _descriptions(self, text: str) -> str:
        edits: list[tuple[int, int, str]] = []
        for line in split_lines(text):
            for r in _DESC_RULES:
                for m in r.pattern.finditer(line.body):
                    raw = m.group("v")
                    value = _unquote(raw)
                    if not value or _DONE_DESC.match(value):
                        continue
                    new = self._maps["description"].get(value)
                    if new is None:
                        new = f"desc-{self._next_name('description', 'desc')}"
                        self._maps["description"][value] = new
                    edits.append(
                        (line.start + m.start("v"), line.start + m.end("v"), _requote(raw, new))
                    )
        return apply_edits(text, edits)

    def _emails(self, text: str) -> str:
        edits: list[tuple[int, int, str]] = []
        for m in EMAIL_RE.finditer(text):
            addr = m.group()
            if SAFE_EMAIL_DOMAIN.search(addr.split("@", 1)[1]):
                continue
            new = self._maps["email"].get(addr)
            if new is None:
                new = f"user{self._next_name('email', 'user')}@example.com"
                self._maps["email"][addr] = new
            edits.append((m.start(), m.end(), new))
        return apply_edits(text, edits)

    # ------------------------------------------------------------------ hostnames

    def _hostnames(self, docs: list[str]) -> list[str]:
        per_doc: list[list[tuple[int, int, int, str]]] = []
        order: list[str] = []
        for text in docs:
            spans = self._host_spans(text)
            per_doc.append(spans)
            for _, _, _, key in spans:
                if key not in order:
                    order.append(key)
        names = self._maps["hostname"]
        for key in order:
            if _DONE_NAME.match(key):
                self._taken["hostname"].add(int(key[1:]))
        for key in order:
            if key in names:
                continue
            if _DONE_NAME.match(key):
                names[key] = key
            else:
                names[key] = f"R{self._next_name('hostname', 'R')}"
        out: list[str] = []
        for text, spans in zip(docs, per_doc, strict=True):
            text = apply_edits(text, [(s, e, names[k]) for s, e, _, k in spans])
            out.append(self._global_names(text))
        return out

    def _global_names(self, text: str) -> str:
        safe = sorted(
            (
                k
                for k, v in self._maps["hostname"].items()
                if k != v and len(k) >= 3 and k.lower() not in _GENERIC_NAMES
            ),
            key=len,
            reverse=True,
        )
        if not safe:
            return text
        rx = re.compile(
            r"(?<![A-Za-z0-9_])(?:" + "|".join(map(re.escape, safe)) + r")(?![A-Za-z0-9_])"
        )
        return rx.sub(lambda m: self._maps["hostname"][m.group()], text)

    def _host_spans(self, text: str) -> list[tuple[int, int, int, str]]:
        """Return ``(start, end, line, key)`` for every structural hostname occurrence."""
        spans: list[tuple[int, int, int, str]] = []
        known: set[str] = set()
        lines = list(split_lines(text))
        for line in lines:
            for r in _HOST_RULES:
                if not r.applies(line, None):
                    continue
                for m in r.pattern.finditer(line.body):
                    name = m.group("v").strip('"')
                    if not name or name.startswith("<") or name == "[":
                        continue
                    key = name.split(".")[0]
                    known.add(key)
                    spans.append(
                        (line.start + m.start("v"), line.start + m.end("v"), line.number, key)
                    )
        for line in lines:
            found = detect_prompt(line.body, known_hostnames=known or None) if line.body else None
            if found is None or not found[0].hostname or found[0].hostname == "redacted":
                continue
            prompt = found[0]
            host = prompt.hostname or ""
            span = self._locate(line.body, prompt.raw, host)
            if span is not None:
                start, end = span
                spans.append(
                    (line.start + start, line.start + end, line.number, host.split(".")[0])
                )
        spans.sort()
        # drop overlaps (statement and prompt on the same text)
        clean: list[tuple[int, int, int, str]] = []
        for s in spans:
            if clean and s[0] < clean[-1][1]:
                continue
            clean.append(s)
        return clean

    @staticmethod
    def _locate(body: str, raw: str, host: str) -> tuple[int, int] | None:
        if not body.startswith(raw):
            return None
        pos = raw.rfind("@") + 1
        while (idx := raw.find(host, pos)) != -1:
            before = raw[idx - 1] if idx else ""
            after = raw[idx + len(host)] if idx + len(host) < len(raw) else ""
            if not (before.isalnum() or before == "_") and not (after.isalnum() or after == "_"):
                end = idx + len(host)
                fqdn = re.compile(r"(?:\.[A-Za-z0-9-]+)*").match(body, end)
                return idx, fqdn.end() if fqdn else end
            pos = idx + 1
        return None

    # ------------------------------------------------------------------ MAC addresses

    def _macs(self, text: str) -> str:
        edits: list[tuple[int, int, str]] = []
        found = [m for m in find_macs(text)]
        for m in found:
            parts = bytes.fromhex(m.mac.replace(":", ""))
            if parts[:5] == b"\x00\x00\x5e\x00\x53":
                self._mac_used.add(parts[5])
        fresh = sorted(
            {m.mac for m in found if self._mac_needs_map(m.mac)} - self._maps["mac"].keys(),
            key=lambda mac: digest(self.salt, "mac", mac),
        )
        for mac in fresh:
            while self._mac_next in self._mac_used and len(self._mac_used) < 256:
                self._mac_next = (self._mac_next + 1) % 256
            idx = self._mac_next
            self._mac_used.add(idx)
            self._mac_next = (self._mac_next + 1) % 256
            self._maps["mac"][mac] = f"00:00:5e:00:53:{idx:02x}"
        for m in found:
            new = self._maps["mac"].get(m.mac)
            if new is None:
                continue
            raw = m.text
            if "." in raw:
                style = MacStyle.CISCO
            elif raw.count("-") == 2:
                style = MacStyle.HUAWEI
            elif "-" in raw:
                style = MacStyle.HYPHEN
            else:
                style = MacStyle.COLON
            upper = any(c in "ABCDEF" for c in raw)
            edits.append((m.start, m.end, format_mac(new, style, upper=upper)))
        return apply_edits(text, edits)

    @staticmethod
    def _mac_needs_map(mac: str) -> bool:
        octets = bytes.fromhex(mac.replace(":", ""))
        multicast_or_zero = bool(octets[0] & 1) or octets == bytes(6)
        return not (multicast_or_zero or octets[:5] == b"\x00\x00\x5e\x00\x53")

    # ------------------------------------------------------------------ AS numbers

    def _asns(self, docs: list[str]) -> list[str]:
        spans = [iter_asn_spans(t) for t in docs]
        values = {s.value for doc in spans for s in doc}
        self._asn_reserved |= {v for v in values if not is_public_asn(v)}
        fresh = sorted(
            (v for v in values if is_public_asn(v) and str(v) not in self._maps["asn"]),
            key=lambda n: digest(self.salt, "asn", str(n)),
        )
        for v in fresh:
            self._maps["asn"][str(v)] = str(self._pick_asn(v))
        out = []
        for text, doc in zip(docs, spans, strict=True):
            edits = [
                (s.start, s.end, self._maps["asn"][str(s.value)])
                for s in doc
                if str(s.value) in self._maps["asn"]
            ]
            out.append(apply_edits(text, edits))
        return out

    def _pick_asn(self, v: int) -> int:
        two = v <= 65535
        pool = (
            [*range(64496, 64512), *range(64512, 65535)]
            if two
            else [*range(65536, 65552), *range(4200000000, 4200000200)]
        )
        key = 2 if two else 4
        used = self._asn_reserved | {int(x) for x in self._maps["asn"].values()}
        while self._asn_cursor[key] < len(pool):
            cand = pool[self._asn_cursor[key]]
            self._asn_cursor[key] += 1
            if cand not in used:
                return int(cand)
        return int(pool[int.from_bytes(digest(self.salt, "asn-wrap", str(v))[:4], "big") % 16])

    # ------------------------------------------------------------------ IP addresses

    def _ips(self, docs: list[str]) -> list[str]:
        spans = [list(iter_addr_spans(t)) for t in docs]
        v4_items: list[tuple[int, int]] = []
        v6_items: list[tuple[int, int]] = []
        todo: list[list[tuple[AddrSpan, str]]] = []
        for doc in spans:
            marked: list[tuple[AddrSpan, str]] = []
            for s in doc:
                cls = s.classify()
                remap = cls == "public" or (cls == "private" and self.remap_private)
                v4 = s.v4
                if v4 is not None:
                    if remap:
                        v4_items.append((int(v4), s.v4_plen))
                    elif cls == "keep" and any(v4 in n for n in V4_POOLS):
                        self._v4.reserve(int(v4), s.v4_plen)
                elif isinstance(s.address, IPv6Address):
                    if remap:
                        v6_items.append((int(s.address), s.plen))
                    elif s.address in V6_POOLS[0]:
                        self._v6.reserve(int(s.address), s.plen)
                if remap:
                    marked.append((s, cls))
            todo.append(marked)
        self._v4.plan(v4_items)
        self._v6.plan(v6_items)
        out = []
        for text, marked in zip(docs, todo, strict=True):
            edits = []
            for s, _ in marked:
                v4 = s.v4
                if v4 is not None:
                    new = str(IPv4Address(self._v4.map(int(v4), s.v4_plen)))
                    self._maps["ipv4"][str(v4)] = new
                    repl = f"::ffff:{new}" if s.mapped else new
                else:
                    assert isinstance(s.address, IPv6Address)
                    repl = str(IPv6Address(self._v6.map(int(s.address), s.plen)))
                    self._maps["ipv6"][str(s.address)] = repl
                edits.append((s.start, s.end, repl))
            out.append(apply_edits(text, edits))
        return out
