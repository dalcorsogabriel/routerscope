"""Deterministic fixture sanitizer.

Phases run in this order on the whole text: secrets, free text (descriptions, banners, user
names; on by default), hostnames, e-mails, domain names, device identifiers, MAC addresses
(including EUI-64 interface IDs), AS numbers, IP addresses. Each phase scans first and rewrites
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

Private, CGNAT and link-local addresses are kept unless ``remap_private=True``.
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
    classify_v4,
    digest,
    iter_addr_spans,
)
from routerscope.sanitize._asn import is_public_asn, iter_asn_spans
from routerscope.sanitize._domains import iter_fqdns
from routerscope.sanitize._free import BANNER_RE, FREE_RULES
from routerscope.sanitize._ids import (
    ISIS_NET_RE,
    MAC_BARE_RE,
    eui64_of_mac,
    is_eui64,
    iter_serial_spans,
    mac_of_eui64,
)
from routerscope.sanitize._lines import Rule, apply_edits, rule, split_lines
from routerscope.sanitize._names import Namer
from routerscope.sanitize.redaction import redact_secrets

EMAIL_RE = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
SAFE_EMAIL_DOMAIN = re.compile(
    r"(?:example\.(?:com|net|org)|[\w.-]+\.(?:example|invalid|test))$", re.IGNORECASE
)

_EOL = re.compile(r"\r\n|\n|\r")
_NAME = r'"?(?P<v>[^\s":;=<>]+)"?;?'
_HOST_RULES: tuple[Rule, ...] = (
    rule("hostname", rf"^\s*(?:hostname|sysname|host-name)\s*[:=]?\s*{_NAME}"),
    rule("host-name", rf"(?<![\w-])host-name\s*[:=]?\s*{_NAME}"),
    rule("system-name", rf"(?<![\w-])system\s+name\s*[:=]?\s*{_NAME}"),
    rule(
        "name-label",
        rf"^\s*(?:system name|host ?name|device name|local system name)\s*[:=]\s*{_NAME}",
    ),
    rule("uptime", r"^(?P<v>[A-Za-z0-9][\w.-]*)\s+uptime\s+is\b"),
    rule("sros-name", rf"^\s*name\s+{_NAME}", ctx=r"^system\b", parent_only=True),
    rule(
        "ros-identity",
        r'(?<![\w.-])name=(?P<v>"[^"]*"|[^\s"]+)',
        ctx=r"^/system[ /]+identity\b",
        ros=True,
    ),
    rule(
        "ros-identity-print", rf"^\s*name\s*:\s*{_NAME}", ctx=r"^/system[ /]+identity\b", ros=True
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

_IP_HOST = re.compile(r"^\s*ip\s+host\s+(?:vrf\s+\S+\s+)?(?P<v>[^\s]+)", re.IGNORECASE)
_CDP_HEADER = re.compile(r"^\s*Device ID\b.*\b(?:Local Intf|Interface|Port)", re.IGNORECASE)
_CDP_KV = re.compile(r"^\s*Device ID\s*:\s*(?P<v>[^\s,]+)", re.IGNORECASE)
_CDP_ROW = re.compile(r"^(?P<v>\S+)\s+[A-Za-z][A-Za-z-]*\d[\w/.:-]*\s+\d+\s")
_DONE_FQDN = re.compile(r"host(\d+)\.example\.net", re.IGNORECASE)


def _unquote(value: str) -> str:
    return value[1:-1] if len(value) >= 2 and value[0] == value[-1] == '"' else value


def _requote(original: str, new: str) -> str:
    return f'"{new}"' if len(original) >= 2 and original[0] == original[-1] == '"' else new


def _swap_block(body: str, new: str) -> str:
    """Replace a multi-line banner body by ``new`` on one line, keeping the surrounding layout."""
    eols = list(_EOL.finditer(body))
    if not eols:
        lead = body[: len(body) - len(body.lstrip())]
        trail = body[len(body.rstrip()) :]
        return lead + new + trail
    first = eols[0]
    head = body[: first.end()] if not body[: first.start()].strip() else first.group()
    indent = re.match(r"[ \t]*", body[first.end() :])
    after = body[eols[-1].end() :]
    trailing = after if not after.strip() else ""
    return head + (indent.group() if indent else "") + new + first.group() + trailing


class Sanitizer:
    """Deterministic sanitizer; the same input and ``salt`` always give the same output.

    One instance keeps its mappings across calls, so sanitizing several files with the same
    instance maps equal values equally. Relationships between networks are only guaranteed
    within one call (use :meth:`sanitize_many` for related files). Documentation addresses,
    private ASNs and already-sanitized names are kept, so sanitizing twice changes nothing.

    ``descriptions`` (default True) also replaces free text: interface/peer descriptions,
    banners, SNMP contact/location, RouterOS comments and user names. Pass False to keep it.
    """

    def __init__(
        self, salt: str = "", *, remap_private: bool = False, descriptions: bool = True
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
        self._hosts = Namer("R{n}", fold=True)
        self._descs = Namer("desc-{n}")
        self._users = Namer("user{n}")
        self._emails = Namer("user{n}@example.com", fold=True)
        self._fqdns = Namer("host{n}.example.net", fold=True)
        self._serials = Namer("SERIAL{n}")
        self._maps: dict[str, dict[str, str]] = {
            k: {} for k in ("ipv4", "ipv6", "asn", "mac", "isis_net")
        }
        self._asn_reserved: set[int] = set()
        self._asn_cursor = {2: 0, 4: 0}
        self._mac_next = 0
        self._mac_used: set[int] = set()
        self._short_hosts: set[str] = set()

    @property
    def mapping(self) -> dict[str, dict[str, str]]:
        """Original -> sanitized values per kind. Sensitive: never commit it."""
        out = {k: dict(v) for k, v in self._maps.items()}
        out["hostname"] = dict(self._hosts.map)
        out["description"] = dict(self._descs.map)
        out["username"] = dict(self._users.map)
        out["email"] = dict(self._emails.map)
        out["domain"] = dict(self._fqdns.map)
        out["serial"] = dict(self._serials.map)
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
            docs = self._free_text(docs)
        docs = self._hostnames(docs)
        docs = [self._email_addresses(t) for t in docs]
        docs = self._domains(docs)
        docs = [self._serial_numbers(t) for t in docs]
        docs = [self._macs(t) for t in docs]
        docs = self._asns(docs)
        docs = self._ips(docs)
        # pseudonyms can create new secret-looking text ("password R1"): redact once more
        return [redact_secrets(t, vendor) for t in docs]

    # ------------------------------------------------------------------ free text

    def _free_text(self, docs: list[str]) -> list[str]:
        for text in docs:  # reserve names that are already pseudonyms
            for m in BANNER_RE.finditer(text):
                self._descs.reserve(m["body"].strip())
            for line in split_lines(text):
                for r, kind in FREE_RULES:
                    if r.applies(line, None):
                        for m in r.pattern.finditer(line.body):
                            (self._descs if kind == "desc" else self._users).reserve(
                                _unquote(m.group("v"))
                            )
        return [self._free_text_one(t) for t in docs]

    def _free_text_one(self, text: str) -> str:
        def banner(m: re.Match[str]) -> str:
            body = m["body"]
            stripped = body.strip()
            if not stripped or self._descs.is_done(stripped):
                return m.group(0)
            return m["head"] + m["d"] + _swap_block(body, self._descs.get(stripped)) + m["end"]

        text = BANNER_RE.sub(banner, text)
        edits: list[tuple[int, int, str]] = []
        for line in split_lines(text):
            for r, kind in FREE_RULES:
                if not r.applies(line, None):
                    continue
                namer = self._descs if kind == "desc" else self._users
                for m in r.pattern.finditer(line.body):
                    raw = m.group("v")
                    value = _unquote(raw)
                    if not value.strip() or namer.is_done(value):
                        continue
                    edits.append(
                        (
                            line.start + m.start("v"),
                            line.start + m.end("v"),
                            _requote(raw, namer.get(value)),
                        )
                    )
        return apply_edits(text, edits)

    # ------------------------------------------------------------------ hostnames

    def _hostnames(self, docs: list[str]) -> list[str]:
        per_doc = [self._host_spans(t) for t in docs]
        for spans in per_doc:  # names that are already pseudonyms keep their number
            for _, _, key, _ in spans:
                self._hosts.reserve(key)
        out: list[str] = []
        for text, spans in zip(docs, per_doc, strict=True):
            edits = [(s, e, self._hosts.get(k)) for s, e, k, _ in spans]
            self._short_hosts |= {k.lower() for _, _, k, stmt in spans if stmt}
            out.append(self._global_names(apply_edits(text, edits)))
        return out

    def _global_names(self, text: str) -> str:
        safe = sorted(
            (
                k
                for k, v in self._hosts.map.items()
                if k.lower() != v.lower()
                and k not in _GENERIC_NAMES
                and (len(k) >= 3 or k in self._short_hosts)
            ),
            key=len,
            reverse=True,
        )
        if not safe:
            return text
        rx = re.compile(
            r"(?<![A-Za-z0-9_])(?:" + "|".join(map(re.escape, safe)) + r")(?![A-Za-z0-9_])",
            re.IGNORECASE,
        )
        return rx.sub(lambda m: self._hosts.map[m.group().lower()], text)

    def _host_spans(self, text: str) -> list[tuple[int, int, str, bool]]:
        """Return ``(start, end, key, from_statement)`` for every structural hostname."""
        spans: list[tuple[int, int, str, bool]] = []
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
                    spans.append((line.start + m.start("v"), line.start + m.end("v"), key, True))
        for line in lines:
            found = detect_prompt(line.body, known_hostnames=known or None) if line.body else None
            if found is None or not found[0].hostname or found[0].hostname == "redacted":
                continue
            prompt = found[0]
            host = prompt.hostname or ""
            span = self._locate(line.body, prompt.raw, host)
            if span is not None:
                start, end = span
                spans.append((line.start + start, line.start + end, host.split(".")[0], False))
        spans.sort()
        clean: list[tuple[int, int, str, bool]] = []
        for s in spans:  # drop overlaps (statement and prompt on the same text)
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

    # ------------------------------------------------------------------ e-mail, domains, serials

    def _email_addresses(self, text: str) -> str:
        edits: list[tuple[int, int, str]] = []
        for m in EMAIL_RE.finditer(text):
            addr = m.group()
            if SAFE_EMAIL_DOMAIN.search(addr.split("@", 1)[1]):
                continue
            edits.append((m.start(), m.end(), self._emails.get(addr)))
        return apply_edits(text, edits)

    def _domains(self, docs: list[str]) -> list[str]:
        for text in docs:
            for m in _DONE_FQDN.finditer(text):
                self._fqdns.reserve(m.group())
        out = []
        for text in docs:
            edits = [(s, e, self._fqdns.get(name)) for s, e, name in iter_fqdns(text)]
            in_cdp = False
            for line in split_lines(text):
                if not line.body.strip():
                    in_cdp = False
                    continue
                for rx in (_IP_HOST, _CDP_KV):
                    if (km := rx.match(line.body)) is not None:
                        edits.append(self._fqdn_edit(line.start, km))
                row = _CDP_ROW.match(line.body) if in_cdp else None
                if row is not None and not self._fqdns.is_done(row.group("v")):
                    edits.append(self._fqdn_edit(line.start, row))
                if _CDP_HEADER.match(line.body):
                    in_cdp = True
            out.append(apply_edits(text, edits))
        return out

    def _fqdn_edit(self, offset: int, m: re.Match[str]) -> tuple[int, int, str]:
        name = m.group("v")
        new = name if self._fqdns.is_done(name) else self._fqdns.get(name)
        return offset + m.start("v"), offset + m.end("v"), new

    def _serial_numbers(self, text: str) -> str:
        lines = [(ln.start, ln.body) for ln in split_lines(text)]
        edits = []
        spans = list(iter_serial_spans(lines))
        for _, _, value in spans:
            self._serials.reserve(value)
        for s, e, value in spans:
            if not self._serials.is_done(value):
                edits.append((s, e, self._serials.get(value)))
        return apply_edits(text, edits)

    # ------------------------------------------------------------------ MAC addresses

    def _assign_macs(self, macs: set[str]) -> None:
        for mac in macs:
            parts = bytes.fromhex(mac.replace(":", ""))
            if parts[:5] == b"\x00\x00\x5e\x00\x53":
                self._mac_used.add(parts[5])
        fresh = sorted(
            {m for m in macs if self._mac_needs_map(m)} - self._maps["mac"].keys(),
            key=lambda mac: digest(self.salt, "mac", mac),
        )
        for mac in fresh:
            while self._mac_next in self._mac_used and len(self._mac_used) < 256:
                self._mac_next = (self._mac_next + 1) % 256
            idx = self._mac_next
            self._mac_used.add(idx)
            self._mac_next = (self._mac_next + 1) % 256
            self._maps["mac"][mac] = f"00:00:5e:00:53:{idx:02x}"

    def _macs(self, text: str) -> str:
        found = list(find_macs(text))
        bare = [
            (m.start("v"), m.end("v"), ":".join(m["v"].lower()[i : i + 2] for i in range(0, 12, 2)))
            for m in MAC_BARE_RE.finditer(text)
        ]
        eui: list[tuple[AddrSpan, str]] = []
        for s in iter_addr_spans(text):
            a = s.address
            if isinstance(a, IPv6Address) and s.embedded is None:
                iid = int(a) & ((1 << 64) - 1)
                if is_eui64(iid):
                    eui.append((s, mac_of_eui64(iid)))
        self._assign_macs({m.mac for m in found} | {b[2] for b in bare} | {mac for _, mac in eui})
        edits: list[tuple[int, int, str]] = []
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
        for start, end, mac in bare:
            new = self._maps["mac"].get(mac)
            if new is not None:
                upper = any(c in "ABCDEF" for c in text[start:end])
                edits.append((start, end, format_mac(new, MacStyle.BARE, upper=upper)))
        for s, mac in eui:
            new = self._maps["mac"].get(mac)
            if new is not None and isinstance(s.address, IPv6Address):
                base = int(s.address) & ~((1 << 64) - 1)
                edits.append((s.start, s.end, str(IPv6Address(base | eui64_of_mac(new)))))
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

    def _wants_remap(self, cls: str) -> bool:
        return cls == "public" or (cls == "private" and self.remap_private)

    def _ips(self, docs: list[str]) -> list[str]:
        spans = [list(iter_addr_spans(t)) for t in docs]
        nets = [self._isis_nets(t) for t in docs]
        v4_items: list[tuple[int, int]] = []
        v6_items: list[tuple[int, int]] = []
        todo: list[list[AddrSpan]] = []
        for doc in spans:
            marked: list[AddrSpan] = []
            for s in doc:
                cls = s.classify()
                remap = self._wants_remap(cls)
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
                    marked.append(s)
            todo.append(marked)
            del marked
        for doc_nets in nets:
            for _, _, addr in doc_nets:
                cls = classify_v4(addr)
                if self._wants_remap(cls):
                    v4_items.append((int(addr), 32))
                elif cls == "keep" and any(addr in n for n in V4_POOLS):
                    self._v4.reserve(int(addr), 32)
        self._v4.plan(v4_items)
        self._v6.plan(v6_items)
        out = []
        for text, marked, doc_nets in zip(docs, todo, nets, strict=True):
            edits = []
            for s in marked:
                v4 = s.v4
                if v4 is not None:
                    new = IPv4Address(self._v4.map(int(v4), s.v4_plen))
                    self._maps["ipv4"][str(v4)] = str(new)
                    if s.embedded == "mapped":
                        repl = f"::ffff:{new}"
                    elif s.embedded is not None:
                        assert isinstance(s.address, IPv6Address)
                        repl = str(IPv6Address((int(s.address) & ~0xFFFFFFFF) | int(new)))
                    else:
                        repl = str(new)
                else:
                    assert isinstance(s.address, IPv6Address)
                    repl = str(IPv6Address(self._v6.map(int(s.address), s.plen)))
                    self._maps["ipv6"][str(s.address)] = repl
                edits.append((s.start, s.end, repl))
            for start, end, addr in doc_nets:
                if self._wants_remap(classify_v4(addr)):
                    new = IPv4Address(self._v4.map(int(addr), 32))
                    digits = "".join(f"{o:03d}" for o in new.packed)
                    repl = f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}"
                    self._maps["isis_net"][str(addr)] = str(new)
                    edits.append((start, end, repl))
            out.append(apply_edits(text, edits))
        return out

    @staticmethod
    def _isis_nets(text: str) -> list[tuple[int, int, IPv4Address]]:
        """ISIS NET system IDs that encode an IPv4 address (``2002.0100.0001`` = 200.201.0.1)."""
        found = []
        for m in ISIS_NET_RE.finditer(text):
            digits = m["sys"].replace(".", "")
            octets = [int(digits[i : i + 3]) for i in range(0, 12, 3)]
            if max(octets) <= 255:
                found.append((m.start("sys"), m.end("sys"), IPv4Address(bytes(octets))))
        return found
