"""Secret redaction rules shared by :func:`redact_secrets` and the scanner.

Every rule captures the secret value in the named group ``v``. Redaction replaces only that
group with :data:`PLACEHOLDER` (keeping surrounding quotes), so the line shape survives.
``vendor`` is only a hint: all generic rules always apply, so a wrong hint cannot leak a secret.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import NamedTuple

from routerscope.sanitize._lines import Line, Rule, rule, split_lines

PLACEHOLDER = "<redacted>"

_EOL = re.compile(r"\r\n|\n|\r")

# value: a quoted string, or a token that stops before a Junos-style ";" terminator
_VP = r'"[^"]*"|\S+?(?=;(?:\s|$)|\s|$)'
_V = rf"(?P<v>{_VP})"
_SKIP = (
    r"(?:(?:[0-9]{1,2}|cipher|irreversible-cipher|simple|plain|hash2?|encrypted|clear|md5|sha\d*"
    r"|password|local|remote|ascii-text|hexadecimal|ascii|hex|level\s+\d+|type\s+\d+)\s+)*"
)
_DENY = (
    r"(?!(?:is|are|was|set|has|not|can|will|required|configured|none|disabled|enabled|prompt"
    r"|policy|encryption|recovery|address|hostname|key|min-length|max-length|lifetime|aging"
    r"|history|attempts|retries|key-string|key-chain|keychain)(?:\s|$|;))(?![{}])(?!\"\")"
)
_COMM_SKIP = r"(?:(?:read|write|complex|cipher|simple|irreversible-cipher)\s+)*"
_CIPHER_DENY = r"(?!(?:aes|3des|des|rc4|chacha|sm4|hmac|null|ssh|rsa|dh|aead)[\w-]*(?:\s|$))"
_MD5_DENY = (
    r"(?!(?:cipher|simple|plain|key-chain|keychain|key|hex|encrypted|clear|hmac|auth|spi"
    r"|authentication)(?:\s|$|;))(?![{}])"
)
_KEYWORDS = (
    r"authentication-key|auth-key|privacy-key|private-key|encryption-key|shared-key"
    r"|pre-shared-key|preshared-key|master-key|session-key|key-string|psk"
)

RULES: tuple[Rule, ...] = (
    rule("vrp-blob", r"(?P<v>%\^%#.*?%\^%#)"),
    rule("vrp-blob-old", r"(?P<v>%@%@.*?%@%@)"),
    rule(
        "password",
        rf"(?<!\w)[\w-]*?(?:password|passwd|passphrase|secret)(?![\w-])\s+{_SKIP}{_DENY}{_V}",
    ),
    rule("key-keyword", rf"(?<!\w)(?:{_KEYWORDS})(?!\w)\s+{_SKIP}{_DENY}{_V}"),
    rule("cipher", rf"(?<![\w-])(?:cipher|irreversible-cipher)\s+{_CIPHER_DENY}(?P<v>\S+)"),
    rule(
        "key-typed",
        rf"(?<![\w-])key\s+(?:(?:[0-9]|encrypted|clear|hash2?|cipher|simple|plain)\s+)+{_DENY}{_V}",
    ),
    rule(
        "aaa-key",
        r"(?<![\w-])(?:tacacs|radius|hwtacacs|ldap|kerberos)[\w-]*\s[^\r\n]*?"
        rf"(?<![\w-])key\s+(?!chain\b){_SKIP}{_DENY}{_V}",
    ),
    rule("key-line", rf"^\s*key\s+(?!chain\b)(?!\d+\s*;?\s*$){_SKIP}{_DENY}{_V}"),
    rule(
        "assign",
        r"(?<![\w.-])[\w.-]*?(?:password|passwd|passphrase|secret|token|psk|key)\s*=\s*(?!\"\")"
        r'(?P<v>"(?:[^"\\]|\\.)+"|\S+)',
    ),
    rule(
        "colon",
        r"(?<![\w-])(?:[\w-]*?(?:password|passwd|passphrase|secret)|api[-_]?key|private[-_]?key"
        r"|secret[-_]?key|access[-_]?key|token|psk)[\"']?[ \t]*:[ \t]*"
        r"(?P<v>\"[^\"]+\"|'[^']+'|[^\s,;{}\"']+)",
    ),
    rule("hash", r"(?P<v>\$(?:[0-9][a-z]?|y)\$[^\s\"';]{3,})"),
    rule(
        "snmp-community",
        rf"(?<![\w-])snmp[\w-]*\s+community\s+{_COMM_SKIP}(?![{{}}]){_V}",
    ),
    rule(
        "snmp-host",
        r"(?<![\w-])snmp-server\s+host\s+\S+\s+(?:(?:vrf\s+\S+|version\s+\S+|traps?|informs?"
        r"|udp-port\s+\d+)\s+)*(?!(?:traps?|informs?|version|vrf|udp-port)(?:\s|$))"
        r"(?P<v>\S+)",
    ),
    rule("securityname", rf"(?<![\w-])securityname\s+(?:(?:cipher|simple|plain)\s+)?{_V}"),
    rule("community-block", rf"^\s*community\s+{_V}", ctx=r"^snmp\b"),
    rule(
        "ros-snmp-name",
        r'(?<![\w.-])name=(?P<v>"[^"]*"|\S+)',
        ctx=r"^/snmp[ /]+community\b",
        ros=True,
    ),
    rule(
        "snmp-user",
        r"(?<![\w-])(?:auth|priv)\s+(?:md5|sha[\w-]*|aes(?:\s+\d+)?|3des|des)\s+"
        rf"(?!(?:priv|auth|access)(?:\s|$)){_V}",
    ),
    rule(
        "md5",
        r"(?<![\w-])md5\s+(?:[0-9]{1,3}\s+|(?![0-9]{1,3}\s))(?:(?:plain|simple|encrypted|clear|7)\s+)?"
        rf"{_MD5_DENY}{_V}",
    ),
    rule(
        "auth-header",
        r"authorization\s*:\s*(?:bearer|basic)\s+(?P<v>[A-Za-z0-9+/=._~-]{8,})",
    ),
    rule("named-token", rf"(?<![\w-])(?:api|access|auth|bearer)[-_ ]?token\s+{_DENY}{_V}"),
    rule("isakmp", rf"(?<![\w-])isakmp\s+key\s+{_SKIP}{_DENY}{_V}"),
    rule("auth-text", rf"(?<![\w-])authentication\s+text\s+{_V}"),
    rule(
        "standby-auth",
        rf"(?<![\w-])(?:standby|vrrp)\s+\d+\s+authentication\s+(?!(?:md5|text)\b){_DENY}{_V}",
    ),
    rule(
        "auth-mode-simple",
        rf"(?<![\w-])authentication-mode\s+(?:simple|plain)\s+(?:cipher\s+)?{_DENY}{_V}",
    ),
)

_PEM_RE = re.compile(
    r"(?P<head>-----BEGIN (?P<t>[A-Z0-9 ]+?)-----)(?P<body>.*?)"
    r"(?P<tail>-----END (?P=t)-----|\Z)",
    re.DOTALL,
)
_CERT_RE = re.compile(
    r"(?P<head>^[ \t]*certificate[ \t]+(?:self-signed[ \t]+|ca[ \t]+)?[0-9A-Fa-f]+[ \t]*"
    r"(?:\r\n|\n|\r))(?P<body>(?:[ \t]+[0-9A-Fa-f ]+(?:\r\n|\n|\r))+)(?P<tail>[ \t]*quit\b)",
    re.MULTILINE,
)


class SecretSpan(NamedTuple):
    rule: str
    start: int  # absolute offsets of the value
    end: int
    value: str


def is_placeholder(value: str) -> bool:
    """True when ``value`` is the redaction placeholder, optionally quoted."""
    return value.strip("\"'") == PLACEHOLDER


def _quoted(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[0] + PLACEHOLDER + value[0]
    return PLACEHOLDER


def _substitute(m: re.Match[str]) -> str:
    value = m.group("v")
    if is_placeholder(value):
        return m.group(0)
    s = m.start(0)
    return m.group(0)[: m.start("v") - s] + _quoted(value) + m.group(0)[m.end("v") - s :]


def _redact_line(line: Line, vendor: str | None) -> str:
    body = line.body
    if not body.strip():
        return body
    for r in RULES:
        if r.applies(line, vendor):
            body = r.pattern.sub(_substitute, body)
    return body


def _block_body(body: str, *, inline_start: bool = True) -> str:
    """Replace the body of a PEM/certificate block by one placeholder line.

    ``inline_start``: the body begins on the marker's own line (PEM), so that remainder is kept.
    """
    eols = list(_EOL.finditer(body))
    if not eols:
        return PLACEHOLDER
    first = eols[0].end() if inline_start else 0
    indent = re.match(r"[ \t]*", body[first:])
    lead = indent.group() if indent else ""
    after = body[eols[-1].end() :]
    trailing = after if not after.strip() else ""
    return body[:first] + lead + PLACEHOLDER + eols[0].group() + trailing


def _pem_sub(m: re.Match[str]) -> str:
    body = m["body"]
    if body.strip() == PLACEHOLDER:
        return m.group(0)
    return m["head"] + _block_body(body) + m["tail"]


def _cert_sub(m: re.Match[str]) -> str:
    return m["head"] + _block_body(m["body"], inline_start=False) + m["tail"]


def _redact_once(text: str, vendor: str | None) -> str:
    text = _PEM_RE.sub(_pem_sub, text)
    text = _CERT_RE.sub(_cert_sub, text)
    out: list[str] = []
    for line in split_lines(text):
        out.append(_redact_line(line, vendor))
        out.append(line.eol)
    return "".join(out)


def redact_secrets(text: str, vendor: str | None = None) -> str:
    """Replace secret values with ``<redacted>``, keeping the shape of every line.

    Covers passwords, secrets, keys, SNMP communities, TACACS/RADIUS keys, routing-protocol
    authentication keys, password hashes (``$1$``, ``$9$``, VRP ``%^%#...%^%#``), RouterOS
    ``password=``-style assignments, PEM blocks and certificates. ``vendor`` is a hint; generic
    rules always apply. Idempotent; line endings and everything else are untouched.
    """
    for _ in range(8):
        new = _redact_once(text, vendor)
        if new == text:
            return new
        text = new
    return text


def iter_secret_spans(line: Line, vendor: str | None = None) -> Iterator[SecretSpan]:
    """Yield unredacted secret values on ``line`` (placeholders are skipped)."""
    for r in RULES:
        if not r.applies(line, vendor):
            continue
        for m in r.pattern.finditer(line.body):
            value = m.group("v")
            if not is_placeholder(value):
                yield SecretSpan(r.name, line.start + m.start("v"), line.start + m.end("v"), value)


def iter_block_spans(text: str) -> Iterator[SecretSpan]:
    """Yield unredacted PEM and certificate blocks (the span covers the block body)."""
    for m in _PEM_RE.finditer(text):
        if m["body"].strip() != PLACEHOLDER:
            yield SecretSpan("pem", m.start("body"), m.end("body"), m["body"])
    for m in _CERT_RE.finditer(text):
        yield SecretSpan("certificate", m.start("body"), m.end("body"), m["body"])
