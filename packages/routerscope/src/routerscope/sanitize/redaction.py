"""Secret redaction rules shared by :func:`redact_secrets` and the scanner.

Every rule captures the secret value in the named group ``v`` (and optionally ``v1``, ``v2``...
for further values on the same match, such as a URL user name). Redaction replaces only those
groups with :data:`PLACEHOLDER` (keeping surrounding quotes), so the line shape survives.
``vendor`` is only a hint: all generic rules always apply, so a wrong hint cannot leak a secret.

Fail-closed post-check: when a rule would replace a bare keyword or a short number (``md5``,
``aes``, ``7``...) while another token follows on the line, the replacement is widened to
swallow that next token too, so a placeholder never sits on the wrong token.
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
# type/algorithm/keyword tokens that may sit between a keyword and its value
_TYPES = (
    r"[0-9]{1,3}|cipher|irreversible-cipher|simple|plain-text|plain|clear|encrypted|hash2?"
    r"|md5|sha[\w-]*|aes[\w-]*|3des|des|(?:hmac|cmac)-[\w-]+|message-digest|password|local|remote"
    r"|ascii-text|ascii|hexadecimal|hex|key|type|value|level"
)
# possessive: never give a type token back to be mistaken for the value
_SKIP = rf"(?:(?:{_TYPES})\s+)*+"
_DENY = (
    r"(?!(?:is|are|was|set|has|not|can|will|required|configured|none|disabled|enabled|prompt"
    r"|policy|encryption|recovery|address|hostname|min-length|max-length|lifetime|aging"
    r"|history|attempts|retries|key-string|key-chain|keychain|config-key)(?:\s|$|;))(?![{}])(?!\"\")"
)
_COMM_SKIP = r"(?:(?:read|write|complex|cipher|simple|irreversible-cipher)\s+)*+"
_CIPHER_DENY = r"(?!(?:aes|3des|des|rc4|chacha|sm4|hmac|null|ssh|rsa|dh|aead)[\w-]*(?:\s|$))"
_MD5_DENY = (
    r"(?!(?:cipher|simple|plain|key-chain|keychain|key|hex|encrypted|clear|hmac|auth|spi"
    r"|authentication)(?:\s|$|;))(?![{}])"
)
_ALG = r"(?:md5|sha[\w-]*|aes[\w-]*(?:\s+\d+)?|3des|des\d*|hmac[\w-]*)"
_KEYWORDS = (
    r"authentication-key|auth[-_]key|privacy-key|private-key|encryption-key|shared-key"
    r"|shared-key-cipher|pre-shared-key|preshared-key|master-key|session-key|key-string|psk"
    r"|[\w-]*-psk|hash-key|md5-key|hmac-[\w-]*key|sha[\w-]*-key|cmac-[\w-]*key|hexadecimal-key"
    r"|plain-text-password-value|simple-password|ascii-text|hexadecimal|secret-key|api-?key"
    r"|token|bearer|read-community|write-community|community-string|snmpv2c-community"
    r"|enablepw|creds?|credentials|master-password|[\w]+_(?:key|secret|password|token)"
    r"|key-hash|ssh-key"
)
_SEP = r"(?:\s+|\s*[=:]\s*)"

RULES: tuple[Rule, ...] = (
    rule("vrp-blob", r"(?P<v>%\^%#.*?%\^%#)"),
    rule("vrp-blob-old", r"(?P<v>%@%@.*?%@%@)"),
    rule(
        "url-credentials",
        r"[A-Za-z][A-Za-z0-9+.-]*://(?P<v1>[^\s:/@\"'<>]+):(?P<v>[^\s\"'/]+)@(?=[^\s@\"']+)",
    ),
    rule("url-user", r"[A-Za-z][A-Za-z0-9+.-]*://(?P<v>[^\s:/@\"'<>]+)@(?=[^\s@\"']+)"),
    rule(
        "password",
        rf"(?<!\w)[\w-]*?(?:password|passwd|pwd|passphrase|secret)(?![\w-])\s+{_SKIP}{_DENY}{_V}",
    ),
    rule("key-keyword", rf"(?<![\w])(?:{_KEYWORDS})(?![\w-]){_SEP}{_SKIP}{_DENY}{_V}"),
    rule(
        "pass-word",
        rf"(?<![\w-])pass(?![\w-])\s+(?!(?:log|any|all|in|out|quick|inspect|through)(?:\s|$)){_DENY}{_V}",
    ),
    rule("cipher", rf"(?<![\w-])(?:cipher|irreversible-cipher)\s+{_CIPHER_DENY}(?P<v>\S+)"),
    rule(
        "key-typed",
        rf"(?<![\w-])key\s+(?=(?:{_TYPES})\s){_SKIP}{_DENY}{_V}",
    ),
    rule(
        "config-key",
        rf"(?<![\w-])key\s+config-key\s+password-encrypt\s+{_V}",
    ),
    rule(
        "aaa-key",
        r"(?<![\w-])(?:tacacs|radius|hwtacacs|ldap|kerberos)[\w-]*\s[^\r\n]*?"
        rf"(?<![\w-])key\s+(?!chain\b){_SKIP}{_DENY}{_V}",
    ),
    rule("key-line", rf"^\s*key\s+(?!chain\b)(?!\d+\s*;?\s*$){_SKIP}{_DENY}{_V}"),
    rule("auth-key-word", rf"(?<![\w-])authentication\s+key\s+{_SKIP}{_DENY}{_V}"),
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
        r"|udp-port\s+\d+|auth|priv|noauth|authpriv|encrypted)\s+)*+"
        r"(?!(?:traps?|informs?|version|vrf|udp-port|auth|priv|noauth|authpriv)(?:\s|$))"
        r"(?P<v>\S+)",
    ),
    rule("securityname", rf"(?<![\w-])securityname\s+(?:(?:cipher|simple|plain)\s+)?{_V}"),
    rule("community-block", rf"^\s*community\s+{_V}", ctx=r"^snmp\b"),
    rule(
        "community-flat",
        r"(?<![\w-])(?:usm-)?community\s+(?P<v>\"[^\"]*\")"
        r"(?=\s+hash2?\b|\s+(?:r|rw|rwa|na)\b|\s+group\b|\s*\{\s*access-permissions)",
    ),
    rule(
        "ros-snmp-name",
        r'(?<![\w.-])name=(?P<v>"[^"]*"|\S+)',
        ctx=r"^/snmp[ /]+community\b",
        ros=True,
    ),
    rule(
        "snmp-user",
        rf"(?<![\w-])(?:auth|priv)\s+{_ALG}\s+(?:(?:encrypted|clear|[0-9])\s+)*+"
        rf"(?!(?:priv|auth|access)(?:\s|$)){_V}",
    ),
    rule(
        "md5",
        r"(?<![\w-])md5\s+(?:[0-9]{1,3}\s+|(?![0-9]{1,3}\s))"
        rf"(?:(?:plain|simple|encrypted|clear|7|key)\s+)*+{_MD5_DENY}{_V}",
    ),
    rule(
        "auth-header",
        r"authorization\s*:\s*(?:bearer|basic)\s+(?P<v>[A-Za-z0-9+/=._~-]{8,})",
    ),
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
    rule("ssid-key", rf"(?<![\w-])ssid\s+\S+\s+key\s+{_SKIP}{_DENY}{_V}"),
    rule(
        "ssh-public-key",
        r"(?<![\w-])(?:ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-\S+)\s+(?P<v>AAAA[A-Za-z0-9+/=]+)",
    ),
    rule(
        "crypto-key-import",
        r"(?<![\w-])crypto\s+key\s+import\s+\S+\s+\S+\s+(?:pem\s+)?(?:exportable\s+)?"
        r"(?:terminal|\S+:\S*)\s+(?P<v>\S+)",
    ),
    rule(
        "engine-id",
        r"engine-?id\s+(?:local\s+|remote\s+\S+\s+(?:udp-port\s+\d+\s+)?)?"
        r"(?P<pre>[0-9A-Fa-f]{8})(?P<v>[0-9A-Fa-f]{2,})(?![\w<])",
    ),
)

_VALUE_GROUPS = {
    r.name: [n for n in r.pattern.groupindex if re.fullmatch(r"v\d*", n)] for r in RULES
}
_WEAK = re.compile(rf"(?:{_TYPES})$", re.IGNORECASE)

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
_NEXT_TOKEN = re.compile(r"[ \t]+([^\s{};]\S*)")


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


def _is_weak(value: str) -> bool:
    return _WEAK.match(value.strip("\"'")) is not None


def _rule_spans(r: Rule, body: str) -> Iterator[tuple[int, int, str]]:
    """Yield ``(start, end, value)`` to redact for rule ``r`` on ``body``, widened if needed."""
    pos = 0
    names = _VALUE_GROUPS[r.name]
    for m in r.pattern.finditer(body):
        spans: list[tuple[int, int, str]] = []
        for name in names:
            if m.start(name) < 0 or is_placeholder(m.group(name)):
                continue
            start, end, value = m.start(name), m.end(name), m.group(name)
            if name == "v":
                # fail closed: never leave the real value after a keyword we redacted
                for _ in range(3):
                    if not _is_weak(value):
                        break
                    nxt = _NEXT_TOKEN.match(body, end)
                    if nxt is None:
                        break
                    if is_placeholder(nxt.group(1)):
                        value = ""  # a keyword followed by an already redacted value: leave it
                        break
                    end, value = nxt.end(), nxt.group(1)
            if value:
                spans.append((start, end, value))
        for start, end, value in sorted(spans):
            if start >= pos:
                yield start, end, value
                pos = end


def _apply_rule(r: Rule, body: str) -> str:
    out: list[str] = []
    pos = 0
    for start, end, value in _rule_spans(r, body):
        out.append(body[pos:start])
        out.append(_quoted(value))
        pos = end
    if not out:
        return body
    out.append(body[pos:])
    return "".join(out)


def _redact_line(line: Line, vendor: str | None) -> str:
    body = line.body
    if not body.strip():
        return body
    for r in RULES:
        if r.applies(line, vendor):
            body = _apply_rule(r, body)
    return body


def _block_body(body: str, *, inline_start: bool = True) -> str:
    """Replace the body of a PEM/certificate block by one placeholder line.

    ``inline_start``: the body begins on the marker's own line (PEM); that remainder is dropped.
    """
    eols = list(_EOL.finditer(body))
    if not eols:
        return PLACEHOLDER
    first = eols[0].end() if inline_start else 0
    indent = re.match(r"[ \t]*", body[first:])
    lead = indent.group() if indent else ""
    after = body[eols[-1].end() :]
    trailing = after if not after.strip() else ""
    head = eols[0].group() if inline_start else ""
    return head + lead + PLACEHOLDER + eols[0].group() + trailing


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

    Covers passwords, secrets, keys, SNMP communities and users, TACACS/RADIUS keys,
    routing-protocol authentication keys, password hashes (``$1$``, ``$9$``, VRP
    ``%^%#...%^%#``), credentials in URLs (user name and password), SNMP engine IDs (the
    enterprise prefix is kept), RouterOS ``password=``-style assignments, PEM blocks and
    certificates. ``vendor`` is a hint; generic rules always apply. Idempotent; line endings and
    everything else are untouched.
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
        if r.applies(line, vendor):
            for start, end, value in _rule_spans(r, line.body):
                yield SecretSpan(r.name, line.start + start, line.start + end, value)


def iter_block_spans(text: str) -> Iterator[SecretSpan]:
    """Yield unredacted PEM and certificate blocks (the span covers the block body)."""
    for m in _PEM_RE.finditer(text):
        if m["body"].strip() != PLACEHOLDER:
            yield SecretSpan("pem", m.start("body"), m.end("body"), m["body"])
    for m in _CERT_RE.finditer(text):
        yield SecretSpan("certificate", m.start("body"), m.end("body"), m["body"])
