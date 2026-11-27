"""Deliberately noisy checks for ``scan``, written independently of the sanitizer's detectors.

These do not import anything from the sanitizer: they are a second opinion, so a pattern the
sanitizer misses is still likely to be caught here. They prefer false positives; a legitimate
value goes into ``.sanitize-allow``. Every function yields ``(kind, offset, text, detail)``.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator

type Hit = tuple[str, int, str, str]

PLACEHOLDER_RE = re.compile(r"""^["']?<redacted>["']?[;,]?$""")
_TOKEN = re.compile(r"""[^\s=:;,"'{}()\[\]]+""")


def _w(text: str) -> frozenset[str]:
    return frozenset(text.split())


# ------------------------------------------------------------------------------ secret keywords

_KEYWORD = re.compile(
    r"(?<![\w-])(?:password|passwd|passphrase|secret|key|community|token|cipher|psk)(?![\w-])",
    re.IGNORECASE,
)
_BENIGN = _w(
    "chain list policy policies encryption is are was set has have not no none disabled enabled "
    "required configured prompt file id generate zeroize pubkey mypubkey rsa ec ecdsa dsa "
    "exportable label modulus size name view group rw ro rwa na access server host address "
    "vrf exec login enable level type value key ascii ascii-text hex hexadecimal md5 sha sha1 "
    "sha256 sha384 sha512 aes des 3des encrypted clear hash hash2 simple plain plain-text local "
    "remote cipher password secret message-digest string strings sent received changed min "
    "max length lifetime history attempts retries recovery lock timeout expire expires "
    "authentication authorization accounting aaa radius tacacs tacacs+ ldap ssh http https "
    "telnet console vty line interface source-interface source auth priv privacy read write "
    "version v1 v2c v3 trap traps inform informs community-list community-filter standard "
    "expanded permit deny add remove delete additive both extended export import in out any "
    "all new-format format include exclude regexp match from to for on off yes true false "
    "optional default mode algorithm algorithms suite suites sha-1 sha-256 hmac "
    "hmac-sha1 hmac-sha256 aes128 aes192 aes256 aes-128 aes-256 aes-128-cmac cmac chacha20 "
    "kex mac macs pubkeys authorized-keys public-key public pki pem der pkcs12 trustpoint "
    "cert certificate crl ca digit digits upper lower special character characters "
    "strength complexity continue quit exit more irreversible-cipher config-key "
    "password-encrypt terminal url usb flash"
)
_BENIGN_NUM = re.compile(r"\d{1,5}$")
_BENIGN_NAME = re.compile(
    r"(?:aes|3des|des|chacha|hmac|cmac|sha|md5|rsa|ecdsa|ed25519|curve|dh|diffie)[\w.@-]*$",
    re.IGNORECASE,
)


def secret_keywords(text: str) -> Iterator[Hit]:
    """A secret-ish keyword followed by a value that is not ``<redacted>``."""
    pos = 0
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        for m in _KEYWORD.finditer(body):
            rest = body[m.end() :]
            judged = None
            for tok in list(_TOKEN.finditer(rest))[:5]:
                word = tok.group()
                if PLACEHOLDER_RE.match(word) or "<redacted>" in word:
                    judged = None
                    break
                if (
                    word.lower() in _BENIGN
                    or _BENIGN_NUM.match(word)
                    or _BENIGN_NAME.match(word)
                    or len(word) < 3
                ):
                    continue
                judged = (tok, word)
                break
            if judged is not None:
                tok, word = judged
                yield "secret", pos + m.end() + tok.start(), word, "heuristic: keyword value"
        pos += len(line)


# ----------------------------------------------------------------------------------- credentials

_URL_CRED = re.compile(r"://(?P<user>[^\s/@:\"'<>]+)(?::(?P<pw>[^\s/@\"'<>]*))?@")


def url_credentials(text: str) -> Iterator[Hit]:
    for m in _URL_CRED.finditer(text):
        values = [v for v in (m["user"], m["pw"]) if v]
        if all(PLACEHOLDER_RE.match(v) for v in values):
            continue
        yield "credentials", m.start(), m.group(), "heuristic: user:pass@ URL"


# ------------------------------------------------------------------------------------ domains

_TLDS = _w(
    "com net org edu gov mil int info biz io dev app cloud tech online site xyz top club shop "
    "store blog link live news email ai tv me cc ws local lan internal corp home intranet "
    "localdomain arpa ac ad ae af ag al am ao ar at au aw az ba bb bd be bf bg bh bi bj bm bn "
    "bo br bs bt bw by bz ca cd cf cg ch ci ck cl cm cn co cr cu cv cy cz de dj dk do dz ec ee "
    "eg es et eu fi fj fm fo fr ga gd ge gf gg gh gi gl gm gn gp gr gt gu gy hk hn hr ht hu id "
    "ie il im in iq ir is it je jm jo jp ke kg kh ki kr kw ky kz la lb lc li lk lr lt lu lv ly "
    "ma mc md mg mk ml mm mn mo mt mu mv mw mx my mz na nc ne ng ni nl no np nz om pa pe pf pg "
    "ph pk pl pr ps pt py qa ro rs ru rw sa sb sc se sg si sk sl sn so sr st su sv sy tg th tj "
    "tn to tr tt tw tz ua ug uk us uy uz va vc ve vg vi vn vu za zm zw"
)
_NOT_DOMAIN_EXT = _w(
    "bin cfg txt log conf pkg img tar gz zip tgz py sh xml json yml yaml csv html htm pdf bak "
    "old dat db cer crt pem key lic ios swi pie rpm iso exe md ini sql jpg png gif cap pcap"
)
_HOST = re.compile(r"(?<![\w.@-])(?:[A-Za-z0-9_-]+\.)+(?P<tld>[A-Za-z]{2,24})(?![\w-])(?!=)")
_RESERVED = re.compile(
    r"(?:(?:^|\.)example\.(?:com|net|org)|\.(?:example|invalid|test|localhost)|^localhost)$", re.I
)


def domain_names(text: str) -> Iterator[Hit]:
    for m in _HOST.finditer(text):
        name = m.group()
        tld = m["tld"].lower()
        if tld not in _TLDS or tld in _NOT_DOMAIN_EXT or _RESERVED.search(name):
            continue
        yield "fqdn", m.start(), name, "heuristic: domain name"


# --------------------------------------------------------------------------------- MAC / EUI-64

_MAC = re.compile(
    r"(?<![\w:.-])(?:(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"
    r"|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}|(?:[0-9A-Fa-f]{4}-){2}[0-9A-Fa-f]{4})(?![\w:.-])"
)


def mac_addresses(text: str) -> Iterator[Hit]:
    for m in _MAC.finditer(text):
        digits = re.sub(r"[^0-9a-fA-F]", "", m.group()).lower()
        multicast = int(digits[:2], 16) & 1
        if multicast or digits == "0" * 12 or digits.startswith("00005e0053"):
            continue
        yield "mac", m.start(), m.group(), "heuristic: MAC address"


_V6_TOKEN = re.compile(r"(?<![\w:.])[0-9A-Fa-f:]{8,}(?![\w:])")


def eui64_interface_ids(text: str) -> Iterator[Hit]:
    """IPv6 addresses whose interface ID embeds a MAC (``xxxx:xxff:fexx:xxxx``)."""
    for m in _V6_TOKEN.finditer(text):
        if ":" not in m.group():
            continue
        try:
            iid = int(ipaddress.IPv6Address(m.group().rstrip(":"))) & ((1 << 64) - 1)
        except ValueError:
            continue
        if (iid >> 24) & 0xFFFF != 0xFFFE:
            continue
        # the documentation MAC 00:00:5e:00:53:xx gives 0200:5eff:fe00:53xx
        if iid >> 40 == 0x02005E and (iid >> 8) & 0xFFFF == 0x0053:
            continue
        yield "eui64", m.start(), m.group(), "heuristic: EUI-64 interface ID"


# ------------------------------------------------------------------------------------- serials

_SERIAL = re.compile(
    r"(?<![\w-])(?:serial(?:[ -]?(?:number|no\.?))?|esn|s/n|sn|software-id|board id)"
    r"(?![\w-])[ \t]*[:=#]?[ \t]*(?P<v>[A-Za-z0-9][A-Za-z0-9._/-]{2,})",
    re.IGNORECASE,
)
_SERIAL_DONE = re.compile(r"SERIAL\d+$")


def serial_numbers(text: str) -> Iterator[Hit]:
    for m in _SERIAL.finditer(text):
        value = m["v"]
        if _SERIAL_DONE.match(value) or PLACEHOLDER_RE.match(value) or not re.search(r"\d", value):
            continue
        yield "serial", m.start("v"), value, "heuristic: serial/ESN"


# ----------------------------------------------------------------------------------- free text

_FREE = re.compile(
    r"(?<![\w.-])(?:description|comment|location|contact|remark)(?![\w-])[ \t]*[:=]?[ \t]*"
    r"(?P<v>[^\r\n]*)",
    re.IGNORECASE,
)
_FREE_OK = re.compile(r"""^["']?desc-\d+["']?[;,]?(?:\s*(?:##.*|/\*.*))?$""")
_BANNER = re.compile(
    r"^[ \t]*banner[ \t]+\w[\w-]*[ \t]+(?P<d>\^C|[^\s\w])(?P<body>.*?)(?:(?P=d)|\Z)",
    re.DOTALL | re.MULTILINE | re.IGNORECASE,
)


def free_text(text: str) -> Iterator[Hit]:
    for m in _FREE.finditer(text):
        value = m["v"].strip()
        if not value or _FREE_OK.match(value) or PLACEHOLDER_RE.match(value):
            continue
        yield "freetext", m.start("v"), value, "heuristic: description/comment/location/contact"
    for b in _BANNER.finditer(text):
        body = b["body"].strip()
        if body and not _FREE_OK.match(body):
            yield "freetext", b.start("body"), body, "heuristic: banner text"


def all_hits(text: str) -> Iterator[Hit]:
    yield from secret_keywords(text)
    yield from url_credentials(text)
    yield from domain_names(text)
    yield from mac_addresses(text)
    yield from eui64_interface_ids(text)
    yield from serial_numbers(text)
    yield from free_text(text)
