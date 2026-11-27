"""Find fully qualified domain names (FQDNs) that identify a network or a customer."""

from __future__ import annotations

import re
from collections.abc import Iterator


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


_GENERIC_TLDS = _words(
    "com net org edu gov mil int info biz name pro aero coop museum io dev app cloud tech online "
    "site xyz top club shop store blog link live news email ai tv me cc ws local lan internal "
    "corp home intranet localdomain arpa mobi asia tel travel jobs cat"
)
_CC_TLDS = _words(
    "ac ad ae af ag al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt "
    "bw by bz ca cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er "
    "es et eu fi fj fk fm fo fr ga gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr "
    "ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li "
    "lk lr ls lt lu lv ly ma mc md mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne "
    "nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa "
    "sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz tc td tf tg th tj tk tl tm tn to "
    "tr tt tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw"
)
# Two-letter TLDs that are also common words or RouterOS property suffixes (remote.as, .id):
# only accepted with at least three labels.
_AMBIGUOUS = _words(
    "as id in is it no to do my so at be by go on or us we am ma im re pa ad al ar mo na ne se sh "
    "si st tm tr vi ve ws"
)
_FILE_EXT = _words(
    "bin cfg txt log conf pkg img tar gz zip tgz py sh xml json yml yaml csv html htm pdf bak old "
    "dat db cer crt pem key lic ios swi pie rpm iso exe md ini sql jpg png gif cap pcap so lua js "
    "css php pl rb c h cpp exp sig tmp lnk rs ps"
)
_TLDS = (_GENERIC_TLDS | _CC_TLDS) - _FILE_EXT

FQDN_RE = re.compile(
    r"(?<![\w.@-])(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+"
    r"(?P<tld>[A-Za-z]{2,24})(?![\w-])(?!=)(?!\.\w)"
)
_SAFE = re.compile(
    r"(?:(?:^|\.)example\.(?:com|net|org)|\.(?:example|invalid|test|localhost)|^localhost)$",
    re.IGNORECASE,
)


def is_safe_domain(name: str) -> bool:
    """True for reserved documentation names (example.com/net/org, *.example, *.invalid...)."""
    return _SAFE.search(name) is not None


def iter_fqdns(text: str) -> Iterator[tuple[int, int, str]]:
    """Yield ``(start, end, name)`` for each non-reserved FQDN-shaped token in ``text``."""
    for m in FQDN_RE.finditer(text):
        tld = m["tld"].lower()
        name = m.group(0)
        if tld not in _TLDS or is_safe_domain(name):
            continue
        if tld in _AMBIGUOUS and name.count(".") < 2:
            continue
        yield m.start(), m.end(), name
