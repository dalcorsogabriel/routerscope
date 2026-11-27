"""Free text that identifies customers and people: descriptions, banners, user names."""

from __future__ import annotations

import re

from routerscope.sanitize._lines import Rule, rule

# trailing ";" and Junos "## comment" / "/* comment */" after a value are not part of it
_END = r"(?=\s*;?\s*(?:##.*|/\*.*)?$)"
_REST = rf"(?P<v>\"[^\"]*\"|\S.*?){_END}"
_QSTR = r'(?P<v>"(?:[^"\\]|\\.)*"|\S+)'
_USER = r'(?P<v>"[^"]+"|[^\s{};"]+)'

# kind "desc" -> desc-N, kind "user" -> userN
FREE_RULES: tuple[tuple[Rule, str], ...] = (
    (
        rule("description", rf"(?<![\w.-])(?:description|remark)(?:[ \t]*:[ \t]*|[ \t]+){_REST}"),
        "desc",
    ),
    (
        rule(
            "snmp-contact-location",
            r"(?<![\w.-])(?:snmp-server\s+|snmp-agent\s+sys-info\s+|snmp\s+)"
            rf"(?:contact|location)(?:[ \t]*:[ \t]*|[ \t]+){_REST}",
        ),
        "desc",
    ),
    (
        rule(
            "snmp-block-text",
            rf"^\s*(?:contact|location)(?:[ \t]*:[ \t]*|[ \t]+){_REST}",
            ctx=r"^snmp\b",
        ),
        "desc",
    ),
    (
        rule(
            "header-information",
            rf"(?<![\w.-])header\s+\w+\s+(?:information|file)\s+{_REST}",
        ),
        "desc",
    ),
    (
        rule("system-contact-label", rf"^\s*(?:system\s+)?(?:contact|location)\s*:\s*{_REST}"),
        "desc",
    ),
    (
        rule(
            "junos-location",
            rf"(?<![\w-])location\s+(?:building|floor|rack|region|postal-code)\s+{_REST}",
        ),
        "desc",
    ),
    (
        rule(
            "junos-location-block",
            rf"^\s*(?:building|floor|rack|region|postal-code)\s+{_REST}",
            ctx=r"^location\b",
            parent_only=True,
        ),
        "desc",
    ),
    (rule("login-banner", rf"(?<![\w.-])(?:login|motd)-banner\s+{_REST}"), "desc"),
    (
        rule(
            "ros-text",
            r"(?<![\w.-])(?:comment|note|description|contact|location|supplicant-identity)="
            r'(?P<v>"(?:[^"\\]|\\.)*"|\S+)',
        ),
        "desc",
    ),
    (rule("vlan-name", rf"^\s*name\s+{_REST}", ctx=r"^vlan\b", parent_only=True), "desc"),
    (rule("username", rf"^\s*username\s+{_USER}"), "user"),
    (rule("local-user", rf"^\s*local-user\s+{_USER}"), "user"),
    (rule("junos-set-user", rf"(?<![\w-])login\s+user\s+{_USER}"), "user"),
    (rule("junos-user", rf"^\s*user\s+{_USER}", ctx=r"^login\b", parent_only=True), "user"),
    (
        rule(
            "sros-user", r'(?<![\w-])user\s+(?P<v>"[^"]+")', ctx=r"security|user-params|local-user"
        ),
        "user",
    ),
    (rule("ppp-user", rf"(?<![\w-])(?:sent-username|chap\s+hostname)\s+{_USER}"), "user"),
    (
        rule(
            "ros-user-name",
            r'(?<![\w.-])name=(?P<v>"[^"]*"|[^\s"]+)',
            ctx=(
                r"^/(?:ppp secret|ip hotspot user|user-manager user"
                r"|user(?!\s*[/ ]\s*(?:group|aaa|ssh-keys|settings)))"
            ),
            ros=True,
        ),
        "user",
    ),
    (rule("ros-user", r'(?<![\w.-])(?:user|username)=(?P<v>"[^"]*"|[^\s"]+)'), "user"),
)

BANNER_RE = re.compile(
    r"(?P<head>^[ \t]*banner[ \t]+(?:motd|login|exec|incoming|slip-ppp|ppp)[ \t]+)"
    r"(?P<d>\^C|[^\s\w])(?P<body>.*?)(?P<end>(?P=d)|\Z)",
    re.DOTALL | re.MULTILINE | re.IGNORECASE,
)
