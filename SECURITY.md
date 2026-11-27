# Security policy

routerscope touches network devices and stores their configs, so security reports are taken seriously.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub:
[Security → Report a vulnerability](https://github.com/dalcorsogabriel/routerscope/security/advisories/new).

Please include the affected version, what an attacker could do, and steps to reproduce. You should get an acknowledgement within 7 days. We will coordinate a fix and a disclosure date with you and credit you unless you prefer otherwise.

## In scope

- A command that changes device state being classified as read by `netcmd-safety`, or sent by the collector.
- Secrets (passwords, keys, SNMP communities) leaking into the index, logs or exports despite redaction.
- The local API, UI or MCP server being reachable from other hosts without the token.
- The SSH proxy weakening authentication or exposing credentials.
- Any outbound network call that is not documented and opt-in.

## Supported versions

Pre-alpha: only the latest `main` and the latest release are supported.

## Accidentally published sensitive data

If you find real (unsanitized) device data in this repository, report it the same way. It will be removed from the history of future releases and the contributor will be contacted.
