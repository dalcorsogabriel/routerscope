# netcmd-safety

> Status: alpha. Part of [routerscope](https://github.com/dalcorsogabriel/routerscope).

Small, dependency-free library that tells you whether a network CLI command is safe to send. It classifies a command as **read**, **session**, **config** or **destructive**, per vendor:

- Cisco IOS / IOS-XE (`cisco_ios`)
- Cisco IOS-XR (`cisco_xr`)
- Huawei VRP (`huawei_vrp`)
- MikroTik RouterOS 7 (`mikrotik_ros7`)
- Juniper Junos (`juniper_junos`)
- Nokia SR OS classic CLI and MD-CLI (`nokia_sros`)
- IP Infusion OcNOS (`ipinfusion_ocnos`)

It is meant for collectors, SSH proxies, MCP servers and AI agents that must never send a write command by accident.

## Install

```sh
pip install netcmd-safety
```

## Usage

```python
from netcmd_safety import Mode, Verdict, classify, is_collector_safe

classify("display bgp peer", "huawei_vrp").verdict        # Verdict.READ
classify("undo peer 192.0.2.1", "huawei_vrp").verdict     # Verdict.DESTRUCTIVE
classify("sh run | redirect flash:x", "cisco_ios").reason  # '| redirect'

# Session-only settings (paging, width) are allowed for collectors, but they are not READ:
is_collector_safe("screen-length 0 temporary", "huawei_vrp")  # True
is_collector_safe("screen-length 0", "huawei_vrp")            # False (persistent)

# Pass the CLI mode when you know it (for example from netprompt):
classify("neighbor 192.0.2.1 shutdown", "cisco_ios", mode=Mode.CONFIG).verdict  # DESTRUCTIVE

# Multi-line input (a paste) is classified line by line, tracking mode changes;
# the most dangerous line wins and is named in the reason:
r = classify("system-view\nbgp 64496\nundo peer 192.0.2.1\nreturn", "huawei_vrp")
r.verdict, r.reason  # DESTRUCTIVE, "line 3 ('undo peer 192.0.2.1'): undo"
```

## Verdicts

| Verdict | Meaning | Collector may send |
|---|---|---|
| `READ` | Only displays information | yes |
| `SESSION` | Changes the current CLI session only (paging, width, leaving a mode) | yes |
| `UNKNOWN` | Not recognized; treat as unsafe | no |
| `CONFIG` | Changes configuration or enters configuration mode | no |
| `DESTRUCTIVE` | Removes or disables configuration, resets sessions or counters, reboots, writes or deletes files | no |

## How it decides

- **Allowlist, fail closed.** A command is `READ` only if it starts with a known read keyword. Anything else is `UNKNOWN` at best.
- **Abbreviations** are resolved the way CLIs do it: a word matches a keyword if it is the keyword itself or an unambiguous prefix of it (`sh ip int br`, `dis cu`, `/ip ad pr`). An ambiguous abbreviation is not read.
- **Pipes** are checked against an allowlist per vendor (`| include`, `| match`, `| display set`...). Pipes that write files (`| redirect`, `| tee`, `| append`, `| save`, `| file`) are destructive, and unknown pipes are unknown. Output redirection with `>` is destructive where the CLI supports it.
- **Config mode:** every statement is `CONFIG`, and it becomes `DESTRUCTIVE` when it removes or disables something (`no`, `undo`, `delete`, `shutdown`, `disable`, `admin-state disable`...).
- **RouterOS:** every bare word is checked against the verb list and the worst verb wins, so an abbreviated menu name cannot hide a write. Scripting syntax (`[...]`, `{...}`, `$var`, `:cmd`) is unknown.
- `ping` and `traceroute` are `UNKNOWN` on purpose: they do not change state, but they generate traffic and an automated collector should not send them.

## Contributing cases

Test cases are plain text files in [`tests/cases/`](tests/cases/), one per vendor, and need no Python:

```
read                display bgp peer
destructive @config undo peer 192.0.2.1
```

A write command must never be added as `read` or `session`. If you are unsure, use `unknown`.
