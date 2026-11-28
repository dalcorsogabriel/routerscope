# Architecture

> Status: design document (pre-alpha). Decisions that change this page get an ADR in [`decisions/`](decisions/0001-record-architecture-decisions.md).

## Capture layer: independent of any terminal

Four sources that can be combined. The user turns on the ones they want.

1. **Collector (active pull, read-only).** routerscope connects to devices itself (SSH via asyncssh/scrapli/netmiko, NETCONF, SNMP, RouterOS API), on demand or on a schedule. It runs a curated set of read commands per vendor (config and state: interfaces, BGP peers, filtered routes, ARP/ND, MAC, LLDP, version, transceivers). No terminal involved.
2. **Local recording SSH proxy (passive).** An SSH server on `localhost` that the user sets as a **jump host / ProxyJump** in any client (Termius calls this *Host Chaining*). It forwards the session to the real device and records the stream in real time, splitting commands from output by prompt. Later, opt-in "terminal features" live here too, without depending on the terminal: config-mode alarm, safe paste, command translation. Built on `asyncssh`. Credentials pass through agent/keyboard-interactive; no password stored by default. Telnet proxy for legacy gear.
3. **Importers.** Log files from SecureCRT, PuTTY, MobaXterm, Windows Terminal, Tabby, iTerm and `script`; **Oxidized (git)** and **RANCID (CVS/git)** repositories; Warpgate recordings; text pasted into the UI (covers Termius and anything else); a watched "drop" folder.
4. **Optional sources of truth:** NetBox/Nautobot (inventory, sites, roles) via API, read-only.

## Pipeline

```
capture (collector | proxy | importers | paste)
   → normalization (strip ANSI, pagination, echoed prompts, timestamps)
   → vendor/platform detection (prompt, verbs, fingerprints)
   → segmentation into (device, command, output, timestamp, source)
   → parsers (state → normalized models) + config parser (hierarchical tree)
   → neutral model (Device, Interface, IPAddress, VRF, BGPPeer, Policy, PrefixList, ACL,
                    StaticRoute, IGP, LAG, VLAN, Transceiver, Version, ARPEntry, MACEntry)
   → storage (SQLite + FTS5; snapshots versioned by timestamp)
   → services: search | diff | locate | refs/where-used | suggestions | simulate | export
   → interfaces: CLI (Typer) | local API (FastAPI) | local web UI | MCP server
```

`ARPEntry` (ip, canonical MAC, interface, vrf) and `MACEntry` (canonical MAC, vlan, port, `static`/`dynamic`, bridge domain / service / bridge name) come from state commands only; ages and timers are deliberately not modelled so repeated captures diff cleanly. See [Command parsers](commands.md).

## Stack

- **Python 3.12+**, managed with **uv**. Distribution: `pipx` / `uv tool install`, plus a Windows executable (PyInstaller) attached to releases.
- **SQLite + FTS5**: single file, fast, zero infrastructure. Auxiliary IP/prefix indexes store IPv4/IPv6 integers and ranges for containment queries.
- **FastAPI** for the local API. **Local web UI** served on `127.0.0.1` (Svelte or HTMX, whichever is lighter to maintain; decided by ADR). Optional later: a **Tauri** desktop wrapper.
- **Typer** for the CLI. **asyncssh** for proxy and collector (scrapli as alternative). **MCP Python SDK** for the MCP server.
- Dependencies under evaluation (license must be compatible with Apache-2.0 in the core; GPL only as an isolated optional plugin): `clijson`, `hier_config`, `ntc-templates`/`textfsm`, `ttp`, `netaddr`/`ipaddress`, `keyring`, `pydantic`.

## Repository layout (monorepo with publishable packages)

```
routerscope/
├── packages/
│   ├── netcmd-safety/   # small lib: classify a command (read | config | destructive) per vendor   → PyPI
│   ├── netprompt/       # lib: detect prompt/vendor/mode (exec/config), segment sessions         → PyPI
│   ├── netaddr-search/  # lib: IP/prefix containment search, MAC/interface normalization         → PyPI
│   └── routerscope/     # app: core, storage, services, CLI, API, UI, MCP
│       └── src/routerscope/
│           ├── capture/{collector,proxy,importers}/
│           ├── vendors/{cisco_ios,cisco_xr,huawei_vrp,mikrotik_ros7,juniper_junos,nokia_sros,ipinfusion_ocnos}/
│           ├── model/  storage/  services/{search,diff,locate,refs,suggest,simulate}/
│           └── api/  ui/  cli/  mcp/
├── rules/       # suggestion rules in YAML (easy contributions)
├── fixtures/    # real, SANITIZED outputs/configs per vendor/version (easy contributions)
├── docs/        # mkdocs-material; docs/decisions/ holds ADRs
├── tests/  benchmarks/  tools/
└── .github/     # workflows, issue/PR templates, CODEOWNERS
```

The three small libraries are strategic: other projects (network MCP servers, automation tools) can depend on them without pulling in the app.

## Plugin system

- Entry point groups: `routerscope.vendors`, `routerscope.importers`, `routerscope.rules`, `routerscope.exporters`.
- A vendor plugin implements: `detect()`, `segment()`, `parse_config()`, `parse_command(cmd, output)`, `readonly_commands()`, `render_snippet(intent)` (for suggestions and rollback) and, later, `safe_apply_strategy()`.
- A guide, **"Add a vendor in 30 minutes"**, with a template and sample fixtures, ships with v0.1.

## Non-intrusion guarantees

1. **Read-only by default.** Every command the collector sends goes through `netcmd-safety`; anything not classified as read is blocked. Allowlists per vendor and version, with tests.
2. **No persistent change.** Paging is disabled **for the session only** (`terminal length 0`, `screen-length 0 temporary`, `environment no more` on SR OS classic, `without-paging` on RouterOS...). Config is never saved.
3. **Rate limiting and politeness:** one session per device, jitter between commands, configurable minimum interval, time windows, timeouts and backoff. Heavy commands (full BGP table, `display current-configuration` on very large boxes) only on explicit request or with filters.
4. **Prefer existing sources** (Oxidized/RANCID backups, NetBox, recorded logs) before touching a device.
5. **Transparent proxy:** < 5 ms added latency per keystroke. If the proxy fails, the session either continues or fails loudly, never silently.
6. **Local audit log** of everything the collector ran: device, command, timestamp.
7. **Kill switch:** one command/flag disables all active access.

## Security and privacy

- Credentials in the OS keyring; never in plain text or logs.
- Automatic secret redaction in the index (passwords, SNMP communities, TACACS/RADIUS keys, `password 7`, `cipher`, `secret`). Redaction is mandatory on export/share.
- UI and API listen on `127.0.0.1` by default; exposing them requires a token.
- No outbound network calls except documented opt-ins (CVE feed, PeeringDB, RPKI). No telemetry.
