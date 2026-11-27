# routerscope

**Instant search, time-travel diff and a Winbox-like browser for multi-vendor router configs and CLI sessions. Works with any terminal.**

[English](README.md) · [Português](README.pt-BR.md) · [Español](README.es.md)

[![CI](https://github.com/dalcorsogabriel/routerscope/actions/workflows/ci.yml/badge.svg)](https://github.com/dalcorsogabriel/routerscope/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
![Status](https://img.shields.io/badge/status-pre--alpha-orange)

> **Works with any terminal:** Termius, PuTTY, SecureCRT, MobaXterm, Windows Terminal, OpenSSH, Tabby, iTerm. No terminal plugin needed.

> ⚠️ **Pre-alpha.** The app is not usable yet. Three standalone libraries are ready to try from source: [`netcmd-safety`](packages/netcmd-safety), [`netprompt`](packages/netprompt) and [`netaddr-search`](packages/netaddr-search). Star/watch the repo, or pick a [good first issue](https://github.com/dalcorsogabriel/routerscope/issues?q=is%3Aopen+label%3A%22good+first+issue%22).

## Why

*Everything your routers have ever shown you, and everything configured on them, searchable in milliseconds. Browse it like Winbox, on any vendor. Test a change before you apply it.*

Network engineers lose minutes every day scrolling terminal history, grepping config backups and asking "what did `display bgp peer` look like before last night's window?". Existing tools cover Cisco/Juniper/Arista well and **Huawei VRP, MikroTik RouterOS and Nokia SR OS** poorly. routerscope fills that gap.

## What it will do

- **Instant search** across configs, command outputs and history: free text, **IP/prefix containment** (`200.0.0.0/22` finds everything inside or covering it), MAC in any format, ASN, communities, VLAN, interface names normalized across vendors, policy/prefix-list/ACL/VRF names.
- **Timeline and semantic diff**: compare outputs by natural key (peer, interface, prefix), ignoring counters, uptime and timestamps. Hierarchical config diff.
- **"Where is it?"**: which devices/interfaces/VRFs an IP, MAC, VLAN or prefix shows up on.
- **Winbox-like browser (read-first)** for every vendor, with click-through references, **where-used**, broken references and unused objects.
- **Suggestions** with evidence and a fix + rollback snippet in the vendor's own dialect. Never applied automatically.
- **What-if simulation**: test a route against a peer's policy, change impact, failure what-if, lab twin export.
- **CLI, local API and a read-only MCP server** so AI assistants can query the index.

## How it captures data (no terminal lock-in)

1. **Importers**: logs from SecureCRT/PuTTY/MobaXterm/Windows Terminal/Tabby/iTerm, Oxidized and RANCID repositories, or just paste text.
2. **Local recording SSH proxy**: set `localhost` as a jump host in any SSH client (Termius *Host Chaining*, OpenSSH `ProxyJump`...).
3. **Read-only collector**: polite, rate-limited, never changes persistent config; every command goes through [`netcmd-safety`](packages/netcmd-safety).

## Principles

Read-only by default · local-first, no telemetry · Windows, Linux and macOS · secrets in the OS keyring · extensible through plugins.

## Vendors

Huawei VRP · MikroTik RouterOS 7 · Nokia SR OS (classic and MD-CLI) · IP Infusion OcNOS · Cisco IOS/IOS-XE/IOS-XR · Juniper Junos. A support matrix generated from the test fixtures will appear here with v0.1.

## Roadmap

| Version | Theme |
|---|---|
| v0.1 | "Everything offline": importers, segmentation, search, diff, CLI, minimal UI, `netcmd-safety` on PyPI |
| v0.2 | Terminal-independent capture: SSH recording proxy, read-only collector |
| v0.3 | Winbox-like browser, where-used, locate, MCP server |
| v0.4 | Suggestion rules (BGP/MANRS hygiene) with fix and rollback snippets |
| v0.5 | Policy tester and change impact |
| v0.6 | Failure what-if, lab twin export, opt-in safe writes |

Details: [docs/roadmap.md](docs/roadmap.md) · Architecture: [docs/architecture.md](docs/architecture.md)

## Reusable libraries

| Package | What it does |
|---|---|
| [`netcmd-safety`](packages/netcmd-safety) | Classify a CLI command as read / config / destructive, per vendor |
| [`netprompt`](packages/netprompt) | Detect prompt, vendor and CLI mode; segment terminal sessions |
| [`netaddr-search`](packages/netaddr-search) | IP/prefix containment search; MAC and interface-name normalization |

## Contributing

The easiest ways to help need no knowledge of the codebase: a **sanitized fixture** of a command on your vendor/version, a **parser** for one command, or a **YAML rule**. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE)
