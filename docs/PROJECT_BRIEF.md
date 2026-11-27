# Project brief

> The founding document of routerscope: the problem, the principles, the scope and the backlog. Technical details live in [architecture.md](architecture.md) and [roadmap.md](roadmap.md).

## 1. Problem and goal

Network engineers at ISPs, carriers and CDNs spend minutes every day on work that should take seconds: scrolling terminal history, grepping config backups, comparing `show` outputs before and after a maintenance window, and tracing where a prefix-list or policy is used. Most tooling covers Cisco, Juniper and Arista well and **Huawei VRP, MikroTik RouterOS, Nokia SR OS and IP Infusion OcNOS** poorly, although these are common in ISP networks.

routerscope is an open-source, daily-use tool that makes that work **faster and safer** without disturbing the network it observes:

> *Everything your routers have ever shown you, and everything configured on them, searchable in milliseconds. Browse it like Winbox, on any vendor. Test a change before you apply it.*

A second goal is a healthy contributor community. The project is designed with a natural, technical contribution surface (fixtures, parsers, rules, vendor plugins) and publishes small reusable libraries that other projects can depend on.

## 2. Principles

1. **Terminal- and tool-independent.** Works with Termius, PuTTY, SecureCRT, MobaXterm, Windows Terminal, OpenSSH, Tabby, iTerm and others. No core feature depends on a specific terminal's plugin or API.
2. **Faster, not only safer.** Every feature must answer "how many seconds or minutes does this save per day?". Search is instant (< 100 ms); no slow screens, no mandatory extra steps.
3. **Non-intrusive.** Read-only by default, rate-limited, never changes persistent configuration, no heavy commands without an explicit request.
4. **Local-first and private.** Runs on the user's machine or server. No telemetry, no outbound data. Secrets in the OS keyring.
5. **Truly multi-vendor**, focused on what the market lacks: Huawei VRP, MikroTik RouterOS 7, Nokia SR OS (classic and MD-CLI), OcNOS, plus Cisco IOS/IOS-XE/IOS-XR and Junos.
6. **Cross-platform.** Windows is a first-class platform, alongside Linux and macOS.
7. **English for code, docs and issues**, with READMEs also in Portuguese and Spanish for the large Latin American ISP community.
8. **Extensible.** Vendors, parsers, suggestion rules and importers are plugins discovered through entry points, so third parties can publish their own packages.

## 3. Landscape: what exists and where the gap is

routerscope integrates with or depends on existing projects where licenses allow. The core is **Apache-2.0**: no GPL dependencies in the core; GPL integrations only as isolated optional plugins.

| Area | Existing tools | Gap routerscope fills |
|---|---|---|
| CLI output parsing | clijson (IOS-XR/Junos/VRP, session parsing, pre/post diff), ntc-templates/TextFSM, Genie, TTP | A searchable index with UI and timeline; RouterOS, SR OS and OcNOS coverage. Use clijson as a backend where it fits |
| Hierarchical config | hier_config (remediation/rollback; VRP, Junos, SR Linux), ciscoconfparse2, netconf-parser | SR OS classic/MD-CLI, RouterOS (`/path set`), OcNOS |
| Session recording | Warpgate (SSH bastion with recording), ssh-guard-proxy | Indexing recordings **by device and command** with search and diff; a lightweight local proxy instead of a server bastion |
| Terminal logs | SecureCRT, PuTTY, MobaXterm, Windows Terminal write log files; some terminals keep logs without export; keeplog indexes local shell output only | Importers for all of these, plus proxy capture for terminals without log export |
| Analysis / simulation | Batfish (Cisco, Juniper, Arista, Palo Alto, F5, A10...; not Huawei, MikroTik or Nokia SR OS) | Policy simulation and impact analysis for VRP, RouterOS and SR OS; delegate to Batfish where supported |
| Lab / digital twin | netlab (RouterOS 7, SR-SIM, vJunos, FRR), containerlab, NetReplica/nrx, Nautobot Digital Twin | Labs generated from **collected real configs**, not from a source of truth |
| Cross-vendor translation | Netcanon (Cisco, Junos, Arista, Aruba, MikroTik, VyOS) | VRP and SR OS, preferably contributed upstream |
| Winbox-like GUI | Winbox and RouterOS-only managers, NetConsole (Cisco/Junos/Arista) | A **multi-vendor, read-first** object browser with where-used navigation |
| BGP / MANRS audit | ROSE-T (emulation-based; Junos, IOS-XR, RouterOS), ARouteServer | A static, instant auditor with vendor-specific fix suggestions, including VRP and SR OS |
| Version → CVE | Commercial NCM tools; RouterOS-only scanners | Read-only multi-vendor version-to-advisory inventory |
| Auto-documentation | NetDoc (NetBox plugin), Merlin (Cisco/pyATS) | Docs generated from collected configs of multi-vendor ISP networks |
| Language servers | Cisco-only LSPs, BIRD2 LSP; VRP has syntax highlighting only | LSP for VRP, SR OS, RouterOS and Junos (optional module) |

## 4. Product

### Core features
1. **Instant search** over configs, command outputs and history: free text; **IP/prefix containment** (`192.0.2.0/24` finds everything inside or covering it); MAC in any format; ASN; standard/large/extended communities; VLAN; interface names normalized across vendors; descriptions and circuit IDs; policy, prefix-list, ACL and VRF names; filters by device, vendor, command and time range.
2. **Timeline and semantic diff.** "What did `display bgp peer` on R1 look like before last night's window?" Diff by natural key (peer, interface, prefix), ignoring counters, uptime and timestamps. Hierarchical config diff showing the parent block.
3. **Locate ("Where is it?").** IP, MAC, VLAN or prefix → devices, interfaces and VRFs where it appears (config, ARP/ND, MAC table, routes), in the latest snapshot and over time.
4. **Winbox-like browser (read-first).** Device tree → sections (Interfaces, IP, Routing/BGP peers, Policies, Prefix-lists, ACL/Firewall, VRFs, QoS, System) as filterable tables. References are clickable; **Where used** lists every user of an object; broken references and unused objects are flagged.
5. **Suggestions (deterministic first).** A rule engine that reports issues with evidence (config lines) and generates **fix and rollback snippets in the vendor's dialect**. Never applied automatically.
6. **Simulation and what-if**, in phases: test a route against a peer's policy; change impact; peer/link failure; lab twin export.
7. **CLI, local API and a read-only MCP server**, so AI assistants can query the index during troubleshooting.

### Writes, later and opt-in
Configuration writes arrive no earlier than v0.6, opt-in only, always as preview → diff → rollback snippet → apply through the vendor's own safety mechanism (MikroTik Safe Mode, `commit confirmed` on Junos and IOS-XR, candidate + `commit confirmed` on SR OS MD-CLI, `commit trial` on VRP where available).

## 5. Architecture and non-intrusion guarantees

See [architecture.md](architecture.md): the four capture sources (read-only collector, local recording SSH proxy, importers, optional source of truth), the processing pipeline, the stack, the repository layout, the plugin system and the seven non-intrusion guarantees (read-only by default, no persistent change, rate limiting, prefer existing sources, transparent proxy, local audit log, kill switch).

## 6. Roadmap

See [roadmap.md](roadmap.md). Each version has a testable acceptance criterion; releases are small and frequent.

## 7. Module backlog

Each module is tracked as an `epic` issue.

| # | Module | What it does | How it stays terminal-independent | Priority |
|---|---|---|---|---|
| A1 | Session index (core) | Searchable index of everything routers have shown | Proxy, importers, paste | P0 |
| A2 | Safe paste | Preview, highlight dangerous commands, confirm and pace multi-line pastes | In the SSH proxy (detects input bursts) | P1 |
| A3 | netcmd-safety (library) | Classify commands as read / config / destructive per vendor and version | A library used by collector, proxy, MCP and agents | P0 |
| A4 | Config-mode alarm | Notify when entering config mode on a production-tagged device | Proxy detects config prompts | P2 |
| A5 | Maintenance watcher | Poll a read command and alert on state change (e.g. peer Established) | Collector, rate-limited, time-boxed | P1 |
| A6 | Muscle-memory translator | Suggest the current vendor's equivalent of a Cisco-style command | Proxy or UI command palette | P2 |
| A7 | Network notepad | Live calculations: subnets, masks, IPv6, dBm/mW, throughput, MAC and interface formats | UI tab and CLI | P2 |
| A8 | Config language server | Go-to-definition, references, undefined and unused objects in editors | Editor-based | P3 |
| A9 | Daily change digest | Human-readable daily summary of config changes from backups | Reads backups only | P1 |
| A10 | CGNAT subscriber lookup | Public IP + port + time → subscriber | — | On hold |
| B1 | Policy tester | Which policy term matches a route and the resulting attributes | UI and CLI | P0 (v0.5) |
| B2 | Change impact | What a prefix-list/policy/ACL change affects, using real received routes | UI and CLI | P1 (v0.5) |
| B3 | Failure what-if | Prefixes left without a path and new best paths when a peer/link fails | UI and CLI | P1 (v0.6) |
| B4 | Lab twin export | netlab/containerlab topology from collected configs | Exporter | P2 |
| B5 | Config translator (VRP / SR OS) | Cross-vendor translation with a support matrix, preferably upstream in Netcanon | Exporter / UI | P3 |
| B6 | Auto-documentation | Per-device and per-network docs and L3 diagrams from snapshots | Exporter | P2 |
| B7 | BGP / MANRS hygiene rules | max-prefix, bogon filters, RPKI ROV, GTSM, BFD, customer prefix-lists, community scrubbing, IPv4/IPv6 parity, TCP-AO, next-hop-self; fix per vendor | Rules over the index | P0 (v0.4) |
| B8 | Version → CVE inventory | Match device versions with advisories (opt-in feed) | Uses collected version outputs | P2 |
| B9 | Pair/link consistency checker | Compare both ends of links and redundant pairs (MTU, BFD, timers, VLAN, LACP, policies) | Rules over the index | P1 |
| B10 | IPv6 plan + config generator | Address plan per POP/role/customer and the matching config snippets | UI and CLI | P3 |

## 8. Quality

- **Golden tests first** for parsers and segmenters: `input.raw` → `expected.yml`.
- **Real, sanitized fixtures** per vendor, version and command. `tools/sanitize_fixture.py` replaces public IPs with documentation ranges, replaces hostnames and removes secrets; CI fails if it detects a secret.
- **Property tests** (hypothesis) for IP/prefix containment, MAC/interface normalization and diff.
- **Command classifier tests:** a large table per vendor; no write command may ever pass as read (mandatory regression test).
- **Proxy tests:** real SSH sessions against a test server with simulated vendor prompts; added latency is measured.
- **Benchmarks** with the roadmap targets, run in CI with tolerance.
- **Optional lab** (manual job or self-hosted runner): netlab/containerlab with FRR, RouterOS CHR and SR Linux / SR-SIM.
- **CI:** Windows/Linux/macOS × Python 3.12/3.13; ruff; mypy strict; pytest with coverage; wheels; tag-driven releases with PyPI trusted publishing and a Windows executable.
- **Coverage:** ≥ 85% for the libraries, ≥ 75% for the app, without chasing numbers with useless tests.

## 9. Security and privacy

- Credentials in the OS keyring; never in plain text or logs.
- Automatic secret redaction in the index (passwords, SNMP communities, TACACS/RADIUS keys, `password 7`, `cipher`, `secret`); mandatory on export and sharing.
- UI and API bind to `127.0.0.1` by default; exposing them requires a token.
- No outbound calls except documented opt-ins (CVE feed, PeeringDB, RPKI).
- Vulnerability reporting process in [SECURITY.md](https://github.com/dalcorsogabriel/routerscope/blob/main/SECURITY.md).

## 10. Community

- A README that shows the value in 20 seconds (search, diff, where-used), one-line install, and "works with any terminal" at the top.
- Short, technical contribution paths: add a fixture, add a parser, add a YAML rule, add a vendor.
- `good first issue` items per vendor and command; `vendor:*`, `area:*` and `P0`–`P3` labels.
- GitHub Discussions, Code of Conduct, issue and PR templates, CODEOWNERS.
- Frequent releases with a changelog.
- Organic growth only: no artificial commits, accounts or trivial mass PRs.

## 11. Definition of done for v0.1.0

- [ ] `pipx install routerscope` / `uv tool install routerscope` works on Windows, Linux and macOS.
- [ ] Imports logs from at least 4 terminals, Oxidized/RANCID repositories and pasted text.
- [ ] Segments sessions of the 7 target vendors, with golden tests.
- [ ] Searches text, IP/prefix (containment), MAC (any format), ASN, community and normalized interface names with p95 < 100 ms on a 1 GB index.
- [ ] Semantic time diff for at least 5 state commands per vendor, plus hierarchical config diff.
- [ ] Documented minimal local UI and CLI.
- [ ] `netcmd-safety` published on PyPI with docs.
- [ ] CI green on the matrix; coverage targets met; zero secrets in fixtures.
- [ ] README with demo GIF, support matrix and contribution guide; 30+ open good first issues.

## 12. Out of scope

- Traffic classification of any kind: OTT/CDN identification, content-domain catalogs, flow/NetFlow analysis to identify services, or mapping of embedded caches.
- Write commands on real devices without explicit opt-in and the vendor's safety mechanism.
- Core features that depend on a specific terminal's plugin or API.
- Telemetry, or sending data to external services without opt-in.
- GPL dependencies in the Apache-2.0 core.
- Committing fixtures that did not go through the sanitizer.
