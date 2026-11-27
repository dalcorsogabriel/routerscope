# Roadmap

Every version has a **testable** acceptance criterion. Releases are small and frequent. Progress is tracked in [GitHub milestones](https://github.com/dalcorsogabriel/routerscope/milestones).

## v0.1 — "Everything offline" (MVP)
- Importers: terminal logs, Oxidized/RANCID, pasted text.
- Prompt-based segmentation for the 7 target vendors; hierarchical config parser.
- FTS5 index; search with IP/prefix containment, normalized MAC, ASN, community and normalized interface names.
- Semantic time diff. Complete CLI and a minimal web UI (search + result + diff).
- `netcmd-safety` v0.1 published on PyPI.
- **Acceptance:** import 1 GB of logs in < 5 min on a regular laptop; search p95 < 100 ms; golden tests per vendor green in CI (Windows/Linux/macOS).

## v0.2 — Terminal-independent capture
- Local recording SSH proxy (tested with Termius, PuTTY, OpenSSH, Windows Terminal).
- Read-only collector, scheduled and on demand, with every non-intrusion guarantee.
- `netprompt` and `netaddr-search` published on PyPI.

## v0.3 — Winbox-like browser, references and "Where is it?"
- Per-device tree, per-section tables, where-used, broken references and unused objects.
- Locate IP/MAC/VLAN/prefix across the whole fleet.
- Read-only MCP server.

## v0.4 — Suggestions
- YAML rule engine with evidence + fix snippet + rollback snippet per vendor.
- Initial rule pack: BGP/MANRS hygiene.

## v0.5 — Simulation I
- Policy tester (route → inbound/outbound policy of a peer → result and matching term) for VRP, RouterOS 7, SR OS, Cisco and Junos. Delegate to Batfish where supported and cross-check results.
- Change impact: "if I change prefix-list X, which peers/policies are affected and which received routes (from snapshots) flip from accepted to rejected".

## v0.6 — Simulation II + opt-in writes
- Peer/link failure what-if using RIB snapshots (Adj-RIB-In when available).
- Lab twin export (netlab/containerlab) from collected configs.
- Opt-in writes with preview, diff, rollback and commit-confirmed / safe mode.

## v0.7+ — Modules
Backlog modules (safe paste, maintenance watcher, change digest, consistency checker, auto-docs, CVE inventory, LSP, translators...) by priority and community demand. See issues labeled `epic`.
