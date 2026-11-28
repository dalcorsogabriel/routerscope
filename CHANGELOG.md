# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Project scaffolding: uv workspace, package skeletons, CI, docs site, community files.
- `netcmd-safety`: fail-closed classifier of CLI commands (read, session, config, destructive, unknown) for Cisco IOS/IOS-XE, IOS-XR, OcNOS, Huawei VRP, Junos, Nokia SR OS and MikroTik RouterOS 7, with plain-text test tables per vendor (#23).
- `netprompt`: prompt, vendor and CLI-mode detection, terminal-noise normalization and session segmentation into prompt/command/output records (#25, #26).
- `netaddr-search`: IPv4/IPv6 prefix parsing and containment, SQLite-friendly bounds, IP/MAC extraction from text, MAC and interface-name normalization (#27).
- Neutral data model (pydantic, frozen) with source provenance on every parsed object, and the vendor plugin protocol and registry over entry points (#28, #33).
- Local storage: SQLite with FTS5 full-text index, versioned snapshots, time-travel queries, typed lookups (prefix, MAC, ASN, community, interface) and mandatory secret redaction before anything is written (#29).
- Ingestion pipeline: importers yield items, the store redacts them and the vendor plugin parses the stored text; plugin failures never stop an import.
- Importers: terminal session logs (SecureCRT, PuTTY, MobaXterm, `script`, ISO-timestamped and plain exports), pasted text, a watched drop folder, and Oxidized/RANCID git history; full-config commands in a session also become config snapshots (#30, #31, #32).
- Config tree parsers (indent, brace, set, RouterOS `/export`) and config parsing for the seven built-in vendors: interfaces, addresses, VRFs, BGP peers, static routes, prefix-lists and VLANs (#34, ADR 0003).
