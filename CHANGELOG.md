# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Project scaffolding: uv workspace, package skeletons, CI, docs site, community files.
- `netcmd-safety`: fail-closed classifier of CLI commands (read, session, config, destructive, unknown) for Cisco IOS/IOS-XE, IOS-XR, OcNOS, Huawei VRP, Junos, Nokia SR OS and MikroTik RouterOS 7, with plain-text test tables per vendor (#23).
- `netprompt`: prompt, vendor and CLI-mode detection, terminal-noise normalization and session segmentation into prompt/command/output records (#25, #26).
- `netaddr-search`: IPv4/IPv6 prefix parsing and containment, SQLite-friendly bounds, IP/MAC extraction from text, MAC and interface-name normalization (#27).
