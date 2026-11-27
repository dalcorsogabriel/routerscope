# routerscope

**Everything your routers have ever shown you, and everything configured on them, searchable in milliseconds. Browse it like Winbox, on any vendor. Test a change before you apply it.**

!!! warning "Experimental project"
    routerscope is in an early, experimental phase and under active development. Commands, APIs and the database format may change without notice, and nothing has been validated against real devices at scale yet. Do not rely on it for production work. The app is not usable yet; this site describes the design and the roadmap.

- Works with **any terminal**: Termius, PuTTY, SecureCRT, MobaXterm, Windows Terminal, OpenSSH, Tabby, iTerm.
- **Read-only by default**, local-first, no telemetry.
- Multi-vendor with a focus on what other tools miss: **Huawei VRP, MikroTik RouterOS 7, Nokia SR OS, IP Infusion OcNOS**, plus Cisco IOS/IOS-XE/IOS-XR and Junos.

## Read next
- [Architecture](architecture.md): capture layer, pipeline, stack, plugins, non-intrusion guarantees.
- [Roadmap](roadmap.md): versions and acceptance criteria.
- [Decisions](decisions/0001-record-architecture-decisions.md): ADRs.
- [Contributing](https://github.com/dalcorsogabriel/routerscope/blob/main/CONTRIBUTING.md): fixtures, parsers, rules and vendors.
