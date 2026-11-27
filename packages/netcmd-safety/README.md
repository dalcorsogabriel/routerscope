# netcmd-safety

> Status: pre-alpha. Part of [routerscope](https://github.com/dalcorsogabriel/routerscope).

Small, dependency-free library that classifies a network CLI command as **read**, **config** or **destructive**, per vendor and version (Cisco IOS/IOS-XE/IOS-XR, Junos, Huawei VRP, MikroTik RouterOS 7, Nokia SR OS classic/MD-CLI, IP Infusion OcNOS).

Intended users: collectors, SSH proxies, MCP servers and AI agents that must never send a write command by accident. Unknown commands are treated as **not read** (fail closed).

Planned API (v0.1):

```python
from netcmd_safety import classify

classify("display bgp peer", vendor="huawei_vrp")  # -> Verdict.READ
classify("undo peer 10.0.0.1", vendor="huawei_vrp")  # -> Verdict.DESTRUCTIVE
```
