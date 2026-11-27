# fixtures/

Real device output and configs, **sanitized**, used by golden tests. Layout:

```
fixtures/<vendor>/<os-version>/<command-slug>/
    input.raw        # exact bytes captured from the device (required)
    meta.yml         # platform, OS version string, command, capture date, mode (optional but helpful)
    expected.yml     # what the parser must produce (added by whoever writes the parser)
```

Vendor slugs: `huawei_vrp`, `mikrotik_ros7`, `nokia_sros` (use `<version>-classic` or `<version>-mdcli`), `ipinfusion_ocnos`, `cisco_ios` (IOS and IOS-XE), `cisco_xr`, `juniper_junos`.

Command slug: the command in lowercase with spaces and slashes turned into `-`, e.g. `display-bgp-peer`, `routing-bgp-session-print`, `show-router-bgp-summary`.

## Rules

- **Sanitize before committing.** Until `tools/sanitize_fixture.py` lands, do it by hand:
  - public IPv4 → documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; public IPv6 → `2001:db8::/32`. Keep private/CGNAT ranges as they are, and keep the structure (same prefix lengths, same relationships between addresses);
  - hostnames, descriptions, circuit IDs and customer names → neutral names (`PE1`, `CUST-A`, `UPLINK-1`);
  - third-party ASNs → documentation ASNs `64496–64511` and `65536–65551` (or private `64512–65534`);
  - passwords, keys, hashes, SNMP communities, TACACS/RADIUS secrets → remove the value or replace with `<redacted>`.
- CI will fail on anything that looks like a secret.
- One command per folder. Record the exact OS version (`display version`, `/system/resource/print`, `show version`).
- Files here are stored byte-for-byte (`.gitattributes` disables line-ending normalization). Do not reformat them.
