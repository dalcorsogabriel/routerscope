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

- **Sanitize before committing.** Run the sanitizer on every raw capture, then read the result:

  ```sh
  uv run python tools/sanitize_fixture.py capture.txt -o fixtures/<vendor>/<version>/<command>/input.raw
  uv run python tools/sanitize_fixture.py --check fixtures      # what CI runs
  ```

  It redacts sensitive values (`<redacted>`: hashes, SNMP communities and users, TACACS/RADIUS
  shared secrets, URL credentials), replaces free text (descriptions, banners, SNMP contact and location,
  comments, user names) with `desc-N` and `userN`, maps public IPv4/IPv6 to the documentation ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `198.18.0.0/15`, `2001:db8::/32`) keeping
  prefix lengths and same-network relationships, maps third-party ASNs to documentation ASNs
  (`64496-64511`, `65536-65551`), MACs (also inside EUI-64 IPv6 addresses) to `00-00-5E-00-53-xx`,
  hostnames to `R1, R2...`, domain names to `hostN.example.net`, serial numbers and ESNs to
  `SERIALN`, and e-mail addresses to `userN@example.com`. Use `--keep-descriptions` to keep free text.
  **Private/CGNAT ranges are kept unless you give `--remap-private`.** See `tools/README.md` for all
  options, the encodings it accepts and its known gaps (VRF, route-map and prefix-list names, circuit
  IDs inside names): read the result before you commit it.
- CI runs `--check` on `fixtures/`: it fails on unredacted credentials, public addresses, public ASNs
  in AS contexts, e-mail addresses, domain names, non-documentation MACs, serial lines and free text,
  and on any file that is not readable text. A legitimate value can go in `.sanitize-allow` (a narrow,
  global, full-match entry plus a comment).
- Never commit the file written by `--map-out` (the tool refuses a path inside a git repository): it maps
  sanitized values back to the originals (`*.sanitize-map*` is git-ignored).
- One command per folder. Record the exact OS version (`display version`, `/system/resource/print`, `show version`).
- Files here are stored byte-for-byte (`.gitattributes` disables line-ending normalization). Do not reformat them.
