# tools/

Maintenance scripts. Planned: support-matrix generator from `fixtures/`.

## sanitize_fixture.py

Mandatory before committing any fixture. Thin wrapper around `routerscope.sanitize`.

```sh
# sanitize (stdout by default; the file is read and written as bytes)
uv run python tools/sanitize_fixture.py raw-capture.txt -o fixtures/<vendor>/<version>/<command>/input.raw
uv run python tools/sanitize_fixture.py input.raw --in-place --salt myteam --map-out ~/private/input.map.json

# check (what CI runs): exit 1 and print `file:line: kind` for every finding
uv run python tools/sanitize_fixture.py --check fixtures "packages/*/tests/data"
```

Options: `--salt S` (changes the deterministic mapping), `--remap-private` (also remap RFC1918/CGNAT),
`--keep-descriptions` (do not replace free text), `--vendor V` (hint), `--map-out FILE`,
`--allow-file FILE`.

**Private, CGNAT and link-local addresses (10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16) are
kept unless you give `--remap-private`.** Review whether your private plan is itself sensitive.

What it does, in order: redacts credentials (`<redacted>`: passwords, hashes, keys, SNMP communities
and users, RADIUS/TACACS keys, user and password in URLs, SNMP engine IDs except the enterprise
prefix), then replaces free text (interface and peer descriptions, banners, SNMP contact and
location, RouterOS comments, user names) with `desc-N` / `userN`, hostnames with `R1, R2...`,
e-mail addresses with `userN@example.com`, domain names with `hostN.example.net`, serial numbers,
ESNs and license IDs with `SERIALN`, MACs (and MACs embedded in EUI-64 IPv6 interface IDs) with
`00-00-5E-00-53-xx` (RFC 7042, original notation kept), public AS numbers with documentation ASNs
(`64496-64511`, `65536-65551`; AS contexts only, including names such as `AS3356-IN`), public IPv4
with `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and then `198.18.0.0/15`, and public IPv6
with `2001:db8::/32`. Addresses in the same original network stay in the same mapped network,
prefix lengths and host bits are kept, masks and wildcards are never touched. Everything else,
including line endings and trailing spaces, is byte-exact; replaced tokens can change width, so
table columns may shift. Sanitizing twice changes nothing.

Encodings: UTF-8 (with or without BOM) and UTF-16/UTF-32 (with a BOM, or NUL-interleaved without)
are decoded, sanitized and written back in the same encoding. Anything else (Latin-1, binary,
archives) is refused with exit code 2: convert the capture to UTF-8 first.

`--map-out FILE` writes the original to sanitized mapping, which is the key to your private data.
The tool refuses a path inside a git repository; keep it elsewhere (`*.sanitize-map*` is also
git-ignored as a second guard) and never commit it.

Known gaps, so review the output: VRF, route-map, prefix-list and ACL names, aliases and scripts,
circuit IDs in names, `show interfaces description` style tables, a `sysname`-like word in the
middle of a prose line, a bare 12-digit hex MAC without a "mac" word next to it, and a Junos
`community NAME {` outside an `snmp { }` block.

### Check mode

`--check PATH...` scans files and directories recursively (wildcards are expanded by the tool, so it
also works in PowerShell). No file is skipped: a file that is not text in a supported encoding, or
has an archive or image suffix, is itself a finding (`binary`). Two layers run on every file:

1. the sanitizer's own detectors: unredacted credentials, PEM and certificate blocks, public IPv4
   and IPv6 addresses, public ASNs in AS contexts and e-mail addresses;
2. a deliberately noisy second opinion written independently (kinds `secret`, `credentials`,
   `fqdn`, `mac`, `eui64`, `serial`, `freetext`, shown with `heuristic:` in the detail): a credential
   keyword followed by something that is not `<redacted>`, domain names, MACs that are not in the
   documentation range, EUI-64 interface IDs, serial lines, and description, comment, location,
   contact or banner text that is not `desc-N`. Markdown files only get layer 1.

Credential values are never printed. CI scans `fixtures/` and `packages/*/tests/data` only. Test
files that deliberately contain public addresses or credential-looking commands (for example
`packages/netaddr-search/tests`, `packages/routerscope/tests/sanitize`) are outside that scope on
purpose.

A legitimate value can be accepted through `.sanitize-allow` at the repository root: one literal
or regular expression per line, `#` starts a comment. Entries are global (they apply to every
finding in every file) and a regular expression must match the whole finding text. Keep entries
narrow and comment why.
