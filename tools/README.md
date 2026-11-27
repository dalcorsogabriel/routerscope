# tools/

Maintenance scripts. Planned: support-matrix generator from `fixtures/`.

## sanitize_fixture.py

Mandatory before committing any fixture. Thin wrapper around `routerscope.sanitize`.

```sh
# sanitize (stdout by default; the file is read and written as bytes)
uv run python tools/sanitize_fixture.py raw-capture.txt -o fixtures/<vendor>/<version>/<command>/input.raw
uv run python tools/sanitize_fixture.py input.raw --in-place --salt myteam --map-out input.sanitize-map.json

# check (what CI runs): exit 1 and print `file:line: kind` for every finding
uv run python tools/sanitize_fixture.py --check fixtures "packages/*/tests/data"
```

Options: `--salt S` (changes the deterministic mapping), `--remap-private` (also remap RFC1918/CGNAT),
`--descriptions` (replace interface/peer description text with `desc-N`), `--vendor V` (hint),
`--map-out FILE` (writes original -> sanitized mapping; it is the key to your private data, so
keep it local: `*.sanitize-map*` is git-ignored), `--allow-file FILE`.

What it does, in order: redacts secrets (`<redacted>`), then maps hostnames to `R1, R2...`, e-mails to
`userN@example.com`, MACs to `00-00-5E-00-53-xx` (RFC 7042, original notation kept), public AS numbers
to documentation ASNs (`64496-64511`, `65536-65551`; AS contexts only), public IPv4 to
`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and then `198.18.0.0/15`, and public IPv6 to
`2001:db8::/32`. Addresses in the same original network stay in the same mapped network, prefix
lengths and host bits are kept, masks and wildcards are never touched. Everything else, including
line endings and trailing spaces, is byte-exact; replaced tokens can change width, so table columns
may shift. Sanitizing twice changes nothing. Review the result: the tool is conservative but not
omniscient (domain names, circuit IDs and free text in banners are not touched).

### Check mode

`--check PATH...` scans files and directories recursively (wildcards are expanded by the tool, so it
also works in PowerShell) for unredacted secrets, PEM/certificate blocks, public IPv4/IPv6 addresses,
public ASNs in AS contexts and e-mail addresses. Secret values are never printed.
CI scans `fixtures/` and `packages/*/tests/data` only. Test files that deliberately contain public
addresses or secret-looking commands (for example `packages/netaddr-search/tests`,
`packages/routerscope/tests/sanitize`) are outside that scope on purpose.

A legitimate value can be accepted through `.sanitize-allow` at the repository root: one literal or
regular expression per line, `#` starts a comment; the whole finding text must match. Keep entries
narrow and comment why.
