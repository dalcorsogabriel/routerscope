# netaddr-search

> **Experimental.** Early-stage library, part of [routerscope](https://github.com/dalcorsogabriel/routerscope). The API may change without notice before 1.0; pin the exact version if you depend on it.

Helpers for network-aware search: IPv4/IPv6 prefix containment (find everything inside or covering `192.0.2.0/24`), MAC normalization (`aabb.cc00.1122` = `AA:BB:CC:00:11:22` = `aabb-cc00-1122`) and interface-name normalization across vendors (`Gi0/0/1`, `GE0/0/1`, `ether1`, `1/1/c1/1`).

## Usage

```python
from netaddr_search import (
    parse_network,
    relation,
    find_ips,
    bounds,
    query_params,
    SQL_INSIDE,
    normalize_mac,
    format_mac,
    MacStyle,
    normalize_interface,
    same_interface,
)

parse_network("192.0.2.0 0.0.0.255")  # IPv4Network('192.0.2.0/24'), Cisco wildcard
relation(parse_network("192.0.2.128/25"), parse_network("192.0.2.0/24"))  # Relation.INSIDE

for m in find_ips("ip address 192.0.2.1 255.255.255.0"):
    m.address, m.network  # 192.0.2.1, 192.0.2.0/24

# SQLite: store (version, start, end) as INTEGER/BLOB/BLOB from bounds(net); then
#   SELECT ... FROM prefixes WHERE <SQL_INSIDE>   with   query_params(net)
# SQL_COVERING (rows containing the query) and SQL_OVERLAPS are also provided.

normalize_mac("aabb.ccdd.eeff")  # 'aa:bb:cc:dd:ee:ff'
format_mac("aa:bb:cc:dd:ee:ff", MacStyle.HUAWEI)  # 'aabb-ccdd-eeff'

normalize_interface("Gi0/0/1")  # 'GigabitEthernet0/0/1'
same_interface("GE0/0/1", "GigabitEthernet0/0/1", "huawei_vrp")  # True
```

Pure standard library, no runtime dependencies. Interface names are normalized within a vendor
family (`cisco_ios`, `cisco_xr`, `huawei_vrp`, `mikrotik_ros7`, `juniper_junos`, `nokia_sros`,
`ipinfusion_ocnos`); names are never mapped across vendors.

## Behaviour notes

- **IP versions**: networks of different versions are always `Relation.DISJOINT`; IPv4-mapped
  IPv6 (`::ffff:192.0.2.1`) does not match IPv4 rows.
- **SQL**: `SQL_INSIDE`, `SQL_COVERING` and `SQL_OVERLAPS` assume columns named `version`,
  `start` and `end`. For other names use `sql_fragments(prefix)`, e.g.
  `sql_fragments("ip_")["inside"]` uses `ip_version`, `ip_start`, `ip_end`.
- **Default routes and ACL "any"**: `find_ips` and `parse_network` read `0.0.0.0 0.0.0.0` as
  `0.0.0.0/0` (mask) and `0.0.0.0 255.255.255.255` as `0.0.0.0/0` (wildcard); after a non-zero
  address `255.255.255.255` is a /32 mask and `0.0.0.0` a /32 wildcard.
- **Version numbers**: a four-part version (`7.16.1.0`) looks like an IPv4 address and is
  returned. Use `find_ips(text, skip_after=("version", "build", "release"))` to drop matches
  that follow those words on the same line.
- **IPv6**: a bare `::` is not matched; `::/0`, `::/128` and `::1` are.
- **Interfaces**: types may be abbreviated to any unique prefix of at least 2 characters
  (`Gig 0/1`, `Ten1/1/1`, `Fas0/1`). On `cisco_ios`, `Fo` is `FortyGigabitEthernet`
  (`FortyGigE` on `cisco_xr`).
- **Errors**: `parse_network`, `normalize_mac` and `normalize_interface` raise `TypeError` for
  non-`str` input.
