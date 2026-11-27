# netaddr-search

> Status: pre-alpha. Part of [routerscope](https://github.com/dalcorsogabriel/routerscope).

Helpers for network-aware search: IPv4/IPv6 prefix containment (find everything inside or covering `200.0.0.0/22`), MAC normalization (`aabb.cc00.1122` = `AA:BB:CC:00:11:22` = `aabb-cc00-1122`) and interface-name normalization across vendors (`Gi0/0/1`, `GE0/0/1`, `ether1`, `1/1/c1/1`).

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
