"""IP/prefix containment search and MAC/interface-name normalization for network tooling."""

from netaddr_search.iface import VENDORS, interface_aliases, normalize_interface, same_interface
from netaddr_search.ip import (
    SQL_COVERING,
    SQL_INSIDE,
    SQL_OVERLAPS,
    IPMatch,
    MatchKind,
    Relation,
    bounds,
    bounds_int,
    find_ips,
    parse_network,
    query_params,
    relation,
    sql_fragments,
)
from netaddr_search.mac import MacMatch, MacStyle, find_macs, format_mac, normalize_mac

__version__ = "0.0.1"

__all__ = [
    "SQL_COVERING",
    "SQL_INSIDE",
    "SQL_OVERLAPS",
    "VENDORS",
    "IPMatch",
    "MacMatch",
    "MacStyle",
    "MatchKind",
    "Relation",
    "__version__",
    "bounds",
    "bounds_int",
    "find_ips",
    "find_macs",
    "format_mac",
    "interface_aliases",
    "normalize_interface",
    "normalize_mac",
    "parse_network",
    "query_params",
    "relation",
    "same_interface",
    "sql_fragments",
]
