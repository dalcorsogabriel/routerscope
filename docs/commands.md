# Command parsers

`VendorPlugin.parse_command(command, output, snapshot)` turns the output of a state command into
neutral objects (`BGPPeer`, `Interface`, `IPAddress`, `ARPEntry`, `MACEntry`, `Version`,
`Device`). The parsers are written from the documented output formats and synthetic golden files
(`packages/routerscope/tests/data/commands/`), not yet from real devices; treat the project as
experimental and report any output that does not parse.

## Supported commands

| Vendor | BGP peers | Interfaces (and addresses) | ARP | MAC table | Version / device |
|---|---|---|---|---|---|
| Cisco IOS / IOS-XE | `show ip bgp summary`, `show bgp all summary`, `show ip bgp vpnv4 vrf X summary` | `show ip interface brief [vrf X]`, `show interfaces description` | `show ip arp [vrf X]` | `show mac address-table` | `show version` |
| Cisco IOS-XR | `show bgp summary`, `show bgp vrf all summary`, `show bgp all all summary` | `show ipv4 interface brief`, `show interfaces brief`, `show interfaces description` | `show arp [vrf X]` | `show l2vpn forwarding bridge-domain mac-address` | `show version` |
| Huawei VRP | `display bgp peer`, `display bgp ipv6 peer`, `display bgp vpnv4 all peer` | `display interface brief`, `display ip interface brief`, `display interface description` | `display arp [vpn-instance X]` | `display mac-address` | `display version` |
| IP Infusion OcNOS | `show ip bgp summary`, `show bgp ipv6 summary` | `show ip interface brief` | `show arp` | `show mac address-table` | `show version` |
| Juniper Junos | `show bgp summary [instance X]` | `show interfaces terse` | `show arp [no-resolve] [vpn X]` | `show ethernet-switching table`, `show bridge mac-table` | `show version` |
| Nokia SR OS (classic and MD-CLI) | `show router [X] bgp summary` | `show router [X] interface`, `show port` | `show router [X] arp` | `show service fdb-mac` | `show version`, `show system information` |
| MikroTik RouterOS 7 | `/routing bgp session print` | `/interface print`, `/ip address print` | `/ip arp print` | `/interface bridge host print` | `/system resource print`, `/system routerboard print`, `/system identity print` |

## How commands are recognised

- Every word may be abbreviated the way engineers type it (`sh ip int br`, `dis bgp peer`,
  `/ro bg se pr`). Each word has a documented minimum length in the vendor's `commands.py`
  (usually 2 letters for `show`/`ip`/`bgp`, 3 for `display`, `interface`, `summary`).
- VRF forms (`vrf X`, `vpn-instance X`, `instance X`, SR OS `router "X"`) set `vrf` on the objects.
- Output pipes make a command unrecognised (`| include`, `| match`, `| display`...) because a
  filtered view would look like a table that lost rows. The exception is Junos `| no-more`.
  Extra arguments (an address, `where ...`, `count-only`) have the same effect.
- RouterOS accepts `/ip/arp/print`, `/ip arp print`, `print detail`, `print terse` and
  `without-paging`; the table, detail and terse shapes of the output are all parsed.
- `parse_command` returns `None` when the output is blank, an error message, or has no
  recognisable table. A table with a header but no rows gives an empty result.

## Conventions and limits

- Each object's `ref` is the exact line range of its row, including wrapped lines.
- BGP state is normalised (`Established`, `Idle`, `Idle (Admin)`, `Active`, `Connect`, `OpenSent`,
  `OpenConfirm`). A prefix count in the state column means `Established`. Counters are not stored.
- `Interface.enabled` is the **admin** state. The model has no operational (line/protocol) state,
  so up/down of enabled interfaces is not kept; this is a known gap.
- Brief outputs without a prefix length (IOS, XR and OcNOS `interface brief`) give `/32` addresses.
- `address_families` is filled only when the output names the family (IOS `For address family`,
  XR `Address Family`). IOS `vpnv4 all` outputs do not say which VRF a peer is in, so `vrf` is empty.
- ARP rows without a MAC (incomplete) are skipped. `entry_type` of MAC rows is `None` when the
  vendor's type is neither static nor dynamic (for example `blackhole` or EVPN).
- MD-CLI uses the same `show` output as classic SR OS; only the MD-CLI `info` / `state` views are
  not parsed.
