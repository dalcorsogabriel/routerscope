# Diff over time

Status: experimental. Code: `routerscope.services.diff`.

Three layers, all read-only and local:

1. **Semantic diff** (`diff_objects`): parsed objects matched by *natural key*, with field-level
   `old -> new`. Ignores counters, uptime and line numbers.
2. **Hierarchical config diff** (`diff_config`): block-aware, shows every change under its parent
   block, with line numbers of both sides.
3. **History service** (`diff_snapshots`, `diff_device`, `changes`): picks the snapshots from the
   store and returns both of the above (plus a plain line diff for command output and sessions).

```python
from routerscope.services.diff import diff_device, changes

result = diff_device(store, "PE1")            # previous version vs latest
print(result.render_text())                    # unified-style, parents as context
for change in result.semantic.changes:         # None if no parsed data is stored
    print(change.label, [(f.field, f.old, f.new) for f in change.fields])

for step in changes(store, "PE1"):             # timeline, noise-only pairs skipped
    print(step.old.captured_at, "->", step.new.captured_at, step.text.stats)
```

Config text output looks like this (`-`/`+` lines, parents as context, indentation by depth):

```
--- 2026-11-01T08:00:00Z 149a7ab6675e
+++ 2026-11-01T08:10:00Z cd0f974e4ef8
 interface GigabitEthernet0/0/1
-  description uplink
+  description uplink to PE1
```

## History selection

| Call | Pair |
|---|---|
| `diff_device(store, host)` | version before the latest (different content) vs latest |
| `at=T` | version in effect at `T` vs the one before it |
| `until=T` | as default, ignoring captures after `T` |
| `since=T` | version in effect at `T` (or the earliest known) vs latest |
| `command="show ..."` | same, for one command's output |

It returns `None` when there are not two different versions. Re-observing identical content
is not a change. `changes()` walks consecutive versions and skips pairs where only noise
changed (`include_empty=True` keeps them).

## Semantic diff

Matching by `(kind, key)`; objects only on one side are added/removed, others are compared field by
field. `ref` (lines, snapshot) is never compared. Repeated keys are paired in order (`#2` suffix).
Tuple fields listed as *unordered* compare as sets. Kinds with entries (prefix lists, ACLs,
policies, IGP interfaces) also get an entry-level diff; a reorder of entries with no sequence
number is reported as `<field>_order`.

| Kind | Natural key | Entries keyed by | Volatile (ignored by default) | Unordered |
|---|---|---|---|---|
| `device`, `version` | singleton | | `version.uptime` | |
| `interface` | normalized name | | | |
| `ip_address` | (interface, address, vrf) | | | |
| `vrf` | name | | | import/export targets, interfaces |
| `bgp_peer` | (vrf, peer) | | none: `state` changes are reported | address families |
| `policy` | name | seq, else term name, else position | | |
| `prefix_list` | (name, afi) | seq, else action+prefix+ge/le | | |
| `acl` | (name, afi) | seq, else raw text | | |
| `static_route` | (vrf, prefix, next hop, interface, blackhole) | | | |
| `igp` | (protocol, process, vrf) | interface name | | areas, levels |
| `lag` | normalized name | | | members |
| `vlan` | VLAN id | | | interfaces |
| `transceiver` | normalized interface | | rx/tx power, temperature | |
| `arp_entry` | (ip, vrf) | | age, expires, uptime | |
| `mac_entry` | (mac, vlan) | | age, expires, uptime | |

`include_volatile=True` compares the volatile fields too. Adding a kind is one line:

```python
from routerscope.services.diff import register_kind
register_kind("arp_entry", ("ip", "vrf"), volatile=("age",))
```

Unregistered kinds still work: the key is `name`/`id` (+ `vrf`) when present, otherwise the whole
content (any change then shows as removed + added); names like `uptime`, `age`, `last_flap`
are volatile. A key naming a missing field falls back to the same generic key.

## Hierarchical config diff

* Parsed with the vendor's tree parser (`routerscope.vendors._tree`). Siblings are matched by
  their text, **ignoring order**. Changing a statement shows as `-` old + `+` new under the same
  parent; a block present on one side only is shown whole.
* Comments are not statements, so `! Last configuration change`, `## Last commit:` and RouterOS
  `# <date> by RouterOS` never produce a diff (comment-only edits are invisible by design).
* Whitespace inside a statement is collapsed (except inside quotes); `show_whitespace=True`
  compares it literally. Indentation defines structure and is not compared as text.
* `inactive:` / `protect:` flags (Junos) are part of the statement.
* Junos `set` vs brace (and MD-CLI flat vs `info`) on different sides are compared by flat paths
  (`format` reports `brace->flat` / `set->flat`; quotes are not preserved in this mode).
* Never raises on arbitrary text; unknown vendors are parsed as indented IOS-like text.

### Ordered sections

Order is ignored everywhere except these (a reorder there is a removed + added pair):

| Vendor | Order-sensitive |
|---|---|
| IOS / OcNOS | `access-list N` lines, `ip(v6) prefix-list` / `as-path access-list` / `community-list` lines without `seq`, entries of `ip(v6)/mac access-list` blocks without a leading number, children of `policy-map` |
| XR | whole body of `route-policy`, entries of `ipv4/ipv6 access-list` without a number, `policy-map` |
| VRP | `rule permit ...` (no number) inside `acl`; `rule 5 ...` is unordered |
| Junos | `term`s inside `policy-statement` and firewall `filter`; the whole `then` block |
| SR OS | none (entries carry numbers/names) |
| RouterOS | `/ip(v6) firewall filter,nat,mangle,raw`, `/routing filter`, `/queue simple`, `/interface bridge filter,nat` |

### Volatile lines

Unindented lines matching these (`re.fullmatch`) are blanked before parsing (line numbers are
kept); the diff reports how many were ignored. Disable with `ignore_volatile_lines=False`, add
your own with `extra_volatile_lines`.

| Vendor | Patterns |
|---|---|
| IOS / OcNOS | `Building configuration...`, `Current configuration : N bytes`, `Using N out of M bytes`, `Last configuration change at ...`, `NVRAM config last updated at ...`, `ntp clock-period N` |
| XR | `Building configuration...`, the `Mon Nov  2 10:00:00.123 UTC` timestamp line, `!! Last configuration change at ...` |
| VRP | `!Software Version ...`, `!Last configuration was updated\|saved at ...` |
| Junos | `## Last commit:` / `## Last changed:` |
| SR OS | `# Generated\|Finished\|Last modified ...` |
| RouterOS | `# ... by RouterOS ...`, `# software id\|model\|serial number = ...` |

## Known gaps

* Renaming a block header (`router bgp 64496` to `64497`) shows as the whole block removed and added.
* Closers (`exit`, `end-policy`, `}`) are not shown.
* No move detection; a moved statement in an ordered section is remove + add.
* Semantic diff of command output needs a vendor `parse_command`; until then command output only
  gets the line diff.
