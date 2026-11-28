# 3. Our own small config tree parser

- Status: accepted
- Date: 2026-11-28

## Context

Step 3.4 of the v0.1 plan needs a hierarchical parser for configurations of seven vendor families: Cisco IOS/IOS-XE and IOS XR, Huawei VRP, IP Infusion OcNOS, Juniper Junos, Nokia SR OS (classic and MD-CLI) and MikroTik RouterOS 7. Every parsed object must carry the exact source lines it came from (`SourceRef`, numbered the way `split_lines` numbers them), so the parser has to report a 1-based line range for every node. The core must stay Apache-2.0 compatible with no GPL, LGPL or AGPL dependency (ADR 0002).

We looked at three candidates. Licenses were read from the package metadata on PyPI (versions current in November 2026).

| Candidate | License | Runtime dependencies | What it does |
|---|---|---|---|
| `hier_config` 4.0 | MIT | `pydantic` | Models a config as a tree to compute remediation (what to add or remove to go from running to intended). Driver-based per platform (IOS, IOS-XR, NX-OS, EOS, Junos, VyOS, ...). |
| `clijson` 0.6 | MIT | none | Turns the output of `show` / `display` **commands** (IOS XR, Junos, Huawei VRP) into JSON. It is a command-output parser, not a configuration tree parser. |
| `ciscoconfparse2` 0.9 | GPL-3.0-only | `hier-config` and about ten more | Query API over IOS-style configs. |

## Decision

**Write our own small tree parser, `routerscope.vendors._tree`, with no new dependency.**

- `ciscoconfparse2` is excluded: GPL-3.0 cannot be in the core, and it would also pull in a long dependency chain. It may still be offered later as a separately published optional plugin, which is outside this decision.
- `clijson` is the wrong tool for this job (command output, not configuration) and does not cover RouterOS, SR OS or OcNOS. It remains a candidate for step 3.5 (state-command parsers), where it will be evaluated on its own merits.
- `hier_config` is MIT and healthy, but it is designed for diff and remediation. It has no Huawei VRP, MikroTik RouterOS, Nokia SR OS or OcNOS driver (some can be written as custom drivers), it does not keep source line numbers on its nodes, and it does not understand brace/`set` forms or RouterOS `key=value` lines. We would have to wrap or fork most of it to get what we need, and `pydantic` is already in the tree only because of our model. Our own diff (step 4.2) works on the neutral model plus the tree, so we do not need its remediation engine.
- The syntaxes involved are small and regular. Four tokenizing strategies cover all seven families, in about 800 lines including docstrings: indentation (IOS, XR, OcNOS, VRP, SR OS classic), braces (Junos, MD-CLI), `set` paths (Junos `display set`, MD-CLI `info flat`) and RouterOS `/export` sections.

### The tree

`ConfigNode` has `text`, `children`, `parent`, `depth`, `line_start` / `line_end` (the whole block, including closers such as `}`, `exit` and `end-policy`), `own_lines` (physical lines owned by the node; for the root, the unclaimed blank and comment lines), `inactive` / `protected` flags, `words`, `path()`, `flat_words`, `walk()`, `find(pattern)` and `child(prefix)`.

`flat_words` (the words of the whole path) is identical for the brace form and the `set` form of the same Junos configuration, so the Junos and MD-CLI extractors read both forms with the same code. Grouping `set` words into the same chunks as the brace form is a keyword-table heuristic; unknown keywords make the rest of the line one leaf, which keeps `flat_words` correct regardless.

### Rules for parsers and extractors

- Parsers never raise: unknown syntax is just more nodes. Hypothesis tests feed arbitrary text to all of them and check that line ranges are within bounds and nested, and that every input line is owned by a node or left to the root as a blank or comment line.
- Extractors are conservative. A value that fails validation (a bad mask, ASN 0, a prefix-list `ge` below the prefix length) drops that object, never the whole file.
- Extractors read the stored, redacted text, as ingestion already provides.

## Consequences

- No new runtime dependency and no license risk. The tree is easy for contributors to extend: a new indentation vendor is a dialect entry plus an extractor.
- We own the maintenance of the syntax edge cases. The golden files and property tests are the safety net, and sanitized real configs (via `contexto/` and `tools/sanitize_fixture.py`) should be added as soon as they are available.
- Known limits: BGP peers whose remote AS comes only from a peer group are resolved for IOS-like, XR and Junos groups but not through every vendor feature (templates, `apply-groups`, Junos `groups`); an XR `prefix-set` mixing IPv4 and IPv6 becomes two `PrefixList` objects with the same name because the model has one address family per list; statements under Junos `inactive:` / `deactivate` are ignored.
- If remediation snippets (a later milestone) need `hier_config`'s algorithms, it can be added then as an optional, isolated integration without touching the tree.
