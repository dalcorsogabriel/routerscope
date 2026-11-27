# Add a vendor in 30 minutes

routerscope finds vendors through Python entry points, so a new vendor is a small
package (or a pull request adding a module) and nothing in the core has to change.

## 1. Copy the template

```console
$ cp -r examples/vendor-plugin-template my-vendor-plugin
$ cd my-vendor-plugin
```

Rename the package folder under `src/`, the project name in `pyproject.toml`, and pick an
id: lowercase letters, digits and underscores (`acme_os`). The entry-point **name must equal
the plugin `id`**:

```toml
[project.entry-points."routerscope.vendors"]
acme_os = "my_vendor_plugin:AcmePlugin"
```

## 2. Implement what the vendor supports

Subclass `BaseVendorPlugin` and override only what you need. Everything else has a safe
default (netprompt detection for built-in vendor ids only, empty parse, no commands, no snippets).

| Method | Purpose |
|---|---|
| `detect(text) -> float` | Confidence 0..1 that the text is from this vendor. Default: netprompt fingerprints, which only know the built-in vendor ids, so a new vendor must implement it. |
| `segment(text)` | Split a session into prompt / command / output. Default: netprompt. |
| `parse_config(text, snapshot) -> ParsedConfig` | Turn a config into neutral objects. |
| `parse_command(command, output, snapshot) -> ParseResult \| None` | Parse one command's output, `None` if unsupported. |
| `readonly_commands() -> Sequence[str]` | Commands a read-only collector may send. |
| `render_snippet(intent) -> Snippet \| None` | Apply and rollback text for a change. |

Every parsed object needs a `ref=SourceRef(snapshot_id, line_start, line_end)` pointing at
the exact lines (1-based, inclusive) it came from, so results can always link back to the
source. Interface names are stored as typed; `Interface` adds a normalized form for you.

```python
from routerscope.model import Device, ParsedConfig, SourceRef
from routerscope.vendors import BaseVendorPlugin


class AcmePlugin(BaseVendorPlugin):
    id = "acme_os"
    name = "Acme OS"

    def detect(self, text: str) -> float:
        return 1.0 if "Acme OS" in text else 0.0

    def parse_config(self, text, snapshot):
        device = None
        for number, line in enumerate(text.splitlines(), start=1):
            if line.startswith("hostname "):
                ref = SourceRef(snapshot_id=snapshot.id, line_start=number, line_end=number)
                device = Device(ref=ref, hostname=line.split()[1])
        return ParsedConfig(snapshot_id=snapshot.id, vendor=self.id, device=device)
```

## 3. Read-only commands are checked

Whatever `readonly_commands()` returns must pass `netcmd_safety.is_collector_safe(cmd, id)`
when the id is a vendor netcmd-safety knows. A plugin that lists anything else (say `reload`)
is rejected at discovery. For vendors netcmd-safety does not know yet, a collector will not
use the commands until the vendor is added there (it fails closed). Add the vendor to
netcmd-safety in the same pull request if you want live collection.

## 4. Add fixtures

Put sample output under `fixtures/<vendor>/`, always passed through
`tools/sanitize_fixture.py` first. Never commit real device output, real addresses or
secrets. Use only documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`, `2001:db8::/32`) and documentation ASNs (64496-64511, 65536-65551).

## 5. Test it

```console
$ pip install -e .
$ python -c "from routerscope.vendors import get; print(get('acme_os'))"
$ pytest
```

Write tests that parse your fixtures and assert on the resulting objects and their `ref`
line ranges.

## How discovery works

* The registry reads the `routerscope.vendors` entry-point group.
* Built-in vendors are registered first. A third-party plugin with an id that is already
  taken is skipped with a warning; to replace a built-in on purpose, set
  `ROUTERSCOPE_VENDOR_OVERRIDE=<id>[,<id>...]`.
* A plugin that fails to import, does not satisfy the `VendorPlugin` protocol or has unsafe
  read-only commands is skipped with a logged warning. It never crashes routerscope.
* `routerscope.vendors.detect_vendor(text)` asks every plugin and returns the best match, or
  `None` on no match or a tie.

## Rules the registry enforces

- `readonly_commands()` must return a list or tuple of strings. It is called **once**, when the
  plugin is registered; the result is frozen, so changing it later has no effect.
- For a vendor id that netcmd-safety knows, every command must be collector-safe in exec mode,
  or the whole plugin is rejected. For other ids the collector never sends any command.
- Line numbers in `SourceRef` follow `routerscope.model.split_lines` (LF, CR and CRLF only).
- `parse_command` returns `None` for commands the plugin does not support and raises for output
  it cannot parse; callers isolate plugin errors.
