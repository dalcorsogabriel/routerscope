# Importers

Importers turn outside material into snapshots. They only read: nothing here talks to a device. Every importer yields `ImportItem` values (see `routerscope.capture.importers.base`); `routerscope.services.ingest.ingest` redacts and stores them and runs the vendor parsers.

All importers work with **any terminal**: they read log files, pasted text or a folder, never a terminal plugin.

## Terminal logs

`SessionLogImporter(path, format=None, tz=None)` reads one log file and yields

- one `session` item: the whole normalized log;
- one `command_output` item per command that produced output, with hostname and vendor from the prompt, the command text and its output.

Commands with no output (for example `ip route ...` in config mode) stay in the session item only. ANSI escapes, backspaces and pagination prompts (`---- More ----`, `--More--`...) are removed by `netprompt.normalize`.

`Source` is `Source(kind="session_log", uri=<path>, importer=<format id>)`.

### Formats

| Id | What it is | Detected by |
|---|---|---|
| `securecrt` | SecureCRT custom log, lines start with `[2026-01-05 10:22:01] ` | most of the first 30 lines have that prefix |
| `iso` | lines start with `2026-01-05T10:22:01.123Z ` (zone optional) | same, ISO prefix |
| `mobaxterm` | MobaXterm with `[10:22:01] ` prefixes (time only) | same, time prefix |
| `putty` | PuTTY log, header `=~=~=~= PuTTY log 2026.01.05 10:22:01 =~=~=~=` | first line is the header |
| `script` | util-linux `script`, `Script started on 2026-01-05 10:22:01+00:00 [...]` | first line is that header |
| `plain` | no timestamps: Windows Terminal, Tabby, iTerm, Termius, MobaXterm or SecureCRT plain exports | everything else |

Force one with `format="securecrt"`. `windows_terminal`, `tabby`, `iterm` and `termius` are aliases of `plain`.

### Timestamps

`captured_at` of each command, first match wins:

1. the timestamp on the command's prompt line, or on the closest timestamped line above it;
2. the header timestamp (PuTTY, `script`);
3. the file modification time.

Time-only stamps (MobaXterm) take their date from the header, else from the modification time, and move to the next day when the clock passes midnight. Stamps without a zone are read in `tz` (default: the machine's local timezone); `captured_at` is never naive. The session item uses the same order with the first stamp of the log.

The session item's content is the normalized log **without** the line timestamps and without header/footer lines (PuTTY header, `Script started` / `Script done`), so the same session captured by two terminals has the same text.

### Encoding

UTF-8, UTF-8 with BOM, UTF-16 with BOM and UTF-16 without BOM (NUL bytes between characters; what Windows PowerShell 5.1 writes with `>` or `Tee-Object`) are detected. Anything else is read as UTF-8 and undecodable bytes become U+FFFD, with a logged warning.

## Paste

`PasteImporter(text, hostname=None, vendor=None, kind=None, command=None, captured_at=None)` covers any terminal where you can copy text (Termius, a web console, an editor).

1. Text with device prompts is handled like a terminal log (`session` item plus one item per command, timestamps auto-detected). `hostname` and `vendor` override what was detected.
2. Without prompts, text that looks like a configuration becomes a `config` item. It looks like one when at least three lines are configuration statements (`hostname`, `interface`, `router bgp`, `set system ...`, `/interface ...`, `system {`, `!` separators...), or one such line plus a vendor recognised by the plugin registry. The hostname comes from the config's own `hostname` / `sysname` / `host-name` / `/system identity` statement when not given.
3. Anything else is stored as `command_output` and **requires** `command`; otherwise `ImportError_` explains why.

Use `kind=` to skip the guessing. `captured_at` defaults to now. `Source(kind="paste", uri="paste", importer="paste")`.

## Drop folder

`DropFolder(path, min_age=0.0)` imports the files that appear in a folder (not its subfolders). Each file is a terminal log if it has prompts (format auto-detected; `Source.importer` is the format id), else a configuration if it looks like one (`captured_at` is the modification time). Other files are recorded as skipped and not retried until they change. `Source(kind="drop_folder", uri=<file path>)`.

```python
folder = DropFolder("~/routerscope-drop")
ingest(store, folder.items())          # new or changed files, once
folder.watch(lambda items: ingest(store, items), interval=2.0, stop_event=stop)
```

- `scan()` returns the items of new or changed files; `items()` is the lazy version; `poll(callback)` is one scan handing each file's items to a callback; `watch(callback, interval=2.0, stop_event=None)` polls until the event is set (stdlib only, no file-watching dependency).
- State lives in `.routerscope-drop.json` inside the folder (name, size, modification time, SHA-256), written atomically. A file is imported again only when its content changes; touching it is not enough. A file is marked done only after its items were consumed or the callback returned, so a failure is retried at the next scan.
- Files modified less than `min_age` seconds ago are skipped, which avoids reading a log a terminal is still writing. Locked files are retried at the next scan.
- Hidden files, the state file and `*.tmp` / `*.part` files are ignored.

## Known gaps

- A file whose size and modification time are both unchanged is assumed unchanged (the SHA-256 is only compared when one of them differs).
- Old-style `script` headers (`Script started on Mon Jan  5 ...`) are removed but carry no timestamp.
- Logs from terminals that put the date on a separate line, or use `[%H:%M:%S.%f]` style stamps, are treated as `plain` unless the format is forced to one with a matching prefix.
- `show running-config` style outputs are stored as `command_output`, not `config`.
