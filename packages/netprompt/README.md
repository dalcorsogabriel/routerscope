# netprompt

> **Experimental.** Early-stage library, part of [routerscope](https://github.com/dalcorsogabriel/routerscope). The API may change without notice before 1.0; pin the exact version if you depend on it.

Library that detects router prompts (`<R1>`, `[~R1]`, `RP/0/RSP0/CPU0:R1#`, `[admin@R1] >`, `A:R1#`, `user@R1>`), infers vendor and CLI mode (exec/config), strips ANSI and pagination artifacts, and segments a raw terminal log into `(prompt, command, output)` records.

## Usage

```python
from netprompt import detect_prompt, detect_vendor, normalize, segment

detect_prompt("[~PE1-bgp]commit", known_hostnames={"PE1"})
# -> (Prompt(hostname="PE1", vendor="huawei_vrp", mode=Mode.CONFIG, context="bgp",
#            flags=frozenset({"two_stage"}), ...), "commit")

detect_vendor("Cisco IOS XR Software, Version 7.5.2")  # "cisco_xr"

for seg in segment(open("session.log").read()):
    print(seg.device, seg.prompt.vendor, seg.prompt.mode, seg.command, len(seg.output))
```

- `normalize(text)` strips ANSI escapes, applies backspaces and carriage-return overwrites, converts CRLF to LF and removes pagination prompts (`---- More ----`, ` --More-- `, `---(more 35%)---`, RouterOS and SR OS pager prompts). Everything else is byte-identical.
- `detect_prompt(line)` returns `(Prompt, typed_command)` for a line that starts with a prompt at column 0, else `None`. `Prompt.vendor` is `None` when ambiguous (for example `R1#` is Cisco IOS or OcNOS); see `Prompt.candidates`.
- `is_prompt_banner(line)` recognises Junos `[edit]` / `{master:0}` and Nokia MD-CLI context lines.
- `segment(text, vendor=None)` splits a whole session into `Segment(prompt, command, output, line, device)`, resolving ambiguous hostnames and vendors from the rest of the session.

Supported vendors: `cisco_ios` (IOS/IOS-XE), `cisco_xr`, `huawei_vrp`, `mikrotik_ros7`, `juniper_junos`, `nokia_sros` (classic and MD-CLI), `ipinfusion_ocnos`. Standard library only.

## Known limitations

- Ambiguous Huawei prompts (`[R1-bgp]`) stay unresolved unless the hostname appears elsewhere in the session or is passed via `known_hostnames`.
- Cisco IOS and OcNOS share prompt syntax; the vendor is inferred only from text fingerprints or the `vendor` argument.
- Prompts must start at column 0 and (Cisco-style) hostnames must start with a letter or digit.
