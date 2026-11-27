# Classification test cases

One file per vendor (`<vendor-id>.txt`). Each non-empty, non-comment line is:

```
<verdict> [@<mode>] <command>
```

- `verdict`: `read`, `session`, `unknown`, `config` or `destructive`.
- `mode` (optional): `@exec` or `@config`. Without it the case is classified with an unknown mode.
- `command`: the rest of the line, exactly as typed on the device.

Example:

```
read                show ip bgp summary
read        @config do show running-config
destructive         clear ip bgp *
```

Adding a case needs no Python: add a line and run `uv run pytest packages/netcmd-safety`.
**A write command must never be added as `read` or `session`.** If you are unsure, use `unknown`.
