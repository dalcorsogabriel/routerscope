# netprompt

> Status: pre-alpha. Part of [routerscope](https://github.com/dalcorsogabriel/routerscope).

Library that detects router prompts (`<R1>`, `[~R1]`, `RP/0/RSP0/CPU0:R1#`, `[admin@R1] >`, `A:R1#`, `user@R1>`), infers vendor and CLI mode (exec/config), strips ANSI and pagination artifacts, and segments a raw terminal log into `(prompt, command, output)` records.
