# Contributing to routerscope

Thanks for helping! routerscope is pre-alpha, so this is the best time to shape it.
Issues and discussions in English, Portuguese or Spanish are welcome; code, docs and commit messages are in English.

## Four short paths

You do not need to know the whole codebase. Pick one:

1. **Add a fixture** (10 minutes, no Python). Capture the output of one command on your vendor/version, sanitize it, open a PR to `fixtures/<vendor>/<version>/<command-slug>/input.raw`. See [fixtures/README.md](fixtures/README.md).
2. **Add a command parser** (1 to 2 hours). Write the expected result for a fixture (`expected.yml`), then the parser that produces it. Golden tests run automatically.
3. **Add a suggestion rule** (30 minutes, YAML). A rule matches on the normalized model and carries the fix and rollback snippets per vendor. Format lands with v0.4; issues labeled `area:rules`.
4. **Add a vendor** ("Add a vendor in 30 minutes" guide ships with v0.1). A vendor plugin implements `detect()`, `segment()`, `parse_config()`, `parse_command()`, `readonly_commands()` and `render_snippet()`.

Look for [`good first issue`](https://github.com/dalcorsogabriel/routerscope/issues?q=is%3Aopen+label%3A%22good+first+issue%22) and the `vendor:*` labels.

## Golden rules

- **Never commit unsanitized data.** No real public IPs, hostnames, customer names, third-party ASNs, passwords, keys or SNMP communities. Use `tools/sanitize_fixture.py` (coming in v0.1); CI rejects fixtures with secret patterns.
- **Read means read.** No command that can change device state may ever be classified as `read` in `netcmd-safety`. When in doubt, classify it as `config`. Every new classification needs a test case.
- **No traffic classification.** The project does not accept features that classify OTT/CDN traffic, catalog content domains, analyze flows/NetFlow to identify services, or map embedded caches.
- **No telemetry, no hidden outbound calls.** External lookups (CVE feeds, PeeringDB, RPKI) are opt-in and documented.
- **Core dependencies must be Apache-2.0 compatible.** No GPL in the core.

## Development setup

Requirements: Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/dalcorsogabriel/routerscope
cd routerscope
uv sync                      # creates .venv with every package in editable mode
uv run pytest                # tests
uv run ruff check .          # lint
uv run ruff format .         # format
uv run mypy --strict packages/*/src
uv run --group docs mkdocs serve   # docs at http://127.0.0.1:8000
```

## Pull requests

- One topic per PR; link the issue (`Closes #123`).
- [Conventional Commits](https://www.conventionalcommits.org/) for titles: `feat(vrp): parse display bgp peer`, `fix(netprompt): ...`, `docs: ...`, `test: ...`.
- CI must be green (lint, types, tests on Windows/Linux/macOS).
- Update `CHANGELOG.md` under `[Unreleased]` for user-visible changes.
- Significant design decisions get a short ADR in `docs/decisions/`.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
