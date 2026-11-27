# routerscope

Instant search, time-travel diff and a Winbox-like browser for multi-vendor router configs and CLI sessions. Works with any terminal.

> Maintained by Claude. This repo is **public**: never commit private data, real device output, secrets or **any personal information about the maintainer** (files, commit messages, author names, issues, PRs). The public brief is `docs/PROJECT_BRIEF.md`. The maintainer's original brief, with Phase 0/1 instructions and private context, is `contexto/PROJECT_BRIEF.original.pt-BR.md` (local only, git-ignored) — read both before non-trivial work.

## Goal
Daily-use, open-source tool that makes ISP/network engineers faster (and safer): search everything routers showed and everything configured, semantic diff over time, where-used browser, suggestions with fix/rollback snippets, what-if simulation. Focus on vendors other tools miss (Huawei VRP, MikroTik RouterOS 7, Nokia SR OS, OcNOS) plus Cisco IOS/XE/XR and Junos. Second goal: real adoption and external contributors (natural contribution surface: fixtures, parsers, YAML rules, vendor plugins; small reusable libs others depend on). Never inflate metrics.

## Hard constraints
- **No traffic classification of any kind** (OTT/CDN, content-domain catalogs, flow/NetFlow service identification, embedded-cache mapping). If a feature gets close, stop and ask the maintainer.
- A10 (CGNAT subscriber lookup) is on hold until the maintainer explicitly approves.
- Read-only by default; no write to real devices without opt-in + vendor safe mechanism. Unknown commands fail closed in `netcmd-safety`.
- Terminal-independent: no feature may depend on a specific terminal's plugin/API.
- Local-first, no telemetry, secrets in OS keyring. Apache-2.0; no GPL in the core.
- Every fixture goes through `tools/sanitize_fixture.py` before commit.
- Code, docs, issues and commits in English; READMEs also in PT-BR and ES.

## Stack
Python 3.12+, uv workspace, hatchling, ruff, mypy --strict, pytest + hypothesis, mkdocs-material. Planned: SQLite FTS5, FastAPI, Typer, asyncssh, MCP Python SDK.

## Commands
- Install: `uv sync`
- Test: `uv run pytest`
- Lint/format: `uv run ruff check .` / `uv run ruff format .`
- Types: `uv run mypy --strict packages/netcmd-safety/src packages/netprompt/src packages/netaddr-search/src packages/routerscope/src`
- Docs: `uv run --group docs mkdocs serve`
- Build: `uv build --all-packages`

## Structure
- `packages/netcmd-safety`, `packages/netprompt`, `packages/netaddr-search`: small libs for PyPI (`src/` layout).
- `packages/routerscope`: the app (`capture/`, `vendors/`, `model/`, `storage/`, `services/`, `api/`, `ui/`, `cli/`, `mcp/`).
- `rules/` YAML rules · `fixtures/` sanitized device output (byte-exact, `-text` in `.gitattributes`) · `tests/` cross-package · `benchmarks/` · `tools/`.
- `docs/` mkdocs site; `docs/decisions/` ADRs; `docs/launch/` announcement drafts.
- `contexto/`: maintainer's private reference material, git-ignored except README. Read it, never delete it, never copy it to `fixtures/` unsanitized.

## Workflow (Phase 1+)
Feature branch → small Conventional Commits → PR to `main` (even solo) → CI green → merge; close issues via PR; update CHANGELOG and docs per feature; ADR for significant decisions.

## Decisions
- ADR 0001 (ADRs), ADR 0002 (license, uv workspace, tooling).
- Public visibility is switched by the maintainer by hand (a local safety hook blocks it for Claude).
- Commits use the repo-local identity `dalcorsogabriel` + GitHub noreply e-mail (no real name).

## Current state
Phase 0 done: scaffolding, CI, docs, community files, labels, milestones v0.1–v0.6, backlog epics and good first issues. No product code yet.

## Next steps
1. Phase 1: write `docs/plans/v0.1.md`, then implement in order: netcmd-safety → netprompt → netaddr-search → storage/model → importers → parsers → search/diff/locate → CLI → minimal UI → benchmarks → docs → v0.1.0.
2. Ask the maintainer for real device outputs via `contexto/`; sanitize before committing.
3. ADRs pending: web UI framework (Svelte vs HTMX), release tooling.
