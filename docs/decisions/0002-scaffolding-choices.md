# 2. Scaffolding choices: license, workspace and tooling

- Status: accepted
- Date: 2026-11-27

## Context

Phase 0 sets up a public monorepo that publishes three small libraries plus an application, and must be easy to contribute to from Windows, Linux and macOS.

## Decision

- **License: Apache-2.0** for every package. GPL dependencies are not allowed in the core; a GPL integration may only exist as a separately published, optional plugin.
- **uv workspace** with a virtual root (`pyproject.toml` with `package = false`) and members in `packages/*`. Each package uses a `src/` layout and the **hatchling** build backend, and ships its own `LICENSE` copy and `py.typed` marker.
- **Python 3.12+**; CI matrix Windows/Linux/macOS × 3.12/3.13.
- **Lint/format: ruff** (line length 100). **Types: mypy --strict** on all packages from the start, because it is cheaper to keep strict than to become strict later.
- **Tests: pytest** with `--import-mode=importlib` (several packages share test basenames), **hypothesis** for property tests.
- **Docs: mkdocs-material**, built with `--strict` in CI.
- **Fixtures are byte-exact:** `.gitattributes` marks `fixtures/**` as `-text`, so line endings in captured device output are never normalized.
- **`contexto/` is git-ignored** except its README: it holds the maintainer's private, unsanitized reference material.
- Package versions start at `0.0.1` and are not published until each library reaches its roadmap milestone.

## Consequences

- One `uv sync` sets up everything; `uv build --all-packages` builds every wheel.
- The Web UI framework (Svelte vs HTMX) and the release tooling (release-please or similar) are still open and get their own ADRs in Phase 1.
