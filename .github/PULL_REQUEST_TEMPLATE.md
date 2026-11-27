## What does this PR do?

<!-- One or two sentences. Link the issue: "Closes #123". -->

## Type
- [ ] Fixture (sanitized device output)
- [ ] Parser / segmenter
- [ ] Suggestion rule (YAML)
- [ ] New vendor
- [ ] Core / capture / search / UI
- [ ] Docs

## Checklist
- [ ] Tests added or updated (`uv run pytest`)
- [ ] `uv run ruff check .` and `uv run ruff format --check .` pass
- [ ] Every fixture went through `tools/sanitize_fixture.py`: **no real public IPs, hostnames or secrets**
- [ ] No command that can change device state is classified as `read`
- [ ] `CHANGELOG.md` updated under `[Unreleased]` (if user-visible)
