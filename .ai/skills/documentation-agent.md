# Skill: Documentation Agent (agent-run)

## Objective
Maintain accurate repository documentation by:
- identifying docs gaps from recent changes (diff + commit history)
- updating `README.md` and `/docs` content
- regenerating API/reference docs when the repo supports it
- validating docs with available linters/link checks/builds
- committing changes to a dedicated branch (no PR)

## Inputs (agent must obtain or infer)
- `default_branch` (commonly `main`)
- `scope` (`docs-only` / `docs+minor-code` / `full-docs-pass`)
- `commit_range` (preferred) e.g., `origin/main...HEAD` (merge-base diff) or `origin/main..HEAD`
- optional: explicit `changed_files` list
- docs toolchain (auto-detect): `mkdocs`, `docusaurus`, `docfx`, `sphinx`, or plain Markdown
- docs locations: `README.md`, `/docs`, and any in-repo docs site config
- branch naming convention (if any)

## Required tools
- `git`
- repo-specific build tools as needed (language/toolchain dependent)

## Guardrails
- Do not modify unrelated code files when producing docs commits.
- Do not create tags, releases, or version bumps.
- Do not commit generated artifacts unless the repo policy already does so (follow existing patterns).
- Do not push to `default_branch` directly; use a dedicated branch.

## Definition of Done
- Docs updated for user-visible changes (usage, configuration, behavior, API, migrations).
- Validation completed using available tools (best-effort based on repo configuration):
  - markdown lint (if configured)
  - link checks (if configured)
  - docs build (if a docs site exists)
- A remote branch is pushed containing:
  - doc updates
  - a commit message describing the scope
  - a local validation summary recorded in the agent output

---

## Procedure

### 0) Initialize & select scope
1. Fetch latest refs: `git fetch --prune origin`
2. Determine `default_branch` (prefer `origin/HEAD`, fallback `main`).
3. Determine `commit_range`:
   - If provided, use it.
   - Else use `{default_branch}...HEAD` (merge-base) to capture branch changes reliably.

### 1) Assess change set & documentation gaps
1. Compute changed files:
   - `git diff --name-only {commit_range}`
2. Inspect context:
   - `git log --oneline {commit_range}`
3. Classify doc impacts:
   - public APIs, config keys, CLI flags, deployment steps, breaking changes, new features, deprecations.

### 2) Discover canonical docs locations
Follow existing repo conventions:
- `README.md`
- `docs/` or `doc/`
- top-level docs (`INSTALL*.md`, `BUILD*.md`, `CONTRIBUTING.md`, `SECURITY.md`, `RELEASE_NOTES.md`)
- docs site configs (`mkdocs.yml`, `docusaurus.config.*`, `docfx.json`, `conf.py`)
- agent/skill docs (`.ai/skills/*.md`) if they are part of documented workflows

### 3) Update quickstart and upgrade guidance
1. If installation/usage changed, update `README.md` quickstart and examples.
2. If breaking changes exist, create/update `docs/UPGRADING.md` (or repo equivalent) with:
   - what changed
   - who is impacted
   - step-by-step migration
   - before/after examples

### 4) API/reference docs (conditional)
1. Detect doc generation setup by presence of config/scripts:
   - `docfx.json` => `docfx build`
   - `mkdocs.yml` => `mkdocs build`
   - `docs/conf.py` => `make -C docs html` (or repo-defined target)
2. If no generator exists, do not invent one; update Markdown reference pages instead.
3. If generation exists:
   - run the repo’s established generation command(s)
   - commit outputs only if the repo already tracks them (verify via `.gitignore` and existing history)

### 5) Validate docs (best-effort)
Run only what is available/configured in the repo:
1. Markdown lint (if present): `markdownlint` / `remark` / configured scripts.
2. Link checks (if present): `lychee`, `markdown-link-check`, or configured scripts.
3. Build docs site (if configured): `mkdocs build`, `docfx build`, `npm run docs:build`, etc.
Record commands + exit codes for agent output.

### 6) Create branch, commit, and push (no PR)
1. Create branch: `docs/{short-topic}-{YYYYMMDD}` (or repo convention)
2. Stage only relevant files (avoid `git add -A` unless scope explicitly allows):
   - `git add README.md docs/ ...`
3. Commit:
   - `git commit -m "docs: {short-summary}"`
4. Push:
   - `git push -u origin HEAD`

---

## Error handling
- If docs build fails:
  - do not claim Definition of Done met
  - include failing command + relevant log excerpt in agent output
- If link-checker is noisy:
  - re-run scoped to docs paths/changed files where supported
  - document filters applied and remaining high-confidence issues

## Agent output (must report)
- `branch` name and pushed remote ref
- files changed (with 1-line rationale each)
- validation commands run + exit status
- lint/link issues summary
- deviations from guardrails (explicit, with reason)

---

## Example quick-run checklist
1. `git fetch --prune origin`
2. `git checkout -b docs/update-readme-20260301`
3. Edit `README.md` and relevant `docs/*.md`
4. Run: `mkdocs build` OR repo-equivalent
5. `git add README.md docs/`
6. `git commit -m "docs: update build & install instructions"`
7. `git push -u origin HEAD`