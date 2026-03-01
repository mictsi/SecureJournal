# Skill: Publish a new version to GitHub (agent-run)

## Objective
Ship a new version safely and repeatably by:
- updating changelog, release notes, and docs
- bumping the version (SemVer)
- tagging the release
- pushing to GitHub
- creating a GitHub Release

## Inputs (agent must obtain or infer)
- `default_branch` (commonly `main` or `master`)
- `new_version` (SemVer, e.g., `1.4.2`)
- `tag` = `v{new_version}`
- Release scope (major/minor/patch) and any breaking changes
- Repo-specific version file locations (e.g., `package.json`, `.csproj`, `pyproject.toml`, etc.)
- Changelog + release notes conventions (file names / format)
- Docs locations (e.g., `README.md`, `/docs`, site generator)

## Required tools
- `git`
- GitHub CLI: `gh` authenticated with repo access
- Project test/build tooling as applicable

## Guardrails
- Do not release from a dirty working tree.
- Do not create tags on commits that aren’t on `default_branch`.
- Prefer fast-forward only when syncing (`git pull --ff-only`).
- Fail the skill if tests/build fail (unless explicitly instructed otherwise).
- Use annotated tags (`git tag -a`).
- Never overwrite an existing remote tag.

## Definition of Done
- Version bumped in canonical location(s)
- `CHANGELOG.md` updated for `vX.Y.Z`
- Release notes prepared (file or generated) and match changelog
- Docs updated to reflect new behavior (at minimum: README and/or docs pages impacted)
- Release commit merged into `default_branch`
- Annotated tag `vX.Y.Z` points to the release commit
- Tag + branch pushed to origin
- GitHub Release created for `vX.Y.Z`
- CI checks green (or clearly reported if pending)

---

## Procedure

### 1) Validate repo state
1. Fetch latest refs: `git fetch --prune origin`
2. Checkout and update default branch:
   - `git checkout {default_branch}`
   - `git pull --ff-only origin {default_branch}`
3. Ensure clean working tree:
   - `git status --porcelain` must be empty
4. Verify no existing tag conflicts:
   - `git tag -l v{new_version}` must be empty
   - `git ls-remote --tags origin v{new_version}` must return nothing

### 2) Determine change set since last release
1. Identify latest tag:
   - `git describe --tags --abbrev=0` (handle “no tags yet” case)
2. Collect commits/PRs since last tag:
   - `git log {last_tag}..HEAD --oneline`
3. Summarize changes into categories:
   - Breaking changes
   - Added
   - Changed
   - Fixed
   - Security
   - Deprecated / Removed

### 3) Update version
1. Locate version declarations (repo-specific). Common cases:
   - Node: `package.json`
   - Python: `pyproject.toml`, `setup.cfg`
   - .NET: `.csproj`, `Directory.Build.props`
   - Go: module tags only (often no file bump)
2. Update to `{new_version}` consistently.
3. Ensure any internal references also updated (e.g., docs badges, examples).

### 4) Update changelog (before release)
1. Update `CHANGELOG.md` (or repo equivalent):
   - Add section for `{tag}` with date (ISO `YYYY-MM-DD`)
   - Populate from the categorized change set
   - Include breaking-change callouts at top
2. Ensure format consistency (Keep a Changelog if used).

### 5) Update release notes (before release)
Choose the repo’s convention (agent must follow existing pattern):
- If `RELEASE_NOTES.md` exists: append a `{tag}` section mirroring changelog.
- If `.github/releases/` is used: create a file like `.github/releases/{tag}.md`.
- If notes are generated: prepare a curated notes file anyway to avoid noisy output.

Minimum release notes content:
- One-paragraph summary
- Highlights (2–5 bullets)
- Breaking changes section (if any) with migration guidance
- Full change list link or bullet list

### 6) Update docs (before release)
Update documentation impacted by the changes:
- `README.md` (quickstart, usage, flags/options, examples)
- `/docs` pages and/or docs site content
- API docs if maintained in-repo
- Upgrade/migration guide if breaking changes:
  - `docs/migration.md` or `UPGRADING.md` (if present/appropriate)

Docs checks:
- Examples compile/run (where reasonable)
- Version references updated (badges, snippets)
- Links not broken (best-effort)

### 7) Run quality gates
1. Run test suite/build/lint as appropriate for the repo.
2. If failures occur:
   - Stop and report failures with logs/commands.
   - Do not commit/tag.

### 8) Create the release commit
1. Stage changes: `git add -A`
2. Commit message:
   - `chore(release): v{new_version}`
3. Confirm commit includes only release-related deltas (no unrelated files).

### 9) Tag the release
1. Create annotated tag:
   - `git tag -a v{new_version} -m "v{new_version}"`
2. Verify tag points to HEAD:
   - `git show v{new_version} --no-patch`

### 10) Push branch and tag
1. Push default branch:
   - `git push origin {default_branch}`
2. Push tag:
   - `git push origin v{new_version}`

### 11) Create GitHub Release
1. Prefer curated notes over auto-generated if available.
2. Create release:
   - `gh release create v{new_version} --title "v{new_version}" --notes-file {notes_file}`
   - If no notes file exists: `--generate-notes` (fallback)
3. Attach artifacts if produced (optional):
   - `gh release upload v{new_version} path/to/artifact.zip`

### 12) Verify
- Tag exists on GitHub and points to the release commit
- Release page exists with correct notes
- CI checks pass for the release commit/tag (or status captured)

---

## Error handling / rollback

### If commit created but tag not pushed
- Fix files and amend commit if needed:
  - `git commit --amend`
- Recreate tag:
  - `git tag -d v{new_version}`
  - `git tag -a v{new_version} -m "v{new_version}"`

### If tag pushed but wrong
**High risk** — coordinate with maintainers.
- Delete remote tag:
  - `git push origin :refs/tags/v{new_version}`
- Delete local tag:
  - `git tag -d v{new_version}`
- Fix commit, recreate tag, push again.

### If GitHub Release created with wrong notes
- Edit release notes via GitHub UI or:
  - `gh release edit v{new_version} --notes-file {corrected_notes_file}`

---

## Agent output (must report)
- `new_version`, `tag`, `default_branch`
- Files changed for version/changelog/release notes/docs
- Tests/build commands executed and result
- Commit SHA and tag reference
- GitHub Release URL (from `gh release view v{new_version} --json url -q .url`)
- Any deviations from guardrails (with rationale)