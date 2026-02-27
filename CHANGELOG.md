# Changelog

## 0.4.1 - 2026-02-27

### Hotfix

- Fixed CI and tagged-release build failures caused by static web asset compression collisions (`ApplyCompressionNegotiation` duplicate-key error).
- Disabled static web asset compression at project level via `StaticWebAssetsCompressionEnabled=false`.
- Hardened tag-build workflow to pass `-p:StaticWebAssetsCompressionEnabled=false` for both build and publish steps.

## 0.4.0 - 2026-02-27

### DevOps and Deployment

- Added GitHub Actions tag-build workflow (`.github/workflows/tag-build.yml`) that runs on new `v*` tags and uploads published web artifacts
- Added Docker support (`Dockerfile`, `docker-compose.yml`, `.dockerignore`)
- Updated Docker runtime to run as non-root user (`10001:10001`)
- Added README workflow badge for tag-build status
- Added environment-variable-first configuration support for Docker/Azure App Service deployment, including App Service connection-string prefix fallbacks
- Added `scripts/generate-env-from-appsettings.ps1` to generate `.env` or PowerShell env exports from `appsettings*.json`

### Documentation

- Updated README, build/install, and local deployment docs with CI, container, rootless runtime, and environment-variable guidance
- Updated release notes for `v0.4.0`

## 0.3.0 - 2026-02-27

### UI / UX

- Refined `My Projects` journal listing into a flex-based, single-line row layout with improved readability
- Added dedicated column headers for the custom project entry list and normalized row typography/alignment
- Added project entry details page (`/projects/entry/{recordId}`) with Back navigation to the selected project context
- Added date sort control (`Newest first` / `Oldest first`) for project journal entries
- Added `Add Journal Entry` action in `My Projects` and automatic post-create redirect from `/journal` back to `/projects?projectId=...`
- Removed project-entry checksum display from `My Projects` entry rows per current UI behavior
- Updated `Audit Search` results to move checksum and checksum-validation actions into a dedicated `Integrity` column
- Added alternating row backgrounds (zebra striping) across table/list views to improve scanability

### Documentation

- Updated README capability list and usage notes for the new journal browsing flow
- Updated install/build/local deployment docs with current page behavior and navigation
- Updated specification UI requirements to document sortable project entries, single-entry detail view, integrity column layout, and alternating row styling
- Added release notes for `0.3.0`

## 0.2.0 - 2026-02-26

### Security

- Added antiforgery protection to local login and converted logout to POST-only with CSRF protection
- Hardened OIDC user resolution to bind external identities by `iss` + `sub` and reject username-collision privilege inheritance
- Added regression and integration tests for OIDC identity binding and CSRF-protected auth endpoints

### Reliability and Performance

- Reduced sync-over-async deadlock risk in auth/current-user flows and moved major Blazor auth/user operations to async paths
- Fixed local principal username normalization regression for Identity users (`admin` vs email fallback)
- Added optional buffered file logging (`Logging:File:*`) for troubleshooting with lower request-path I/O overhead

### Persistence and Compatibility

- Persisted external OIDC identity fields (`ExternalIssuer`, `ExternalSubject`) in app-user storage
- Added best-effort schema upgrades for existing SQLite / EF-backed app-user tables to support external identity columns

### UI / UX

- Compacted top header layout and simplified current-user display

### Testing and Repo Layout

- Moved test project to repository root (`SecureJournal.Tests/`)
- Added CSRF integration tests and expanded OIDC security coverage

### Documentation

- Updated README, build, install, local deployment, and specification docs for 0.2.0 behavior and configuration
