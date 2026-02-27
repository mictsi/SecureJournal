# Changelog

## 0.4.5 - 2026-02-27

### Reliability and Error Handling

- Hardened local auth endpoints (`/auth/local-login`, `/auth/logout`) to gracefully handle antiforgery validation failures and return user-safe redirects instead of surfacing server errors.
- Added startup critical logging for production database initialization failures to improve diagnosis during boot failures.
- Hardened OIDC setup and runtime behavior:
  - fail-fast validation for required OIDC configuration when `Authentication:EnableOidc=true`
  - support for `Authentication:Oidc:RequireHttpsMetadata` and `SignedOutCallbackPath`
  - explicit OIDC remote/authentication failure handlers with safe redirects and structured logging
- Improved SQLite resiliency under contention by adding `busy_timeout` plus transient connection open retries for lock/busy scenarios.
- Hardened reconnect modal JavaScript against missing DOM elements and unavailable `window.Blazor` runtime methods.

## 0.4.4 - 2026-02-27

### DevOps and Deployment

- Added `scripts/provision-azure.ps1` to provision Azure dependencies for App Service deployments, including:
  - resource group, storage/table, key vault, App Service plan/web app
  - optional Entra app registrations for app access + OIDC
  - OIDC app `groupMembershipClaims` configuration for group claims in ID tokens
- Added `scripts/deploy-appservice.ps1` to publish and deploy `SecureJournal.Web` to Azure App Service with current `Authentication:*`, `BootstrapAdmin:*`, `Security:*`, and `Logging:*` settings.
- Updated GitHub `Tag Build` workflow to include Docker image build validation (`docker build`) on tagged releases.

### Documentation

- Updated README and deployment/build/install docs to cover Azure provisioning/deployment scripts and Entra ID token group-claim configuration.

## 0.4.2 - 2026-02-27

### Hotfix

- Restored static web asset compression (`CompressionEnabled=true`) after removing duplicate checked-in Blazor runtime files under `wwwroot/_framework`.
- Updated tag-build workflow restore/build/test/publish steps to run cleanly with compression enabled.
- Removed local startup-script `_framework` sync behavior that could recreate static asset collisions.
- Added configuration switches for logging behavior:
  - `Logging:Console:Enabled`
  - `Logging:SqlQueries:Enabled`
- Fixed left navigation theme behavior so the sidebar and nav links switch correctly in light mode.

## 0.4.1 - 2026-02-27

### Hotfix

- Fixed CI and tagged-release build failures caused by static web asset compression collisions (`ApplyCompressionNegotiation` duplicate-key error).
- Enabled static web asset compression at project level (`CompressionEnabled=true`).
- Updated tag-build workflow to build/publish with compression enabled.

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
