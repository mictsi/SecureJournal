# Secure Journal

[![Tag Build](https://github.com/mictsi/SecureJournal/actions/workflows/tag-build.yml/badge.svg)](https://github.com/mictsi/SecureJournal/actions/workflows/tag-build.yml)

Secure Journal is a role-based project event journaling application for a single organization with multiple projects.

It is designed for:

- `Administrators` who manage users, groups, projects, and audit/export workflows
- `Project Users` who create and read append-only journal entries in projects they can access
- `Auditors` who search/export audit logs and review linked journal evidence without direct journal browsing

## What Users Can Do

- Sign in with local accounts (ASP.NET Identity cookie auth)
- Sign in with OIDC (when enabled by configuration)
- View `My Projects` and browse journal entries per project
- Search project journal entries by partial text in `Subject`, `Description`, and `Notes`
- Sort project journal entries by date (`Newest first` / `Oldest first`)
- Open a dedicated journal entry details page from `My Projects` and return to the selected project context
- Create append-only journal entries (`Action`, `Subject`, `Description`, `Notes`)
- Soft-delete journal entries (preserved for admin visibility and audit evidence)
- Search audit logs with filters (date/user/project/action/entity/outcome + field-specific contains)
- Validate audit checksums per audit row
- Export journal/audit data as `CSV` or `JSON` (with automatic download)

## Security/Behavior Highlights

- Journal fields are encrypted before SQLite storage
- Audit details are plaintext with SHA-256 checksums
- Per-browser authenticated sessions (cookie expiration configurable; default 8 hours)
- Password hashing + configurable password complexity policy
- Local login/logout endpoints use antiforgery protection (logout is POST-only)
- OIDC users are bound to stable external identity (`iss` + `sub`) instead of username-only matching
- OIDC username collisions with local users are rejected; unmapped external roles are denied
- Role and project access enforced server-side
- Optional buffered file logging can be enabled via `Logging:File:*` settings for troubleshooting
- Console provider logging can be toggled via `Logging:Console:Enabled`
- EF Core SQL statement logging can be toggled via `Logging:SqlQueries:Enabled`

## Current Status

This repository contains a working Blazor Server application with:

- ASP.NET Identity local authentication
- optional OIDC sign-in + OIDC group-to-role mapping configuration
- EF Core provider-backed persistence for `SQLite`, `SQL Server`, and `PostgreSQL`
- xUnit test suite in `SecureJournal.Tests/` (service + integration coverage)

The repository also keeps legacy fallback paths (prototype store/auth toggles) for compatibility/testing. Explicit EF Core migrations and environment-specific validation are still recommended before production deployment.

Recent UI behavior highlights:

- `/journal` redirects back to `/projects?projectId=...` after successful entry creation
- `My Projects` uses an inline columnar entry list with alternating row colors for readability
- `Audit Search` displays checksum and checksum-validation controls in a dedicated `Integrity` result column

## Container / Cloud Configuration

The app supports environment-based configuration for Docker and Azure App Service:

- Standard .NET hierarchical env vars (for example `Security__JournalEncryptionKey`, `ConnectionStrings__SecureJournalSqlite`).
- Azure App Service connection-string env vars (for example `SQLCONNSTR_SecureJournalSqlServer`, `POSTGRESQLCONNSTR_SecureJournalPostgres`, `CUSTOMCONNSTR_*`).
- Optional shorthand env vars:
  - `SECUREJOURNAL_JOURNAL_ENCRYPTION_KEY`
  - `SECUREJOURNAL_APP_CONNECTION_STRING`
  - `SECUREJOURNAL_IDENTITY_CONNECTION_STRING`
  - `SECUREJOURNAL_BOOTSTRAP_ADMIN_PASSWORD`

Container assets included:

- `Dockerfile`
- `docker-compose.yml`
- `.dockerignore`
- `scripts/generate-env-from-appsettings.ps1` (generate env vars from `appsettings*.json`)

Container runtime security:

- The image runs as a non-root user (`UID/GID 10001`) by default.
- `docker-compose.yml` also pins the runtime user to `10001:10001`.

## Documentation

- Build instructions: `docs/BUILDING.md`
- Local deployment and configuration: `docs/LOCAL_DEPLOYMENT_AND_CONFIGURATION.md`
- Detailed specification and replication baseline: `SPECIFICATION.md`
- Legacy install/run instructions (still valid, less detailed): `INSTALL_INSTRUCTIONS.md`
- Changelog / release history: `CHANGELOG.md`
- Release notes: `RELEASE_NOTES.md`
- Sanitized config templates:
  - `SecureJournal.Web/appsettings.template.json`
  - `SecureJournal.Web/appsettings.Development.template.json`
