# Secure Journal

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
- Role and project access enforced server-side

## Current Status

This repository contains a working Blazor Server application with:

- ASP.NET Identity local authentication
- optional OIDC sign-in + OIDC group-to-role mapping configuration
- EF Core provider-backed persistence for `SQLite`, `SQL Server`, and `PostgreSQL`

The repository also keeps legacy fallback paths (prototype store/auth toggles) for compatibility/testing. Explicit EF Core migrations and environment-specific validation are still recommended before production deployment.

## Documentation

- Build instructions: `docs/BUILDING.md`
- Local deployment and configuration: `docs/LOCAL_DEPLOYMENT_AND_CONFIGURATION.md`
- Detailed specification and replication baseline: `SPECIFICATION.md`
- Legacy install/run instructions (still valid, less detailed): `INSTALL_INSTRUCTIONS.md`
- Sanitized config templates:
  - `SecureJournal.Web/appsettings.template.json`
  - `SecureJournal.Web/appsettings.Development.template.json`
