# Secure Journal

[![Tag Build](https://github.com/mictsi/SecureJournal/actions/workflows/tag-build.yml/badge.svg)](https://github.com/mictsi/SecureJournal/actions/workflows/tag-build.yml)

<p align="center">
  <img src="SecureJournal.Web/wwwroot/images/logo_125_by_125.png" alt="Secure Journal logo" width="96" />
</p>

Secure Journal is a role-based project event journaling application for a single organization with multiple projects.

It is designed for:

- `Administrators` who manage users, groups, projects, and audit/export workflows
- `Project Users` who create and read append-only journal entries in projects they can access
- `Auditors` who search/export audit logs and review linked journal evidence without direct journal browsing

## What Users Can Do

- Sign in with local accounts (ASP.NET Identity cookie auth)
- Login with OpenID (when enabled by configuration)
- Admins can create users from `User Accounts` (`/admin/user-accounts`)
- Admins can manage user role/group memberships from `User management` (`/admin/users`)
- Admins can create projects from `Create project` (`/admin/projects/create`) and groups from `Create group` (`/admin/groups/create`)
- Admins can edit project metadata from `Project Management` (`/admin/projects`) from a focused project card
- Admins can enable/disable project access from `Project Management`; disabled projects are hidden from project users
- Admins can enable/disable users and delete users from `User management`
- Admins can reset passwords for local users from `Manage user` (selected-user context)
- View `My Projects` and browse journal entries per project
- Search and page the `My Projects` project list
- Favorite projects privately and use `Show favorites` to return to them quickly
- Search project journal entries by partial text in `Subject`, `Description`, and `Notes`
- Sort project journal entries by date (`Newest first` / `Oldest first`)
- Open a dedicated journal entry details page from `My Projects` and return to the selected project context
- Create append-only journal entries (`Subject`, `Description`, `Notes`) with multiple file attachments
- Soft-delete journal entries (preserved for admin visibility and audit evidence)
- Search audit logs with filters (date/user/project/action/entity/outcome + field-specific contains)
- Validate audit checksums per audit row
- Export journal/audit data as `CSV` or `JSON`; include journal files in a ZIP archive with a manifest

## Security/Behavior Highlights

- Journal fields, attachment filenames, and file contents are encrypted before database storage
- Audit details are plaintext with SHA-256 checksums
- Per-browser authenticated sessions (cookie expiration configurable; default 8 hours)
- Password hashing + configurable password complexity policy
- Local login/logout endpoints use antiforgery protection (logout is POST-only)
- OIDC users are bound to stable external identity (`iss` + `sub`) instead of username-only matching
- OIDC username collisions with local users are rejected; unmapped external roles are denied
- Disabled users are blocked from access across local/OIDC resolution and authenticated request paths
- Entra ID app registration provisioning can enforce group claims in ID tokens (`groupMembershipClaims`)
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

- My projects, People, Groups, and Manage projects begin with Search or Show all, followed by paged results and a focused record card.
- Centered workspaces preserve search and paging when returning from a record. Quick read has a dedicated entry list and reader pane.
- Favorite buttons on project cards and headers save preferences per account. Show favorites supports search and paging without changing project permissions.
- Audit search shows Date, Project, Who, Status, Action, and Message in compact rows; View details exposes evidence and integrity checks.
- Entries show date, author, and subject in a compact row. Show entry expands the full description, notes, and files inline. Quick read uses a paged entry list on the left and one selected full entry on the right; selection and filters survive return navigation. On phones, Back to entries returns to the list.
- Adding an entry from a project fixes that project in the composer, including through primary navigation. New entries open their saved detail page. Draft text and files survive a canceled navigation.
- Layouts follow Sekura Design MCP 3.2.1 and support narrow screens, light/dark themes, keyboard use, and enlarged text.

### File attachments and exports

Choose multiple files or drag them into a new journal entry. Each entry supports up to **10 files**, **10 MiB per file**, and **20 MiB total**. Files are saved atomically with the entry and cannot be changed afterward. Cancel, retry, and remove controls help resolve upload errors before saving.

File downloads require current access to the entry and use download-only responses. Names and contents are encrypted at rest. Files are not previewed or executed by the application; uploaded content is not malware-scanned.

Administrators can include files when exporting journal records. The ZIP contains `journal.csv` or `journal.json`, `manifest.json`, and files grouped by entry ID. The manifest records filenames, paths, sizes, and SHA-256 checksums. Project, date, and soft-delete filters apply to both records and files. ZIP exports allow up to 10,000 entries, 10 MiB of journal text, 1,000 files, and 50 MiB of file contents; use smaller scopes for larger collections. Exports contain decrypted data and need appropriate storage protection. Audit exports remain CSV/JSON.

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
- `scripts/provision-azure.ps1` (provision RG + storage + key vault + App Service + Entra app registrations)
- `scripts/deploy-appservice.ps1` (publish/deploy SecureJournal to Azure App Service with app settings)
- `scripts/cleanup-sqlserver.sql` (clean app data in SQL Server; optional Identity data cleanup mode)

Container runtime security:

- The image runs as a non-root user (`UID/GID 10001`) by default.
- `docker-compose.yml` also pins the runtime user to `10001:10001`.

Azure App Service health check:

- The application exposes a health endpoint at `/health` that returns HTTP `200 OK` for instance probes.
- In Azure App Service, set **Health check path** to `/health`.

Authentication startup hotfix:

- Startup now safely skips auth middleware/endpoints when Identity database auth is not enabled.
- If `Authentication:EnableAspNetIdentity=true` while `Persistence:EnableProductionIdentityDatabase=false`, the app logs a warning and continues to run (instead of failing at startup).

## Application Insights Telemetry

Secure Journal supports optional Azure Application Insights telemetry for monitoring and diagnostics.

To enable:
- Set `ApplicationInsights:Enabled` to `true` in your appsettings or environment variables.
- Provide your Azure Application Insights connection string in `ApplicationInsights:ConnectionString`.
- The app will automatically register telemetry if enabled.

See `docs/LOCAL_DEPLOYMENT_AND_CONFIGURATION.md` for more details.

## Documentation

- Build instructions: `docs/BUILDING.md`
- Local deployment and configuration: `docs/LOCAL_DEPLOYMENT_AND_CONFIGURATION.md`
- Detailed specification and replication baseline: `SPECIFICATION.md`
- Legacy install/run instructions (still valid, less detailed): `INSTALL_INSTRUCTIONS.md`
- Changelog / release history: `CHANGELOG.md`
- Release notes: [0.24.1](docs/release_notes/v0.24.1.md)
- Sanitized config templates:

---

## 0.24.1 Release

Version-only patch release following the Quick read and project favorites redesign.
See the [release notes](docs/release_notes/v0.24.1.md).

## 0.24.0 Release

Quick read now uses two panes: choose an entry on the left to read it on the
right. Project favorites are saved per user, with Show favorites beside Show my
projects. See the [release and upgrade notes](docs/release_notes/v0.24.0.md).

---

## 0.23.0 Release

Compact journal rows expand inline; Quick read provides pageable full content.
Project context is fixed when adding entries from a journal. Individual files
can be up to 10 MiB, and audit activity uses aligned scanning columns.
See the [release and upgrade notes](docs/release_notes/v0.23.0.md).

---

## 0.22.0 Release

Search-first workspaces replace body directory columns, and journal entries now
support multiple files, drag and drop, and ZIP exports with file manifests.
See the [release and upgrade notes](docs/release_notes/v0.22.0.md).

---

## 0.21.1 Release

This patch keeps journal action buttons readable in desktop tables while
preserving the phone layout. It includes the 0.21.0 changes below.

---

## 0.21.0 Release

This release simplifies project journals, project creation, exports, and account
administration. Drafts survive filtering and navigation within a workflow, and
phone layouts keep journal subjects and actions readable. Security fixes cover
markup sanitization, redirects, permissions, sessions, trusted proxies, and
sensitive logging. Dependencies and container tooling are updated, with locked
restores and automated vulnerability checks.

Builds require .NET SDK 10.0.402. See the
[upgrade notes](docs/release_notes/v0.21.0.md#upgrade-notes) before deployment.

---

## v0.10.1 Release

This release refactors the Projects page for improved usability and responsiveness, with minor UI and style adjustments to enhance user experience.

---

## v0.10.0 Release

This release refactors the Project Management and Group Management pages for improved usability and responsiveness, standardizes group/user membership labels, and adds advanced group user management features (filtering, sorting, paging). Navigation and layout changes streamline admin workflows and reduce UI clutter.

---

## v0.9.4 Release

This release updates the admin Create Project flow from a single form into a route-driven wizard that matches the requested sequence: define project, configure group permissions (existing vs new groups), optionally assign members to new groups, then persist everything only on final submit. The flow now supports step navigation (back/cancel) and returns to the start page after completion.
  - `SecureJournal.Web/appsettings.template.json`
  - `SecureJournal.Web/appsettings.Development.template.json`
