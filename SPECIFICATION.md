# Secure Journal Application Specification (Draft v1.1)

## 1. Purpose

A secure journal application for one or more users to record major events occurring in projects. The system must isolate projects from each other, enforce role-based access, and provide strong auditing and encryption.

## 2. Scope

The application supports:

- Multiple projects with strict data separation
- Journal entries for project events
- Role-based access (`Administrator`, `Project User`, `Auditor`)
- Local authentication and generic OIDC authentication
- Encrypted journal data storage and audit logging with integrity checksums
- Export of project data and audit data (CSV/JSON)

## 3. Technology Constraints

- Platform: `.NET 10`
- UI: `Blazor` (recommended: server-hosted / interactive server for key safety)
- Database support:
  - `SQLite` for testing/development
  - `SQL Server` and `PostgreSQL` for production
- Authentication:
  - Local login
  - Generic OIDC provider


## 4. Core Principles

- Security-first: persisted journal/application business data is encrypted at rest by the application layer
- Auditability: all important actions are logged and searchable
- Immutability: journal entries are append-only (no edits)
- Least privilege: access only through roles and project/group membership
- Separation: projects are logically isolated from each other

## 5. Roles and Permissions

### 5.1 Administrator

- Create/manage projects
- Create/manage/delete groups
- Add/remove users to/from groups
- Add/remove groups to/from one or more projects
- Create/manage users (including local accounts)
- Manage multi-role assignments per user
- Enable/disable user accounts
- Delete user accounts
- Reset passwords for local users
- View all journal data across projects
- View and search all audit logs
- Export project data and audit data
- Manage authentication settings (local/OIDC) via configuration/admin settings (as implemented)

### 5.2 Project User

- Access one or more projects through group membership
- Create journal entries in authorized projects
- Read journal entries in authorized projects
- No update/edit of journal entries
- May request/delete (soft-delete) entries only if permitted by policy
- Deletion hides records from project users, preserves data for administrators, and preserves evidence in the audit trail for auditors

### 5.3 Auditor

- Read all audit logs across all projects
- Search/filter audit logs
- Export audit data
- No direct read access to journal entries (audit role focuses on audit logs/search/export)
- No project/group/user administration changes

## 6. Functional Requirements

### 6.1 Project and Group Management

- The system shall support creation of multiple projects.
- The system shall support creation of groups.
- The system shall support adding and removing users from groups.
- The system shall support adding and removing groups from projects.
- The system shall support deleting groups.
- A user's project access shall be derived from group membership (except administrators who have global access).

### 6.2 User Management

- Administrators shall create local users.
- User account creation shall be available on a dedicated administrator page (`/admin/user-accounts`).
- Membership and role management shall be available on a dedicated administrator page (`/admin/users`).
- Users shall support membership in multiple groups.
- Users shall support assignment of multiple roles.
- Group/role edits shall support a batched "Save" operation (checkbox selection + explicit save), not immediate per-toggle persistence.
- Administrators shall be able to disable and re-enable users.
- Administrators shall be able to delete users.
- Local-password reset shall be available only for local accounts.
- The system shall support enabling/disabling local login.
- The system shall support generic OIDC login.
- Users authenticated via OIDC shall be mapped to application users and roles/groups.
- OIDC user identity binding shall use stable provider identifiers (`iss` + `sub`) and not rely on username/email alone.
- OIDC diagnostics shall support optional claim/token logging when `iss`/`sub` are missing:
  - `Authentication:Oidc:LogClaimsWhenIssuerSubjectMissing`
  - `Authentication:Oidc:LogTokensWhenIssuerSubjectMissing`
- OIDC configuration shall support role mapping by external group membership, where each application role can be configured with one or more external groups.
- Role assignment shall be managed by administrators only.

### 6.3 Journal Entry Management

- Journal entries shall be tied to exactly one project.
- Journal entries shall be immutable after creation (no updates).
- Journal entries may be soft-deleted (hidden) but never physically removed through normal UI operations.
- The project journal list shall support sorting by creation date ascending/descending.
- The project journal list shall support opening a dedicated single-entry details view.
- Read visibility of soft-deleted entries:
  - Hidden from project users
  - Visible to administrators in direct journal views (with deletion metadata)
  - Auditors access deletion evidence via audit logs (not direct journal reads)

### 6.4 Journal Entry Fields

For each journal entry, the system shall store:

- `RecordId` (auto-generated)
- `CreatedAtUtc` (auto-generated)
- `CreatedBy` (from authenticated user)
- `Action` (max 50 chars)
- `Subject` (one line, max 80 chars)
- `Description` (max 500 chars)
- `Notes` (max 2000 chars)

### 6.5 Data Validation

- All text fields shall enforce maximum length limits.
- Required fields shall be validated server-side.
- Date/time and actor fields shall be system-generated and immutable.
- Input shall be normalized before checksum generation (UTF-8, trimmed/normalized consistently).

### 6.6 Checksums (SHA-256)

- All user-input journal fields shall have a SHA-256 checksum computed before database insert.
- Checksums shall be stored with the record for integrity verification.
- The system should also store a full-record checksum (recommended) for tamper detection.
- Checksums do not replace encryption; original values must remain retrievable (encrypted).

## 7. Security Requirements

### 7.1 Data Encryption

- All persisted application data shall be encrypted before storage (application-layer encryption).
- Encryption key shall be supplied via configuration.
- Keys shall never be exposed to the client/browser.
- Encrypted fields shall include journal content and sensitive metadata as required.

### 7.2 Audit Log Encryption

- Audit logs shall not be encrypted in the database (finalized decision).
- Audit log integrity shall be protected using checksums for tamper detection.
- Sensitive content in audit logs should be minimized because payloads are stored in plaintext.

### 7.3 Authentication Security

- Local passwords shall be stored using secure password hashing (framework standard).
- OIDC integration shall use secure token validation and HTTPS.
- OIDC logins without required identity claims (`iss`/`sub`) or without an explicit mapped application role shall be denied.
- Disabled users shall be denied access regardless of authentication path (local/OIDC/session restore).
- Authentication events shall be audited (success/failure/logout/lockout as applicable).
- Session cookies shall expire automatically after a configurable duration (current appsettings setting: `Security:SessionCookieHours`, default `8` hours).
- Local login and logout endpoints shall use CSRF/antiforgery protection; logout shall be POST-only.

### 7.4 Authorization Security

- All access checks shall be enforced server-side.
- Unauthorized access attempts shall be logged.
- Project data access shall always be scoped by project membership unless role is Admin/Auditor.


## 8. Auditing Requirements

### 8.1 Events to Audit

The system shall log, at minimum:

- All CRUD operations (including attempted operations)
- All permission/role/group/project assignment changes
- All authentication events
- All export actions
- All access-denied events

### 8.2 Audit Log Content (minimum)

Each audit log entry should include:

- `AuditId`
- `TimestampUtc`
- `ActorUserId` / `ActorUsername`
- `Action` (Create/Read/Update/Delete/Login/Logout/Assign/Export/etc.)
- `EntityType` (JournalEntry/User/Group/Project/Permission/Auth/etc.)
- `EntityId` (when applicable)
- `ProjectId` (when applicable)
- `Outcome` (Success/Failure/Denied)
- `Details` (plaintext; not encrypted)
- `Checksum` (recommended for integrity verification)
- Optional: IP address, user agent, correlation/request ID

### 8.3 Audit Log Search

- Audit logs shall be searchable by authorized roles (`Administrator`, `Auditor`).
- Minimum searchable filters:
  - Date/time range
  - User
  - Project
  - Action type
  - Entity type
  - Outcome
- Exportable audit results shall preserve filter criteria metadata.
- Audit results shall present checksum values and checksum-validation actions in a dedicated integrity area/column for clarity.
- Checksum validation status shall be shown inline next to the validation action with explicit valid/invalid indicators.

## 9. Export Requirements

### 9.1 Who Can Export

- `Administrator` can export project data and audit data.
- `Auditor` can export audit data and project-scoped audit data only.
- `Auditor` shall not export journal entries directly.

### 9.2 Export Formats

- `CSV`
- `JSON`

### 9.3 Export Scope

- Export shall support selecting a specific project.
- Export shall support filtering by date range.
- Export actions shall be audit logged.
- Export should support including/excluding soft-deleted records (with default behavior defined by role).

## 10. Non-Functional Requirements

### 10.1 Performance

- Common reads/searches should return paged results.
- Audit search shall support pagination and filtering to avoid loading full datasets.
- Project list and project-entry list views should support pagination and configurable page size.

### 10.2 Reliability

- All writes (journal + audit) should be transactional where possible.
- Failure to write audit logs for sensitive operations should fail the operation or trigger a clear error policy (recommended: fail closed for security-sensitive actions).
- Interactive-server reconnect behavior shall expose visible, readable retry/reload controls when connection is interrupted.

### 10.3 Portability

- Database provider abstraction shall support SQLite, SQL Server, and PostgreSQL with minimal code changes.
- Runtime configuration should support environment-variable deployment patterns for containerized and cloud-hosted environments (including .NET hierarchical keys and provider-specific connection-string injection).

### 10.4 Time Handling

- All timestamps shall be stored in UTC.

## 11. Suggested Data Model (High-Level)

- `Users`
- `Roles`
- `UserRoles`
- `Groups`
- `GroupMembers`
- `Projects`
- `ProjectGroups`
- `JournalEntries`
- `JournalEntryVisibility` (optional, if per-project hiding becomes more granular)
- `AuditLogs`
- `AuthProviders` / `OidcSettings` (if stored in DB; otherwise configuration only)

## 12. Business Rules (Important)

- Journal entries are append-only; corrections require new entries.
- Soft-delete hides data from project users; administrators retain direct visibility and auditors rely on audit logs.
- All user-entered journal fields require SHA-256 checksum before persistence.
- Journal/application business data is encrypted; audit logs are plaintext with integrity checksums.
- Administrators manage users, groups, project mappings, and roles.
- Project users only operate within assigned projects.
- Auditors focus on read/search/export of audit data only (no direct journal reads).

## 13. Assumptions Made in This Draft

- `Subject` field max length is finalized at `80` characters (single-line input in UI).
- Journal entries are immutable for all roles (stronger audit integrity).
- Blazor deployment is server-side/interactively server-rendered to avoid exposing encryption keys.

## 14. Open Questions (to Finalize Spec)

1. Should `Auditor` be allowed to read journal entries directly, or only audit logs? Only audit logs.
2. Should `Project User` be allowed to soft-delete their own entries, or any entry in the project? They should be able to soft-delete all entries in the projects and deletion should be logged in the audit logs
3. Result field removed from journal entries (finalized)
4. Is export output required to be encrypted/password-protected files? No encryption needed
5. Are attachments/files part of journal entries (currently out of scope)? No attachment support.
6. Is multi-tenant deployment needed, or is this a single organization app with multiple projects? Single organization app with multiple projects.

## 15. UI
1. UI should be WCAG compatible
2. The application shall support dark mode and light mode
3. Theme contrast must keep primary actions readable in both themes (including login/OIDC actions)
4. Include basic formatting tools for notes and description fields
5. Project entry list should show consistent column headers with one row per entry (without repeating field-name prefixes in each row)
6. List and table views should use alternating row backgrounds to improve readability
7. Single-entry details view should include clear Back navigation to the prior project context
8. Admin pages should use flex/grid layouts that keep primary selection lists and editors visible without page jumps
9. User management UX should be user-centric: select a user, then manage groups/roles via checkboxes and save changes in one operation
10. Project group access UX should be project-centric: select a project, then manage group access via checkboxes and save changes in one operation
11. Multi-assigned groups in project and admin tables should render as per-group tags/chips (not collapsed into unreadable overflow text)
12. Audit/group/project table cells should be top-aligned for multi-line readability
13. Reconnection and Blazor error UX must remain readable and actionable in both themes (`Retry`, `Reload`, and dismissal controls visible)

## 16. Code testing and security best practises
1. Always test the codes, Use TDD principles
2. Always validate the user input
3. Always use security best practises
4. Always check latest version of modules/drivers/packages 

## 17. Finalized Override
1. Audit logs should not be encrypted (stored plaintext with integrity checksum)

## 18. Development Setup, Run, and Configuration

Install/setup/run instructions have been moved to:

- `INSTALL_INSTRUCTIONS.md`
- `docs/BUILDING.md`
- `docs/LOCAL_DEPLOYMENT_AND_CONFIGURATION.md`

Configuration policy for the current project (current repository state):

- Runtime settings may come from appsettings files and/or environment variables.
- In the current repository state, sanitized template files are source-controlled:
  - `SecureJournal.Web/appsettings.template.json`
  - `SecureJournal.Web/appsettings.Development.template.json`
- Active runtime files (`appsettings.json`, `appsettings.Development.json`) are environment-local and may be absent from source control.
- For shared/staging/production environments, sensitive values should be overridden via environment variables, user-secrets, or a secret manager.
- Secrets currently stored in appsettings include (at minimum):
  - `Security:JournalEncryptionKey`
  - `Authentication:Oidc:ClientSecret`
  - `BootstrapAdmin:Password`
- Session/login cookie settings are also stored in appsettings (for the current prototype), including:
  - `Security:SessionCookieName`
  - `Security:SessionCookieHours`
- OIDC role/group mapping configuration is also stored in appsettings (current config foundation), including:
  - `Authentication:Oidc:GroupClaimType`
  - `Authentication:Oidc:RoleGroupMappings:Administrator[]`
  - `Authentication:Oidc:RoleGroupMappings:Auditor[]`
  - `Authentication:Oidc:RoleGroupMappings:ProjectUser[]`
- Optional OIDC diagnostics settings (supported by current implementation):
  - `Authentication:Oidc:LogClaimsWhenIssuerSubjectMissing`
  - `Authentication:Oidc:LogTokensWhenIssuerSubjectMissing`
- Optional direct persistence connection-string overrides are supported:
  - `Persistence:AppConnectionString`
  - `Persistence:IdentityConnectionString`

Current implementation bootstrap behavior:

- On first run with a clean local database, the application seeds a startup administrator account from `BootstrapAdmin` appsettings values.
- Local login uses ASP.NET Identity (cookie auth) when `Authentication:EnableAspNetIdentity=true`; otherwise it falls back to the prototype local-auth implementation.
- The admin pages allow the startup administrator to create users, groups, projects, and assignments.

## 19. Replication Baseline (Current Repository)

This section documents what is needed to reproduce the current working implementation as it exists in this repository.

### 19.1 Repository Layout (Current)

- `SecureJournal.Core/` - core domain models, validation, security, application contracts
- `SecureJournal.Web/` - Blazor Server UI, application services, EF Core persistence, ASP.NET Identity/OIDC integration, and legacy fallback paths
- `SecureJournal.Tests/` - xUnit tests for core service behavior and regression coverage
- `scripts/` - local start scripts plus Azure deploy/provision helpers and SQL cleanup utility
- `.artifacts/` - local build/test outputs (including `verify-build` workaround output)

### 19.2 SDK / Runtime Assumptions

- `.NET 10 SDK` installed
- ASP.NET Core/Blazor runtime components available
- Local HTTPS dev certificate trusted (`dotnet dev-certs https --trust`) for easiest local use

### 19.3 Build / Test / Run Commands (Current Layout)

Build (normal):

```powershell
dotnet restore SecureJournal.Web\SecureJournal.Web.csproj
dotnet build SecureJournal.Web\SecureJournal.Web.csproj
```

Build (workaround for the local web-assets issue observed in this environment):

```powershell
dotnet build SecureJournal.Web\SecureJournal.Web.csproj -p:RestoreIgnoreFailedSources=true -o .artifacts\verify-build
```

Run (script, recommended):

```powershell
.\scripts\start.ps1
```

Run (manual, workaround flags):

```powershell
dotnet run --project SecureJournal.Web --launch-profile https -p:RestoreIgnoreFailedSources=true
```

Tests:

```powershell
dotnet test SecureJournal.Tests\SecureJournal.Tests.csproj -m:1 --logger "console;verbosity=minimal" -p:RestoreIgnoreFailedSources=true
```

### 19.4 Required Configuration Files (Current)

- `SecureJournal.Web/appsettings.template.json` (sanitized template)
- `SecureJournal.Web/appsettings.Development.template.json` (sanitized template)
- Optional runtime-local active files:
  - `SecureJournal.Web/appsettings.json`
  - `SecureJournal.Web/appsettings.Development.json`

The current implementation expects effective runtime configuration (from files and/or environment variables) to contain:

- connection strings (`SQLite`, plus placeholder `SQL Server` / `PostgreSQL`)
- journal encryption key
- local password policy and complexity settings
- session cookie settings
- local/OIDC authentication toggles and OIDC placeholders
- optional OIDC diagnostics toggles:
  - `Authentication:Oidc:LogClaimsWhenIssuerSubjectMissing`
  - `Authentication:Oidc:LogTokensWhenIssuerSubjectMissing`
- bootstrap administrator credentials
- logging configuration (including request logging mode/level)
- optional buffered file logging (`Logging:File:Enabled`, `Logging:File:Path`, `Logging:File:MinimumLevel`)
- OIDC role-group mappings (`Authentication:Oidc:RoleGroupMappings:*`)

### 19.5 Current Local Storage / Persistence Behavior

- The application supports provider-backed persistence via EF Core for app data and Identity (`Sqlite`, `SqlServer`, `PostgreSql`) when enabled by configuration
- App-data and Identity may share the same database connection (separate EF contexts)
- When no migrations are present and `Persistence:AutoMigrateOnStartup=false`, startup performs context-specific schema creation checks and creates missing tables for each context
- Persisted entities include:
  - users
  - projects
  - groups
  - user-group assignments
  - group-project assignments
  - journal entries
  - audit logs
- Journal fields are application-encrypted before SQLite storage
- Audit details are plaintext with checksums
- The legacy SQLite prototype store remains available as a fallback path when `Persistence:EnableProductionAppDatabase=false`

### 19.6 Current UI / Workflow Baseline

- `/` = login page
- `/projects` = `My Projects` (project list + project-specific journal entry browsing/search)
- `/journal` = `New Journal Entry` form (create-only)
- `/audit` = audit search with linked journal evidence display
- `/exports` = CSV/JSON export generation + download
- `/admin/projects`, `/admin/groups`, `/admin/users`, `/admin/user-accounts` = admin management pages
- Current admin information architecture:
  - `/admin/user-accounts` = create users (local/external, initial roles)
  - `/admin/users` = manage selected user memberships, roles, enabled/disabled state, delete user, reset local password
  - `/admin/projects` = project list with paging + selected-project group access editor (checkbox + save)
  - `/admin/groups` = create and delete groups, with member/project mapping overview

### 19.6.1 Production Foundation Feature Flags (Current)

- `Authentication:EnableAspNetIdentity`
- `Authentication:EnableLocalLogin`
- `Authentication:EnableOidc`
- `Persistence:EnableProductionAppDatabase`
- `Persistence:EnableProductionIdentityDatabase`
- `Persistence:Provider` (`Sqlite`, `SqlServer`, `PostgreSql`)
- `Persistence:AutoMigrateOnStartup`
- Optional OIDC diagnostics:
  - `Authentication:Oidc:LogClaimsWhenIssuerSubjectMissing`
  - `Authentication:Oidc:LogTokensWhenIssuerSubjectMissing`

When enabled, the app initializes:

- ASP.NET Core Identity (EF Core store)
- App-data EF Core persistence store (projects/groups/users/journals/audit)
- OIDC registration (when `Authentication:EnableOidc=true`)
- OIDC group->role claims mapping parser/transformer
- OIDC external identity binding by `iss` + `sub` with collision protections
- bootstrap Identity admin seeding from `BootstrapAdmin`

Template configuration files for safe sharing/onboarding:

- `SecureJournal.Web/appsettings.template.json`
- `SecureJournal.Web/appsettings.Development.template.json`

### 19.7 SQL Server / PostgreSQL Replication Note

- `SQL Server` and `PostgreSQL` connection string examples are included in:
  - `docs/LOCAL_DEPLOYMENT_AND_CONFIGURATION.md`
- They are supported through the provider-switched EF Core persistence configuration.
- OIDC role-group mapping configuration examples are included in:
  - `docs/LOCAL_DEPLOYMENT_AND_CONFIGURATION.md`

