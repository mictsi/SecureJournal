# Release Notes

## v0.6.0 - 2026-02-27

### Highlights

- Expanded administrator user lifecycle controls in `User management`:
  - user state toggle (`Enable user` / `Disable user`)
  - user deletion.
- Moved local password reset into `Manage user` (selected-user context) and restricted resets to local users only.
- Strengthened disabled-user enforcement so disabled accounts are blocked from active access paths.
- Restored visible Blazor reconnect UX by ensuring reconnect modal rendering + robust reconnect state class handling.

### Technical Notes

- Added `EnableUser(Guid userId)` to the application service contract and service implementation.
- Updated `UserManagement.razor` to:
  - rename `Manage user` heading casing
  - show stateful enable/disable toggle action
  - include local-only selected-user password reset form.
- Updated auth/runtime guard paths to reject/evict disabled users consistently.
- Updated reconnect modal integration and client logic:
  - `MainLayout.razor` now renders `<ReconnectModal />`
  - `ReconnectModal.razor.js` now applies reconnect state classes deterministically for UI visibility.

## v0.5.0 - 2026-02-27

### Highlights

- Reworked admin UI flow for user administration:
  - local account create/reset operations moved to a dedicated `User Accounts` page
  - group/role governance centered in `User Management` with user-first selection.
- Added batch save workflow for group/role membership updates to prevent hanging behavior during interactive updates for Entra/OIDC users.
- Enabled cleaner multi-membership management:
  - users can be members of multiple groups
  - users can hold multiple roles
  - checkbox-based membership editing with explicit save.
- Improved operational safety and release readiness:
  - added SQL Server cleanup script (`scripts/cleanup-sqlserver.sql`)
  - deployment script now fails fast when journal encryption key is missing.

### Technical Notes

- Added/updated persistence operations for role and group membership mutation paths in:
  - `SecureJournal.Web/Services/InMemorySecureJournalAppService.cs`
  - `SecureJournal.Web/Services/EfCorePrototypeStore.cs`
  - `SecureJournal.Web/Services/SqlitePrototypeStore.cs`
- Added service and regression test coverage for user/group/role paths in `SecureJournal.Tests/InMemorySecureJournalAppServiceTests.cs`.
- Improved admin page routing/navigation (`NavMenu`, `UserManagement`, new `UserAccounts` page) and reconnect modal styling/readability.
- Deployment scripts were streamlined for App Service usage (`scripts/provision-azure.ps1`, `scripts/deploy-appservice.ps1`) and now include stronger configuration validation.

## v0.4.5 - 2026-02-27

### Highlights

- Improved authentication endpoint resiliency with explicit antiforgery-failure handling and user-safe redirect behavior.
- Added stronger OIDC startup/runtime hardening for configuration validation and remote/auth failure paths.
- Improved SQLite operational resilience under transient lock/busy conditions.
- Hardened reconnect modal client script against missing DOM/Blazor runtime assumptions.

### Technical Notes

- `Program.cs` now handles `AntiforgeryValidationException` for local login/logout and logs startup DB initialization failures at critical level.
- `ProductionInfrastructureRegistration.cs` now validates required OIDC settings when enabled, applies `RequireHttpsMetadata`, supports `SignedOutCallbackPath`, and defines `OpenIdConnectEvents` failure handlers.
- `SqlitePrototypeStore.cs` now applies `PRAGMA busy_timeout=5000` and retries transient SQLite connection-open failures.
- `ReconnectModal.razor.js` now guards event hookup and reconnect/resume calls when UI elements or `window.Blazor` methods are unavailable.

## v0.4.4 - 2026-02-27

### Highlights

- Added Azure automation scripts:
  - `scripts/provision-azure.ps1` for provisioning App Service prerequisites and Entra app registrations.
  - `scripts/deploy-appservice.ps1` for publish + zip deployment to Azure App Service.
- Added support in provisioning flow to configure Entra `groupMembershipClaims` for OIDC app registrations so group claims are emitted in ID tokens.
- Added Docker image build validation to the GitHub tagged-release workflow.

### Technical Notes

- `provision-azure.ps1` now outputs App Service metadata (`appServicePlanName`, `webAppName`, app URL) and current-style OIDC env keys (`Authentication__Oidc__*`).
- `deploy-appservice.ps1` now uses current SecureJournal configuration keys (`Authentication__*`, `Security__*`, `BootstrapAdmin__*`, `Logging__*`) and supports OIDC role-group mapping env keys:
  - `Authentication__Oidc__RoleGroupMappings__Administrator__*`
  - `Authentication__Oidc__RoleGroupMappings__Auditor__*`
  - `Authentication__Oidc__RoleGroupMappings__ProjectUser__*`
- Tag-build workflow now includes `docker build -t securejournal:${{ github.ref_name }} .`.

## v0.4.2 - 2026-02-27

### Highlights

- Re-enabled static web asset compression for web builds and publishes.
- Eliminated static asset collisions by removing duplicate checked-in Blazor runtime files from `wwwroot/_framework`.
- Updated tag-build workflow steps so restore/build/test/publish run consistently for tagged releases.
- Added logging configuration toggles for console provider output and EF Core SQL statement logging.
- Fixed left navigation sidebar color behavior when switching to light theme.

### Technical Notes

- Project setting: `CompressionEnabled=true` in `SecureJournal.Web.csproj`.
- Tag-build workflow no longer forces `CompressionEnabled=false`.
- Startup script no longer copies framework runtime files into `SecureJournal.Web/wwwroot/_framework`.

## v0.4.1 - 2026-02-27

### Highlights

- Hotfix for CI/tagged release builds failing during static web asset compression.
- Resolved duplicate-key failure in `ApplyCompressionNegotiation` by removing duplicate checked-in `_framework` runtime files.
- Updated GitHub tag-build workflow to run with compression enabled.

### Technical Notes

- Project-level setting: `CompressionEnabled=true` in `SecureJournal.Web.csproj`.
- Workflow build/publish commands no longer force compression off.

## v0.4.0 - 2026-02-27

### Highlights

- Added GitHub Actions tag build workflow (`push` on `v*`) with restore/build/test/publish and artifact upload.
- Added workflow status badge to `README.md`.
- Added Docker packaging (`Dockerfile`, `docker-compose.yml`, `.dockerignore`) for local and cloud-hosted container runs.
- Added rootless container runtime (non-root user `10001:10001`) in both Docker image and compose setup.
- Added environment-variable-first configuration support for Docker and Azure App Service, including:
  - standard hierarchical .NET keys (`Section__Subsection__Key`)
  - Azure connection-string prefixes (`SQLCONNSTR_*`, `POSTGRESQLCONNSTR_*`, `CUSTOMCONNSTR_*`, etc.)
  - optional shorthand env vars for common security/connection values
- Added script to generate env files from appsettings:
  - `scripts/generate-env-from-appsettings.ps1`

### Technical Notes

- Persistence options now support direct connection string overrides:
  - `Persistence:AppConnectionString`
  - `Persistence:IdentityConnectionString`
- Updated template appsettings files to include the new persistence override keys.
- Updated deployment and build documentation for CI, Docker, and environment-variable workflows.

## v0.3.0 - 2026-02-27

### Highlights

- Improved `My Projects` journal readability with a column-header row and single-line, flex-based entries.
- Added date sorting (`Newest first` / `Oldest first`) in `My Projects`.
- Added dedicated journal entry details page (`/projects/entry/{recordId}`) with Back navigation.
- Added `Add Journal Entry` action in `My Projects`.
- After creating an entry in `/journal`, users now return to `/projects` with the created project preselected.
- Removed checksum display from `My Projects` entry rows.
- Updated `Audit Search` results with a dedicated `Integrity` column for checksum + validation controls.
- Added alternating row colors (zebra striping) for table/list readability across pages.

### Technical Notes

- Documentation and specification were updated to match current behavior.
- Release build artifact target: `securejournal-web-v0.3.0.zip` (published web output).
