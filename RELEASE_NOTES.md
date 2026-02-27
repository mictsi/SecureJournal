# Release Notes

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
