# Secure Journal Install and Run Instructions

This file contains the installation, setup, and local run instructions for the current Secure Journal application.

For the newer split documentation pages, see:

- `docs/BUILDING.md`
- `docs/LOCAL_DEPLOYMENT_AND_CONFIGURATION.md`

## 1. Required Components

- Operating system:
  - Windows 10/11 (examples below use PowerShell)
  - Linux/macOS also supported with equivalent `dotnet` commands
- `.NET 10 SDK` (`10.0.x`) with ASP.NET Core/Blazor support
- Optional but recommended:
  - `Git`
  - `Visual Studio 2022` with **ASP.NET and web development** workload, or
  - `VS Code` + C# extensions
- HTTPS development certificate (for local HTTPS):
  - `dotnet dev-certs https --trust`

## 2. Install Commands (Windows / PowerShell)

Install .NET 10 SDK (if not installed):

```powershell
winget install Microsoft.DotNet.SDK.10
```

Install Git (optional):

```powershell
winget install Git.Git
```

Verify installation:

```powershell
dotnet --version
dotnet --list-sdks
```

Optional (for containerized deployment):

```powershell
docker --version
docker compose version
```

## 3. Configure Settings (AppSettings Files)

The current local-development setup uses appsettings files for runtime configuration. For shared or production environments, prefer environment variables, `dotnet user-secrets`, or a secret manager for sensitive values.

Files:

- `SecureJournal.Web/appsettings.json`
- `SecureJournal.Web/appsettings.Development.json`
- `SecureJournal.Web/appsettings.template.json` (sanitized template)
- `SecureJournal.Web/appsettings.Development.template.json` (sanitized template)

Recommended setup flow:

- Start from the `*.template.json` files for new environments.
- Copy values into `appsettings.json` / `appsettings.Development.json`.
- Replace all placeholder secrets/connection strings before use.

Current settings include:

- `ConnectionStrings:*`
- `Security:JournalEncryptionKey`
- `Authentication:EnableLocalLogin`
- `Authentication:EnableOidc`
- `Authentication:OidcProviderName`
- `Authentication:Oidc:*` (including `ClientSecret`)
- `BootstrapAdmin:*` (including `Password`)
  - `BootstrapAdmin:SyncPasswordOnStartup` (development convenience; can resync admin password from appsettings on startup)
- `Logging:Console:Enabled` (toggle console logger provider)
- `Logging:SqlQueries:Enabled` (toggle EF Core SQL statement logging)
- `Logging:File:*` (optional buffered file logging for troubleshooting)

Update the placeholders in the appsettings files before running, and avoid committing real secrets.

Default local behavior (current repository settings):

- The app runs with ASP.NET Identity enabled (`Authentication:EnableAspNetIdentity=true`).
- The app runs with provider-backed EF Core persistence enabled for app data and Identity (`Persistence:EnableProductionAppDatabase=true`, `Persistence:EnableProductionIdentityDatabase=true`).
- The default provider is SQLite (`Persistence:Provider=Sqlite`) using `ConnectionStrings:SecureJournalSqlite` and `ConnectionStrings:SecureJournalIdentitySqlite`.
- Default development value in `SecureJournal.Web/appsettings.Development.json` creates `securejournal.dev.db` in the application working directory.
- Identity data defaults to `securejournal.identity.dev.db`.
- On first run with a clean database, the app seeds only the startup administrator from `BootstrapAdmin` in appsettings.
- In `Development`, `BootstrapAdmin:SyncPasswordOnStartup=true` can resync the bootstrap admin password from appsettings on each startup (helpful if an old local DB has a stale admin password).
- No demo projects/users/journal records are seeded anymore.

Environment-variable deployment is also supported (Docker / Azure App Service):

- Hierarchical keys, for example `Security__JournalEncryptionKey`, `BootstrapAdmin__Password`, `ConnectionStrings__SecureJournalSqlite`
- Azure App Service connection-string prefixes (`SQLCONNSTR_*`, `POSTGRESQLCONNSTR_*`, `CUSTOMCONNSTR_*`)
- Optional shorthand keys such as `SECUREJOURNAL_JOURNAL_ENCRYPTION_KEY`
- Helper script available: `scripts/generate-env-from-appsettings.ps1`

Azure App Service automation scripts are included:

- `scripts/provision-azure.ps1` to provision Azure resources and optional Entra OIDC app registration.
- `scripts/deploy-appservice.ps1` to publish and deploy `SecureJournal.Web` to App Service.

If you are using Entra group-to-role mapping, configure group claims in ID tokens during provisioning:

- `-OidcGroupMembershipClaims SecurityGroup`

Clean database reset (manual):

```powershell
Remove-Item -Force .\securejournal.dev.db -ErrorAction SilentlyContinue
Remove-Item -Force .\securejournal.identity.dev.db -ErrorAction SilentlyContinue
Remove-Item -Force .\SecureJournal.Web\securejournal.dev.db -ErrorAction SilentlyContinue
Remove-Item -Force .\SecureJournal.Web\securejournal.identity.dev.db -ErrorAction SilentlyContinue
```

The next app start recreates the SQLite database and seeds the bootstrap admin user.

## 4. Run the Application

From the repository root:

```powershell
cd c:\Users\ghost\GitHub\SecureJournal
dotnet restore SecureJournal.Web\SecureJournal.Web.csproj
dotnet build SecureJournal.Web\SecureJournal.Web.csproj
dotnet run --project SecureJournal.Web
```

Open the local URL shown in the console (typically `https://localhost:xxxx`).

Recommended startup scripts (repository root):

```powershell
.\scripts\start.ps1
.\scripts\start-clean.ps1
```

The scripts:

- print the bootstrap admin credentials loaded from appsettings
- optionally delete the SQLite DB (`start-clean.ps1`)
- run the app with the local SDK workaround flags already applied

After startup:

- `/` is the start page and contains only the app name + login form
- Use `/login` for the extended local login page (including change-password form)
- Use `/admin/user-accounts` to create users
- Use `/admin/users` (`User management`) to manage roles/groups, toggle enable/disable state, delete users, and reset passwords for local users from `Manage user`
- Use `/admin/projects` and `/admin/groups` for project/group administration
- Local login and logout are antiforgery-protected (`/auth/logout` is POST-only)
- `/projects` supports project entry search + date sorting and opens full entry details at `/projects/entry/{recordId}`
- `/journal` redirects to `/projects?projectId=...` after successful entry creation
- `/audit` shows checksum and checksum-validation controls in a dedicated `Integrity` column

Hot reload during development:

```powershell
dotnet watch --project SecureJournal.Web run
```

Run with Docker Compose:

```powershell
docker compose up --build
```

Container security note:

- The container runs as non-root user `10001:10001` (rootless app process).

Example Azure script usage:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\provision-azure.ps1 `
  -SubscriptionId "<subscription-guid>" `
  -ResourceGroupName "rg-securejournal-prod" `
  -Location "eastus" `
  -NamePrefix "securejournal" `
  -OidcGroupMembershipClaims "SecurityGroup"

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\deploy-appservice.ps1 `
  -SubscriptionId "<subscription-guid>" `
  -ResourceGroupName "rg-securejournal-prod" `
  -Location "eastus" `
  -AppServicePlanName "securejournal-asp-prod" `
  -WebAppName "securejournal-web-prod" `
  -JournalEncryptionKey "<strong-encryption-key>" `
  -AdminPassword "<bootstrap-admin-password>"
```

## 5. Known Local SDK Issue (Observed in This Environment)

If you see a restore/build error similar to:

- `NU1101: Unable to find package Microsoft.AspNetCore.App.Internal.Assets`

Use this temporary build/run workaround:

```powershell
dotnet build SecureJournal.Web\SecureJournal.Web.csproj -p:RestoreIgnoreFailedSources=true
dotnet run --project SecureJournal.Web -p:RestoreIgnoreFailedSources=true
```

Note:
- `-p:RequiresAspNetWebAssets=false` can break Blazor framework asset routing (`/_framework/*.js`) and should only be used as a last-resort troubleshooting flag.

Recommended permanent fix:

- Repair/reinstall the `.NET 10 SDK`
- Ensure the ASP.NET Core web tooling/components were installed correctly

## 6. Current Prototype Scope (What Runs Today)

- Blazor Server UI scaffold
- SQLite persistence for users, projects, groups, group mappings, journal entries, and audit logs
- Bootstrap administrator seeded from appsettings on first run (and password can be synced on startup in Development)
- Encrypted journal fields stored in SQLite
- Plaintext audit details stored in SQLite with checksums
- Journal entry create + soft-delete demo workflow
- Project journal list with date sort + dedicated single-entry detail page
- Group-based project access assignment workflow (user -> group -> project)
- Role-aware UI behavior for `Administrator`, `Project User`, `Auditor`
- Administrator user lifecycle controls (enable/disable/delete)
- Local password change for the current signed-in local user (ASP.NET Identity-backed when enabled)
- Local-password reset for selected local users in `User management` (`Manage user`)
- CSV/JSON export workflows
- Automated service tests

Production-capable features now implemented in the repository:

- ASP.NET Identity local authentication (cookie-based)
- OIDC sign-in plumbing and role mapping configuration
- OIDC external identity binding using stable `iss` + `sub` claims (username collisions with local users are rejected)
- EF Core provider-backed app-data and Identity persistence (`SQLite`, `SQL Server`, `PostgreSQL`) via configuration flags
- Shared SQL database support for app-data + Identity contexts (startup can create missing context tables when no migrations are present)
- Buffered file logging toggle for troubleshooting (`Logging:File:*`)

Still recommended before production deployment:

- Add and apply explicit EF Core migrations for both contexts in your chosen provider/environment
- Add integration tests for your configured OIDC provider

