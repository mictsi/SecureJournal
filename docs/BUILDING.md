# Building Secure Journal

## Prerequisites

- `.NET SDK 10.0.402` or a later servicing patch in that feature band (`global.json`)
- PowerShell (examples below use Windows PowerShell/PowerShell)
- Optional: trusted local HTTPS dev certificate
  - `dotnet dev-certs https --trust`

## Repository Layout (Current)

Package versions are maintained in `Directory.Packages.props`, including transitive
pins. Restore the checked-in lockfiles with `dotnet restore SecureJournal.Tests/SecureJournal.Tests.csproj --locked-mode`.
All NuGet vulnerability severities are audited; advisories and an unavailable audit
feed fail restore. Updating a dependency requires regenerating and reviewing the
lockfiles. Microsoft.Build.Framework and Microsoft.NET.StringTools remain on
18.9.6, the newest versions supporting .NET 10; 18.10 and later require .NET 11.

Frontend asset integrity is checked with `python3 scripts/verify-frontend-assets.py`.
The pinned TinyMCE distribution includes a rebuilt DOMPurify module because the
upstream editor release bundles an older sanitizer. Its exact source hashes,
licenses, and reproducible build instructions are in
`SecureJournal.Web/wwwroot/lib/tinymce/THIRD-PARTY-BUILD.txt` and `scripts/frontend/`.
Run `npm --prefix scripts/frontend audit --audit-level=low` to audit that build
tooling. A TinyMCE or DOMPurify update must regenerate the bundle and its integrity
manifest; simply changing a package version is insufficient.

To rebuild the patched editor after restoring the pinned NuGet package:

```sh
npm ci --ignore-scripts --prefix scripts/frontend
python3 scripts/verify-frontend-assets.py --sync-tinymce
python3 scripts/verify-frontend-assets.py
npm exec --prefix scripts/frontend -- playwright install chromium
npm run test:sanitizer --prefix scripts/frontend
```

The container uses .NET 10.0.13 on Alpine 3.24 with ICU and timezone data, runs
as UID/GID 10001, and retains SQLite's Linux-musl native asset. Rebuild with
`docker build --pull` to refresh the base image when security updates are released.

- `SecureJournal.Core/` - shared domain/application contracts
- `SecureJournal.Web/` - Blazor Server app
- `SecureJournal.Tests/` - xUnit tests (service tests + integration tests)
- `scripts/` - local startup + deployment helpers

## Configuration Templates

Sanitized config templates are included for bootstrapping environments:

- `SecureJournal.Web/appsettings.template.json`
- `SecureJournal.Web/appsettings.Development.template.json`

Copy values from the templates into the active `appsettings*.json` files and replace placeholders before running.

## Restore / Build

From the repository root:

```powershell
dotnet restore SecureJournal.Tests\SecureJournal.Tests.csproj --locked-mode
dotnet build SecureJournal.Web\SecureJournal.Web.csproj --no-restore
```

## Tests

After restoring the test project above, run:

```powershell
dotnet test SecureJournal.Tests\SecureJournal.Tests.csproj --no-restore -m:1 --logger "console;verbosity=minimal"
```

Notes:

- The test project is located at the repository root (`SecureJournal.Tests/`).
- Project references build the application automatically. Use the SDK selected by
  `global.json`; the previous web-assets workaround is no longer necessary.
- Provider compatibility tests exercise SQLite storage, SQL Server/PostgreSQL SQL
  generation, and Azure authentication-provider loading. They do not replace tests
  against your deployed SQL Server or PostgreSQL database.

## Hot Reload

```powershell
dotnet watch --project SecureJournal.Web run
```

## Recommended Local Start Scripts

```powershell
.\scripts\start.ps1
.\scripts\start-clean.ps1
```

These scripts:

- load appsettings
- show the bootstrap administrator username without printing its password
- optionally delete the SQLite DB (`start-clean.ps1`)
- delete both local SQLite databases (`SecureJournal` app DB + `Identity` DB) when using `start-clean.ps1`
- restore locked dependencies with vulnerability auditing, then run the app

Runtime hotfix notes:

- The app now exposes `GET /health` with `200 OK` for App Service Health Check probes.
- Authentication middleware is activated only when Identity auth + Identity DB are both enabled, avoiding startup crashes in non-identity configurations.

## Optional Troubleshooting File Logging

You can enable buffered file logging for local troubleshooting:

```json
{
  "Logging": {
    "File": {
      "Enabled": true,
      "Path": "logs/securejournal.dev.log",
      "MinimumLevel": "Debug"
    }
  }
}
```

The logger writes asynchronously using a buffered queue and periodic flushes to reduce request-path I/O overhead.

## Continuous Build And Security Checks

The pull-request/push workflow also runs weekly to catch new advisories:

- `.github/workflows/ci.yml`
- `.github/workflows/tag-build.yml`

Both workflows restore locked NuGet dependencies, audit frontend maintenance
packages, verify bundled assets, run tests, build the final Docker image, and scan
it with the pinned, checksum-verified Trivy release. The image scan includes all
severities and unfixed findings; findings or scanner failures prevent publishing.
The pull-request workflow also runs browser sanitizer regressions. The tag workflow
runs on `v*` tags (for example `v0.8.0`) and uploads the published web artifact.

## Docker Build

Build image from repository root:

```powershell
docker build -t securejournal:local .
```

Run with explicit environment values:

```powershell
docker run --rm -p 8080:8080 `
  -e Security__JournalEncryptionKey="replace-with-strong-key" `
  -e BootstrapAdmin__Password="ChangeMe123!" `
  securejournal:local
```

Rootless container runtime:

- The image runs as non-root user `10001:10001`.
- For custom host bind-mounts, ensure the target directories are writable by `UID/GID 10001`.

## Azure App Service Scripts

Provision Azure resources and Entra app registrations:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\provision-azure.ps1 `
  -SubscriptionId "<subscription-guid>" `
  -ResourceGroupName "rg-securejournal-prod" `
  -Location "eastus" `
  -NamePrefix "securejournal" `
  -OidcGroupMembershipClaims "SecurityGroup"
```

Deploy application package to App Service:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\deploy-appservice.ps1 `
  -SubscriptionId "<subscription-guid>" `
  -ResourceGroupName "rg-securejournal-prod" `
  -Location "eastus" `
  -AppServicePlanName "securejournal-asp-prod" `
  -WebAppName "securejournal-web-prod" `
  -JournalEncryptionKey "<strong-encryption-key>" `
  -AdminPassword "<bootstrap-admin-password>"
```

## Generate Env Vars From AppSettings

Use the helper script to flatten `appsettings*.json` into environment variables:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\generate-env-from-appsettings.ps1 `
  -AppSettingsPath SecureJournal.Web\appsettings.template.json `
  -Format dotenv `
  -OutputPath .artifacts\generated\securejournal.env
```

PowerShell export format:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\generate-env-from-appsettings.ps1 `
  -Format powershell `
  -OutputPath .artifacts\generated\securejournal.env.ps1
```

## Release Artifact (Local)

You can produce a local release artifact zip from the repository root:

```powershell
dotnet restore SecureJournal.Web\SecureJournal.Web.csproj --locked-mode
dotnet publish SecureJournal.Web\SecureJournal.Web.csproj -c Release -o .artifacts\publish\web --no-restore
Compress-Archive -Path .artifacts\publish\web\* -DestinationPath .artifacts\releases\securejournal-web-v0.8.0.zip -Force
```

This zip is suitable for attaching to a GitHub release.
