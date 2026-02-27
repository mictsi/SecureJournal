# Building Secure Journal

## Prerequisites

- `.NET 10 SDK` (`10.0.x`)
- PowerShell (examples below use Windows PowerShell/PowerShell)
- Optional: trusted local HTTPS dev certificate
  - `dotnet dev-certs https --trust`

## Repository Layout (Current)

- `SecureJournal.Core/` - shared domain/application contracts
- `SecureJournal.Web/` - Blazor Server app
- `SecureJournal.Tests/` - xUnit tests (service tests + integration tests)
- `scripts/` - local startup helpers

## Configuration Templates

Sanitized config templates are included for bootstrapping environments:

- `SecureJournal.Web/appsettings.template.json`
- `SecureJournal.Web/appsettings.Development.template.json`

Copy values from the templates into the active `appsettings*.json` files and replace placeholders before running.

## Restore / Build

From the repository root:

```powershell
dotnet restore SecureJournal.Web\SecureJournal.Web.csproj
dotnet build SecureJournal.Web\SecureJournal.Web.csproj
```

## Build With Local SDK Workaround (This Environment)

If you hit the local `.NET 10` web assets issue (`Microsoft.AspNetCore.App.Internal.Assets`), use:

```powershell
dotnet build SecureJournal.Web\SecureJournal.Web.csproj -p:RestoreIgnoreFailedSources=true -p:RequiresAspNetWebAssets=false -o .artifacts\verify-build
```

## Tests

Build the web project first (because tests reference `.artifacts\verify-build` DLLs), then run:

```powershell
dotnet test SecureJournal.Tests\SecureJournal.Tests.csproj -m:1 --logger "console;verbosity=minimal" -p:RestoreIgnoreFailedSources=true
```

Notes:

- The test project is located at the repository root (`SecureJournal.Tests/`).
- Some local environments may require compiling the web project first if test assembly references are resolved from local build outputs.

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
- print bootstrap admin credentials
- optionally delete the SQLite DB (`start-clean.ps1`)
- delete both local SQLite databases (`SecureJournal` app DB + `Identity` DB) when using `start-clean.ps1`
- run the app with the local SDK workaround flags

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

## CI Tag Build Workflow

This repository includes a GitHub Actions workflow:

- `.github/workflows/tag-build.yml`

Trigger:

- Push of a new git tag matching `v*` (for example `v0.4.0`)

Workflow behavior:

- Restore + build web project
- Run tests
- Publish web output
- Upload published output as a workflow artifact

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
dotnet publish SecureJournal.Web\SecureJournal.Web.csproj -c Release -o .artifacts\publish\web -p:RestoreIgnoreFailedSources=true -p:RequiresAspNetWebAssets=false
Compress-Archive -Path .artifacts\publish\web\* -DestinationPath .artifacts\releases\securejournal-web-v0.3.0.zip -Force
```

This zip is suitable for attaching to a GitHub release.
