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
- sync Blazor framework JS fallback files to `SecureJournal.Web\wwwroot\_framework`
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
