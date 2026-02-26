# Local Deployment And Configuration

This page explains how to run the application locally and how to configure it, including example connection strings for SQLite, SQL Server, and PostgreSQL.

## 1. AppSettings Files

Primary configuration files:

- `SecureJournal.Web/appsettings.json`
- `SecureJournal.Web/appsettings.Development.json`
- `SecureJournal.Web/appsettings.template.json` (sanitized template)
- `SecureJournal.Web/appsettings.Development.template.json` (sanitized template)

Current repository state:

- The sample/dev setup uses `appsettings*.json` for local configuration.
- Do not commit real secrets. Prefer `dotnet user-secrets`, environment variables, or a secret manager for non-local environments.

Recommended workflow:

1. Start from the sanitized `*.template.json` files.
2. Copy values into the active `appsettings*.json` files.
3. Replace all placeholders (connection strings, encryption keys, OIDC secrets, bootstrap admin password).
4. Override sensitive values from environment variables in shared/staging/production environments.

## 2. Important Settings

### Connection Strings

- `ConnectionStrings:SecureJournalSqlite`
- `ConnectionStrings:SecureJournalSqlServer`
- `ConnectionStrings:SecureJournalPostgres`
- `ConnectionStrings:SecureJournalIdentitySqlite`
- `ConnectionStrings:SecureJournalIdentitySqlServer`
- `ConnectionStrings:SecureJournalIdentityPostgres`

### Persistence

- `Persistence:Provider` = `Sqlite` | `SqlServer` | `PostgreSql`
- `Persistence:EnableProductionAppDatabase`
- `Persistence:EnableProductionIdentityDatabase`
- `Persistence:AutoMigrateOnStartup`

### Security

- `Security:JournalEncryptionKey`
- `Security:LocalPasswordMinLength`
- `Security:LocalPasswordRequireUppercase`
- `Security:LocalPasswordRequireLowercase`
- `Security:LocalPasswordRequireDigit`
- `Security:LocalPasswordRequireNonAlphanumeric`
- `Security:SessionCookieName`
- `Security:SessionCookieHours`

### Authentication

- `Authentication:EnableLocalLogin`
- `Authentication:EnableOidc`
- `Authentication:EnableAspNetIdentity`
- `Authentication:OidcProviderName`
- `Authentication:Oidc:*`
- `Authentication:Oidc:GroupClaimType`
- `Authentication:Oidc:RoleGroupMappings:*`

### Logging

- `Logging:File:Enabled`
- `Logging:File:Path`
- `Logging:File:MinimumLevel`

### OIDC Role -> Group Mapping (Configuration)

You can predefine how external OIDC groups map to application roles.

Current config shape:

```json
{
  "Authentication": {
    "Oidc": {
      "GroupClaimType": "groups",
      "RoleGroupMappings": {
        "Administrator": [ "SecureJournal-Admins" ],
        "Auditor": [ "SecureJournal-Auditors" ],
        "ProjectUser": [ "SecureJournal-ProjectUsers", "SecureJournal-Operators" ]
      }
    }
  }
}
```

Notes:

- Keys under `RoleGroupMappings` must match application role names:
  - `Administrator`
  - `Auditor`
  - `ProjectUser`
- Values are one or more external group identifiers (name or object ID depending on your OIDC provider/claims setup).
- `GroupClaimType` defaults to `groups`.
- This configuration is used by the OIDC claims transformation to grant application roles from external group claims.
- OIDC sign-in now requires stable external identity claims (`iss` + `sub`) and an explicit mapped application role.
- Username collisions with local accounts are rejected (no username-based role inheritance).

### Bootstrap Admin

- `BootstrapAdmin:Username`
- `BootstrapAdmin:DisplayName`
- `BootstrapAdmin:Password`
- `BootstrapAdmin:SyncPasswordOnStartup`

Security note:

- Set a non-default bootstrap admin password before first use.

## 3. Connection String Examples

## SQLite (current working provider)

```json
{
  "ConnectionStrings": {
    "SecureJournalSqlite": "Data Source=securejournal.dev.db"
  }
}
```

Notes:

- With the default relative path, the DB file is created in the app working directory (typically repository root when started from scripts).
- When `Persistence:EnableProductionAppDatabase=true`, the app uses the EF Core provider-backed app-data store (same connection string family and provider switch).

## SQL Server (configuration example)

```json
{
  "ConnectionStrings": {
    "SecureJournalSqlServer": "Server=localhost;Database=SecureJournal;Trusted_Connection=True;TrustServerCertificate=True;"
  }
}
```

Alternative SQL auth example:

```json
{
  "ConnectionStrings": {
    "SecureJournalSqlServer": "Server=localhost,1433;Database=SecureJournal;User ID=securejournal;Password=ChangeMe123!;Encrypt=True;TrustServerCertificate=True;"
  }
}
```

## PostgreSQL (configuration example)

```json
{
  "ConnectionStrings": {
    "SecureJournalPostgres": "Host=localhost;Port=5432;Database=securejournal;Username=securejournal;Password=ChangeMe123!;SSL Mode=Prefer;Trust Server Certificate=true"
  }
}
```

Important:

- SQL Server and PostgreSQL values are supported through EF Core provider switching (`Persistence:Provider`).
- The same provider selection applies to the app-data store and Identity store when their corresponding enable flags are set.
- You may use the same physical database for app-data and Identity (separate EF contexts). Startup schema initialization handles missing tables per context when migrations are not yet present.

## 3.1 Production Mode (Identity + OIDC + Provider-Backed Persistence)

The repository includes a configurable production-capable stack:

- ASP.NET Core Identity (EF Core store)
- OIDC authentication (`AddOpenIdConnect`, enabled by config)
- OIDC group-to-role claims mapping (`RoleGroupMappings`)
- provider-switched app-data and Identity `DbContext` support (`Sqlite`, `SqlServer`, `PostgreSql`)
- bootstrap Identity admin seeding from `BootstrapAdmin`

Feature flags (current repository defaults are enabled for local SQLite):

```json
{
  "Persistence": {
    "EnableProductionAppDatabase": true,
    "EnableProductionIdentityDatabase": true,
    "Provider": "Sqlite",
    "AutoMigrateOnStartup": false
  },
  "Authentication": {
    "EnableAspNetIdentity": true,
    "EnableOidc": false
  }
}
```

Startup schema behavior when `Persistence:AutoMigrateOnStartup=false`:

- The app attempts EF schema creation for each context.
- If app-data and Identity share one database, startup checks for missing context tables and creates the missing schema for that context.
- Explicit EF Core migrations are still recommended for production environments.

## 4. Local Startup

Recommended:

```powershell
.\scripts\start.ps1
```

Clean DB and restart:

```powershell
.\scripts\start-clean.ps1
```

`start-clean.ps1` removes both local SQLite databases (app-data and Identity) before starting.

Manual run:

```powershell
dotnet run --project SecureJournal.Web --launch-profile https -p:RestoreIgnoreFailedSources=true -p:RequiresAspNetWebAssets=false
```

Login/logout behavior:

- Local login POST and logout POST are protected by antiforgery validation.
- Logout is POST-only (`/auth/logout`), so UI clients should submit a form instead of linking to a GET endpoint.

## 5. Login And First Use

1. Start the app.
2. Open `https://localhost:7224/` (default script profile).
3. Log in with the bootstrap admin credentials from appsettings.
4. Use admin pages to create users, groups, projects, and mappings.
5. Use `My Projects` for project-specific journal browsing/search.

## 6. Local "Deployment" (Published Output)

If you want a local publish folder build:

```powershell
dotnet publish SecureJournal.Web\SecureJournal.Web.csproj -c Release -o .artifacts\publish\web -p:RestoreIgnoreFailedSources=true -p:RequiresAspNetWebAssets=false -p:StaticWebAssetsCompressionEnabled=false
```

Run the published app locally:

```powershell
dotnet .\.artifacts\publish\web\SecureJournal.Web.dll
```

Notes:

- Copy/update `appsettings*.json` in the publish folder as needed.
- You can start from `appsettings.template.json` / `appsettings.Development.template.json` when preparing environment-specific publish configs.
- For local testing with HTTPS, prefer the built-in dev profile (`dotnet run`) and startup scripts.
- Relative file-log paths (for `Logging:File:Path`) resolve from the app content root.
- File logging is buffered and intended for troubleshooting; configure rotation/retention externally if enabled long-term.
