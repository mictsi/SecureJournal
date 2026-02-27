param(
    [switch]$CleanDb,
    [switch]$HttpOnly,
    [switch]$UseWebAssetsWorkaround
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot

$devSettingsPath = Join-Path $repoRoot "SecureJournal.Web\appsettings.Development.json"
$baseSettingsPath = Join-Path $repoRoot "SecureJournal.Web\appsettings.json"
$settingsPath = if (Test-Path $devSettingsPath) { $devSettingsPath } else { $baseSettingsPath }

$settings = Get-Content -Path $settingsPath -Raw | ConvertFrom-Json

function Get-SqliteDataSourceCandidates {
    param(
        [string]$ConnectionString
    )

    $candidates = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($ConnectionString)) {
        return $candidates
    }

    if ($ConnectionString -notmatch "Data Source\s*=\s*([^;]+)") {
        return $candidates
    }

    $dataSource = $Matches[1].Trim().Trim('"')
    if ([string]::IsNullOrWhiteSpace($dataSource) -or $dataSource -eq ":memory:") {
        return $candidates
    }

    if ([System.IO.Path]::IsPathRooted($dataSource)) {
        $candidates.Add($dataSource)
        return $candidates
    }

    # Current startup script runs from repo root, but older runs/manual runs may have created DBs under SecureJournal.Web.
    $candidates.Add((Join-Path $repoRoot $dataSource))
    $candidates.Add((Join-Path (Join-Path $repoRoot "SecureJournal.Web") $dataSource))
    return $candidates
}

$appSqliteConnectionString = [string]$settings.ConnectionStrings.SecureJournalSqlite
$identitySqliteConnectionString = [string]$settings.ConnectionStrings.SecureJournalIdentitySqlite

$sqliteDbPaths = @()
$sqliteDbPaths += Get-SqliteDataSourceCandidates -ConnectionString $appSqliteConnectionString
$sqliteDbPaths += Get-SqliteDataSourceCandidates -ConnectionString $identitySqliteConnectionString
$sqliteDbPaths = $sqliteDbPaths |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    ForEach-Object { [System.IO.Path]::GetFullPath($_) } |
    Select-Object -Unique

if ($CleanDb) {
    if ($sqliteDbPaths.Count -eq 0) {
        Write-Host "No SQLite database paths found in appsettings connection strings."
    }
    else {
        foreach ($path in $sqliteDbPaths) {
            if (Test-Path $path) {
                Remove-Item -Path $path -Force
                Write-Host "Deleted SQLite database: $path"
            }
            else {
                Write-Host "SQLite database not found (nothing to delete): $path"
            }
        }
    }
}

$bootstrapUsername = [string]$settings.BootstrapAdmin.Username
$bootstrapPassword = [string]$settings.BootstrapAdmin.Password
$syncPassword = [string]$settings.BootstrapAdmin.SyncPasswordOnStartup

Write-Host "Starting Secure Journal..." -ForegroundColor Cyan
Write-Host "Settings file: $settingsPath"
if ($sqliteDbPaths.Count -gt 0) {
    foreach ($path in $sqliteDbPaths) {
        Write-Host "SQLite DB:    $path"
    }
}
Write-Host "Admin user:   $bootstrapUsername"
Write-Host "Admin pass:   $bootstrapPassword"
Write-Host "Sync on boot: $syncPassword"
Write-Host ""

$useHttpsProfile = -not $HttpOnly
if ($useHttpsProfile) {
    $certCheckOutput = & dotnet dev-certs https --check 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "HTTPS development certificate check failed. You may need:" -ForegroundColor Yellow
        Write-Host "  dotnet dev-certs https --trust" -ForegroundColor Yellow
    }
    else {
        Write-Host "HTTPS dev certificate: available" -ForegroundColor Green
    }

    Write-Host "Launching with HTTPS profile (https://localhost:7224)" -ForegroundColor Cyan
} else {
    Write-Host "Launching with HTTP profile (login may be affected by redirects/security settings)." -ForegroundColor Yellow
}

$projectPath = Join-Path $repoRoot "SecureJournal.Web\SecureJournal.Web.csproj"
if ($useHttpsProfile) {
    if ($UseWebAssetsWorkaround) {
        Write-Host "Using web-assets workaround flag (may disable interactive framework assets)." -ForegroundColor Yellow
        & dotnet run --project $projectPath --launch-profile https -p:RestoreIgnoreFailedSources=true -p:RequiresAspNetWebAssets=false
    }
    else {
        & dotnet run --project $projectPath --launch-profile https -p:RestoreIgnoreFailedSources=true
    }
}
else {
    if ($UseWebAssetsWorkaround) {
        Write-Host "Using web-assets workaround flag (may disable interactive framework assets)." -ForegroundColor Yellow
        & dotnet run --project $projectPath --launch-profile http -p:RestoreIgnoreFailedSources=true -p:RequiresAspNetWebAssets=false
    }
    else {
        & dotnet run --project $projectPath --launch-profile http -p:RestoreIgnoreFailedSources=true
    }
}
exit $LASTEXITCODE

