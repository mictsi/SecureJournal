param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$WebAppName,

    [string]$SettingsFile = "",
    [string]$ProjectPath = "./SecureJournal.Web/SecureJournal.Web.csproj",
    [string]$Configuration = "Release",
    [string]$OutputDirectory = "./.artifacts/deploy/appservice",
    [string]$AppEnvironment = "Production",

    # Optional additional overrides: KEY=VALUE
    [string[]]$AdditionalSettings = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Az {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    $output = & az @Args
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw "Azure CLI failed (exit $code): az $($Args -join ' ')"
    }

    return $output
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & $FileName @Arguments
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw "Command failed (exit $code): $FileName $($Arguments -join ' ')"
    }
}

function Convert-ToLeafString {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return "" }
    if ($Value -is [bool]) { return $Value.ToString().ToLowerInvariant() }
    if ($Value -is [datetime]) { return $Value.ToString("o", [System.Globalization.CultureInfo]::InvariantCulture) }

    if ($Value -is [byte] -or
        $Value -is [sbyte] -or
        $Value -is [int16] -or
        $Value -is [uint16] -or
        $Value -is [int32] -or
        $Value -is [uint32] -or
        $Value -is [int64] -or
        $Value -is [uint64] -or
        $Value -is [single] -or
        $Value -is [double] -or
        $Value -is [decimal]) {
        return [Convert]::ToString($Value, [System.Globalization.CultureInfo]::InvariantCulture)
    }

    return [string]$Value
}

function Add-FlattenedSettings {
    param(
        [AllowNull()][object]$Node,
        [string]$PathPrefix,
        [hashtable]$Target
    )

    if ($null -eq $Node) {
        return
    }

    if ($Node -is [System.Collections.IDictionary]) {
        foreach ($key in $Node.Keys) {
            $segment = [string]$key
            $nextPrefix = if ([string]::IsNullOrWhiteSpace($PathPrefix)) { $segment } else { "$PathPrefix`__$segment" }
            Add-FlattenedSettings -Node $Node[$key] -PathPrefix $nextPrefix -Target $Target
        }
        return
    }

    if ($Node -is [System.Collections.IEnumerable] -and -not ($Node -is [string])) {
        $index = 0
        foreach ($item in $Node) {
            $nextPrefix = if ([string]::IsNullOrWhiteSpace($PathPrefix)) { "$index" } else { "$PathPrefix`__$index" }
            Add-FlattenedSettings -Node $item -PathPrefix $nextPrefix -Target $Target
            $index++
        }
        return
    }

    $properties = @($Node.PSObject.Properties | Where-Object { $_.MemberType -eq "NoteProperty" })
    if ($properties.Count -gt 0) {
        foreach ($property in $properties) {
            $segment = [string]$property.Name
            $nextPrefix = if ([string]::IsNullOrWhiteSpace($PathPrefix)) { $segment } else { "$PathPrefix`__$segment" }
            Add-FlattenedSettings -Node $property.Value -PathPrefix $nextPrefix -Target $Target
        }
        return
    }

    if ([string]::IsNullOrWhiteSpace($PathPrefix)) {
        return
    }

    $Target[$PathPrefix] = Convert-ToLeafString -Value $Node
}

function Test-PlaceholderValue {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $true
    }

    $trimmed = $Value.Trim()
    return $trimmed -match "^<.+>$"
}

function Test-UsableSettingValue {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    return -not (Test-PlaceholderValue -Value $Value)
}

function Test-AnyUsableSettingPresent {
    param(
        [hashtable]$SettingsMap,
        [string[]]$Keys
    )

    foreach ($key in $Keys) {
        if ($SettingsMap.ContainsKey($key)) {
            $value = [string]$SettingsMap[$key]
            if (Test-UsableSettingValue -Value $value) {
                return $true
            }
        }
    }

    return $false
}

function Resolve-SettingsFilePath {
    param([string]$ConfiguredPath)

    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

    if (-not [string]::IsNullOrWhiteSpace($ConfiguredPath)) {
        if ([System.IO.Path]::IsPathRooted($ConfiguredPath)) {
            return $ConfiguredPath
        }
        return Join-Path $repoRoot $ConfiguredPath
    }

    $candidates = @(
        (Join-Path $repoRoot "SecureJournal.Web\appsettings.Production.json"),
        (Join-Path $repoRoot "SecureJournal.Web\appsettings.json"),
        (Join-Path $repoRoot "SecureJournal.Web\appsettings.template.json")
    )

    return $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI is not installed. Install it first: https://aka.ms/installazurecliwindows"
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "dotnet SDK is not installed or not available in PATH."
}

try {
    Invoke-Az -Args @("account", "show", "--output", "none") | Out-Null
}
catch {
    throw "Azure CLI is not authenticated. Run 'az login' first."
}

Invoke-Az -Args @("account", "set", "--subscription", $SubscriptionId) | Out-Null

$resolvedSettingsFile = Resolve-SettingsFilePath -ConfiguredPath $SettingsFile
if ([string]::IsNullOrWhiteSpace($resolvedSettingsFile) -or -not (Test-Path $resolvedSettingsFile)) {
    throw "No appsettings file found. Pass -SettingsFile explicitly."
}

$projectFile = (Resolve-Path $ProjectPath).Path
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$deployRoot = Join-Path $repoRoot $OutputDirectory
$publishDir = Join-Path $deployRoot "publish"
$zipPath = Join-Path $deployRoot "$WebAppName.zip"

Write-Host "Using appsettings: $resolvedSettingsFile" -ForegroundColor Cyan
$settingsJson = Get-Content -Path $resolvedSettingsFile -Raw | ConvertFrom-Json

$settings = @{}
Add-FlattenedSettings -Node $settingsJson -PathPrefix "" -Target $settings

# Remove empty/placeholder values from source config to avoid pushing invalid placeholders.
foreach ($key in @($settings.Keys)) {
    $value = [string]$settings[$key]
    if (Test-PlaceholderValue -Value $value) {
        $settings.Remove($key) | Out-Null
    }
}

# Required runtime settings for App Service.
$settings["ASPNETCORE_ENVIRONMENT"] = $AppEnvironment
$settings["Kestrel__Endpoints__Http__Url"] = "http://+:8080"

foreach ($override in $AdditionalSettings) {
    if ([string]::IsNullOrWhiteSpace($override)) {
        continue
    }

    $separatorIndex = $override.IndexOf("=")
    if ($separatorIndex -le 0) {
        throw "Invalid AdditionalSettings item '$override'. Expected KEY=VALUE."
    }

    $key = $override.Substring(0, $separatorIndex).Trim()
    $value = $override.Substring($separatorIndex + 1)
    if ([string]::IsNullOrWhiteSpace($key)) {
        throw "Invalid AdditionalSettings item '$override'. Key cannot be empty."
    }

    $settings[$key] = $value
}

Write-Host "Verifying web app '$WebAppName' exists..." -ForegroundColor Cyan
Invoke-Az -Args @(
    "webapp", "show",
    "--resource-group", $ResourceGroupName,
    "--name", $WebAppName,
    "--output", "none"
) | Out-Null

$existingAppSettingsRaw = Invoke-Az -Args @(
    "webapp", "config", "appsettings", "list",
    "--resource-group", $ResourceGroupName,
    "--name", $WebAppName,
    "--output", "json"
)
$existingAppSettingsText = [string]::Join([Environment]::NewLine, @($existingAppSettingsRaw))
$existingAppSettings = @{}
if (-not [string]::IsNullOrWhiteSpace($existingAppSettingsText)) {
    $existingEntries = @($existingAppSettingsText | ConvertFrom-Json)
    foreach ($entry in $existingEntries) {
        if ($null -eq $entry -or [string]::IsNullOrWhiteSpace([string]$entry.name)) {
            continue
        }

        $existingAppSettings[[string]$entry.name] = Convert-ToLeafString -Value $entry.value
    }
}

# Prevent accidental key drift: encrypted journal rows require the exact same key used at write time.
$journalKeyAliases = @(
    "Security__JournalEncryptionKey",
    "SECUREJOURNAL_JOURNAL_ENCRYPTION_KEY",
    "JOURNAL_ENCRYPTION_KEY"
)
$journalKeyProvided = Test-AnyUsableSettingPresent -SettingsMap $settings -Keys $journalKeyAliases
$journalKeyAlreadyPresent = Test-AnyUsableSettingPresent -SettingsMap $existingAppSettings -Keys $journalKeyAliases
if (-not $journalKeyProvided -and -not $journalKeyAlreadyPresent) {
    throw "Missing journal encryption key. Set Security__JournalEncryptionKey in your settings file or pass -AdditionalSettings 'Security__JournalEncryptionKey=<your-key>' before deployment."
}

if (Test-Path $deployRoot) {
    Remove-Item -Path $deployRoot -Recurse -Force
}
New-Item -Path $deployRoot -ItemType Directory -Force | Out-Null

$settingsFilePath = Join-Path $deployRoot "appsettings.deploy.json"
$settings | ConvertTo-Json -Compress | Set-Content -Path $settingsFilePath -Encoding utf8

Write-Host "Applying $($settings.Keys.Count) App Service app settings..." -ForegroundColor Cyan
Invoke-Az -Args @(
    "webapp", "config", "appsettings", "set",
    "--resource-group", $ResourceGroupName,
    "--name", $WebAppName,
    "--settings", "@$settingsFilePath",
    "--output", "none"
) | Out-Null

Write-Host "Publishing app from '$projectFile' ($Configuration)..." -ForegroundColor Cyan
Invoke-External -FileName "dotnet" -Arguments @(
    "publish", $projectFile,
    "-c", $Configuration,
    "-o", $publishDir,
    "--nologo"
)

Write-Host "Packaging deployment artifact..." -ForegroundColor Cyan
Compress-Archive -Path (Join-Path $publishDir "*") -DestinationPath $zipPath -Force

Write-Host "Deploying package to App Service..." -ForegroundColor Cyan
Invoke-Az -Args @(
    "webapp", "deploy",
    "--resource-group", $ResourceGroupName,
    "--name", $WebAppName,
    "--src-path", $zipPath,
    "--type", "zip",
    "--output", "none"
) | Out-Null

$defaultHostName = (Invoke-Az -Args @(
    "webapp", "show",
    "--resource-group", $ResourceGroupName,
    "--name", $WebAppName,
    "--query", "defaultHostName",
    "--output", "tsv"
)).Trim()

$appUrl = "https://$defaultHostName"
$portalUrl = "https://portal.azure.com/#view/WebsitesExtension/WebsiteOverviewBlade/id/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$WebAppName"

Write-Host "Deployment completed successfully." -ForegroundColor Green
Write-Host "App URL: $appUrl" -ForegroundColor Green
Write-Host "Azure Portal: $portalUrl" -ForegroundColor Green
