param(
    [string]$AppSettingsPath,
    [ValidateSet("dotenv", "powershell")]
    [string]$Format = "dotenv",
    [string]$OutputPath,
    [string]$Prefix = "",
    [switch]$IncludeEmptyValues
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot

if ([string]::IsNullOrWhiteSpace($AppSettingsPath)) {
    $candidatePaths = @(
        (Join-Path $repoRoot "SecureJournal.Web\appsettings.Development.json"),
        (Join-Path $repoRoot "SecureJournal.Web\appsettings.json"),
        (Join-Path $repoRoot "SecureJournal.Web\appsettings.Development.template.json"),
        (Join-Path $repoRoot "SecureJournal.Web\appsettings.template.json")
    )

    $AppSettingsPath = $candidatePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
}
elseif (-not [System.IO.Path]::IsPathRooted($AppSettingsPath)) {
    $AppSettingsPath = Join-Path $repoRoot $AppSettingsPath
}

if (-not (Test-Path $AppSettingsPath)) {
    throw "AppSettings file not found: $AppSettingsPath"
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = if ($Format -eq "powershell") {
        Join-Path $repoRoot ".env.ps1"
    }
    else {
        Join-Path $repoRoot ".env"
    }
}
elseif (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath = Join-Path $repoRoot $OutputPath
}

$raw = Get-Content -Path $AppSettingsPath -Raw
$json = $raw | ConvertFrom-Json

$entries = New-Object System.Collections.Generic.List[object]

function Convert-ToLeafString {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ""
    }

    if ($Value -is [bool]) {
        return $Value.ToString().ToLowerInvariant()
    }

    if ($Value -is [datetime]) {
        return $Value.ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
    }

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

function Add-FlattenedEntries {
    param(
        [AllowNull()]
        [object]$Node,
        [string]$PathPrefix
    )

    if ($null -eq $Node) {
        if ($IncludeEmptyValues -and -not [string]::IsNullOrWhiteSpace($PathPrefix)) {
            $entries.Add([PSCustomObject]@{
                    Key   = $PathPrefix
                    Value = ""
                })
        }
        return
    }

    if ($Node -is [System.Collections.IDictionary]) {
        foreach ($key in $Node.Keys) {
            $segment = [string]$key
            $nextPrefix = if ([string]::IsNullOrWhiteSpace($PathPrefix)) { $segment } else { "$PathPrefix`__$segment" }
            Add-FlattenedEntries -Node $Node[$key] -PathPrefix $nextPrefix
        }
        return
    }

    if ($Node -is [System.Collections.IEnumerable] -and -not ($Node -is [string])) {
        $index = 0
        foreach ($item in $Node) {
            $nextPrefix = if ([string]::IsNullOrWhiteSpace($PathPrefix)) { "$index" } else { "$PathPrefix`__$index" }
            Add-FlattenedEntries -Node $item -PathPrefix $nextPrefix
            $index++
        }
        return
    }

    $properties = $Node.PSObject.Properties | Where-Object { $_.MemberType -eq "NoteProperty" }
    if ($properties.Count -gt 0) {
        foreach ($property in $properties) {
            $segment = [string]$property.Name
            $nextPrefix = if ([string]::IsNullOrWhiteSpace($PathPrefix)) { $segment } else { "$PathPrefix`__$segment" }
            Add-FlattenedEntries -Node $property.Value -PathPrefix $nextPrefix
        }
        return
    }

    if ([string]::IsNullOrWhiteSpace($PathPrefix)) {
        return
    }

    $leafValue = Convert-ToLeafString -Value $Node
    if (-not $IncludeEmptyValues -and [string]::IsNullOrEmpty($leafValue)) {
        return
    }

    $entries.Add([PSCustomObject]@{
            Key   = $PathPrefix
            Value = $leafValue
        })
}

Add-FlattenedEntries -Node $json -PathPrefix ""

$sorted = $entries | Sort-Object Key -Unique

if ($Prefix) {
    $sorted = $sorted | ForEach-Object {
        [PSCustomObject]@{
            Key   = "$Prefix$($_.Key)"
            Value = $_.Value
        }
    }
}

function Convert-ToDotEnvValue {
    param([string]$Value)

    if ($null -eq $Value) {
        return ""
    }

    $needsQuotes = $Value -match "[\s#=]|^$"
    if (-not $needsQuotes) {
        return $Value
    }

    $escaped = $Value.Replace("\", "\\").Replace("`r", "\r").Replace("`n", "\n").Replace('"', '\"')
    return """$escaped"""
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# Generated from $AppSettingsPath")
$lines.Add("# Format: $Format")
$lines.Add("# Generated at: $(Get-Date -Format "yyyy-MM-dd HH:mm:ssK")")

if ($Format -eq "powershell") {
    $lines.Add("")
    foreach ($entry in $sorted) {
        $valueText = if ($null -eq $entry.Value) { "" } else { [string]$entry.Value }
        $safeValue = $valueText.Replace("'", "''")
        $lines.Add("`$env:$($entry.Key) = '$safeValue'")
    }
}
else {
    $lines.Add("")
    foreach ($entry in $sorted) {
        $lines.Add("$($entry.Key)=$(Convert-ToDotEnvValue -Value $entry.Value)")
    }
}

$outputDirectory = Split-Path -Path $OutputPath -Parent
if ($outputDirectory -and -not (Test-Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

$lines | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host "Generated $($sorted.Count) env entries from: $AppSettingsPath" -ForegroundColor Green
Write-Host "Output file: $OutputPath" -ForegroundColor Green
