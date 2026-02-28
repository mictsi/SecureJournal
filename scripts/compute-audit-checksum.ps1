param(
    [Parameter(Mandatory = $true)]
    [string]$TimestampUtc,

    [Parameter(Mandatory = $true)]
    [string]$User,

    [Parameter(Mandatory = $true)]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [string]$Entity,

    [string]$EntityId = "",

    [string]$Project = "",

    [Parameter(Mandatory = $true)]
    [string]$Outcome,

    [Parameter(Mandatory = $true)]
    [string]$Details,

    [switch]$ShowMaterial
)

$ErrorActionPreference = "Stop"

function Normalize-Value {
    param([string]$Value)

    if ($null -eq $Value) {
        return ""
    }

    return $Value.Trim().Normalize([Text.NormalizationForm]::FormKC)
}

$utcTimestamp = [DateTime]::Parse(
    $TimestampUtc,
    [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::RoundtripKind
).ToUniversalTime().ToString("O", [Globalization.CultureInfo]::InvariantCulture)

$separator = [char]0x1F
$material = [string]::Join($separator, @(
    $utcTimestamp,
    (Normalize-Value $User),
    (Normalize-Value $Action),
    (Normalize-Value $Entity),
    (Normalize-Value $EntityId),
    (Normalize-Value $Project),
    (Normalize-Value $Outcome),
    (Normalize-Value $Details)
))

$hashBytes = [System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($material))
$checksum = [Convert]::ToHexString($hashBytes)

Write-Output "Checksum: $checksum"

if ($ShowMaterial) {
    Write-Output "Material: $material"
}
