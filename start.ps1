[CmdletBinding()]
param(
    [switch]$CleanDb,
    [switch]$HttpOnly,
    [switch]$UseWebAssetsWorkaround
)

$ErrorActionPreference = "Stop"

$scriptPath = Join-Path $PSScriptRoot "scripts\start.ps1"

if (-not (Test-Path $scriptPath)) {
    throw "Expected startup script was not found: $scriptPath"
}

& $scriptPath `
    -CleanDb:$CleanDb `
    -HttpOnly:$HttpOnly `
    -UseWebAssetsWorkaround:$UseWebAssetsWorkaround

exit $LASTEXITCODE