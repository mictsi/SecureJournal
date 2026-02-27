param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$Location,

    [string]$NamePrefix = "securejournal",
    [string]$AppServicePlanName = "",
    [Parameter(Mandatory = $true)]
    [string]$WebAppName,
    [string]$AppServiceSku = "B1",
    [string]$AppServiceRuntime = "DOTNETCORE:10.0"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Az {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    $out = & az @Args
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw "Azure CLI failed (exit $code): az $($Args -join ' ')"
    }

    return $out
}

function New-RandomSuffix {
    param([int]$Length = 6)
    $chars = "abcdefghijklmnopqrstuvwxyz0123456789".ToCharArray()
    -join (1..$Length | ForEach-Object { $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)] })
}

function ConvertTo-NormalizedPrefix {
    param([string]$InputPrefix)
    $value = $InputPrefix.ToLowerInvariant()
    $value = $value -replace "[^a-z0-9-]", ""
    if ([string]::IsNullOrWhiteSpace($value)) {
        return "securejournal"
    }

    return $value
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI is not installed. Install it first: https://aka.ms/installazurecliwindows"
}

try {
    Invoke-Az -Args @("account", "show", "--output", "none") | Out-Null
}
catch {
    throw "Azure CLI is not authenticated. Run 'az login' first."
}

Invoke-Az -Args @("account", "set", "--subscription", $SubscriptionId) | Out-Null

$prefix = ConvertTo-NormalizedPrefix -InputPrefix $NamePrefix
$suffix = New-RandomSuffix

if ([string]::IsNullOrWhiteSpace($AppServicePlanName)) {
    $AppServicePlanName = "$prefix-asp-$suffix"
    if ($AppServicePlanName.Length -gt 40) {
        $AppServicePlanName = $AppServicePlanName.Substring(0, 40)
    }
}

if ($AppServicePlanName -notmatch "^[a-zA-Z0-9-]{1,40}$") {
    throw "AppServicePlanName must be 1-40 chars, letters/numbers/hyphens only."
}

$WebAppName = $WebAppName.ToLowerInvariant()
if ($WebAppName -notmatch "^[a-z0-9-]{2,60}$") {
    throw "WebAppName must be 2-60 chars, lowercase letters/numbers/hyphens only."
}

Write-Host "Creating/updating resource group '$ResourceGroupName' in '$Location'..." -ForegroundColor Cyan
Invoke-Az -Args @(
    "group", "create",
    "--name", $ResourceGroupName,
    "--location", $Location,
    "--output", "none"
) | Out-Null

Write-Host "Creating/updating App Service plan '$AppServicePlanName' (SKU: $AppServiceSku, Linux)..." -ForegroundColor Cyan
Invoke-Az -Args @(
    "appservice", "plan", "create",
    "--name", $AppServicePlanName,
    "--resource-group", $ResourceGroupName,
    "--location", $Location,
    "--sku", $AppServiceSku,
    "--is-linux",
    "--output", "none"
) | Out-Null

$webAppExists = $false
try {
    $existingName = (Invoke-Az -Args @(
        "webapp", "show",
        "--resource-group", $ResourceGroupName,
        "--name", $WebAppName,
        "--query", "name",
        "--output", "tsv"
    )).Trim()
    $webAppExists = -not [string]::IsNullOrWhiteSpace($existingName)
}
catch {
    $webAppExists = $false
}

if (-not $webAppExists) {
    Write-Host "Creating web app '$WebAppName'..." -ForegroundColor Cyan
    Invoke-Az -Args @(
        "webapp", "create",
        "--resource-group", $ResourceGroupName,
        "--plan", $AppServicePlanName,
        "--name", $WebAppName,
        "--runtime", $AppServiceRuntime,
        "--https-only", "true",
        "--output", "none"
    ) | Out-Null
}
else {
    Write-Host "Web app '$WebAppName' already exists. Reusing existing app." -ForegroundColor Yellow
}

Write-Host "Applying secure web app defaults..." -ForegroundColor Cyan
Invoke-Az -Args @(
    "webapp", "config", "set",
    "--resource-group", $ResourceGroupName,
    "--name", $WebAppName,
    "--always-on", "true",
    "--http20-enabled", "true",
    "--min-tls-version", "1.2",
    "--ftps-state", "Disabled",
    "--output", "none"
) | Out-Null

$defaultHostName = (Invoke-Az -Args @(
    "webapp", "show",
    "--resource-group", $ResourceGroupName,
    "--name", $WebAppName,
    "--query", "defaultHostName",
    "--output", "tsv"
)).Trim()

$appUrl = if ([string]::IsNullOrWhiteSpace($defaultHostName)) {
    ""
}
else {
    "https://$defaultHostName"
}

$portalUrl = "https://portal.azure.com/#view/WebsitesExtension/WebsiteOverviewBlade/id/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$WebAppName"

$result = [PSCustomObject]@{
    subscriptionId     = $SubscriptionId
    resourceGroupName  = $ResourceGroupName
    location           = $Location
    appServicePlanName = $AppServicePlanName
    webAppName         = $WebAppName
    appServiceSku      = $AppServiceSku
    appServiceRuntime  = $AppServiceRuntime
    appUrl             = $appUrl
    appServicePortalUrl= $portalUrl
}

Write-Host "Provisioning completed." -ForegroundColor Green
Write-Host "App URL: $appUrl" -ForegroundColor Green
Write-Host "Azure Portal: $portalUrl" -ForegroundColor Green
$result | ConvertTo-Json -Depth 4
