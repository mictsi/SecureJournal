param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$Location,

    [string]$NamePrefix = "sharepass",
    [string]$StorageAccountName = "",
    [string]$KeyVaultName = "",
    [string]$AppServicePlanName = "",
    [string]$WebAppName = "",
    [string]$AppServiceSku = "B1",
    [string]$AppServiceRuntime = "DOTNETCORE:10.0",
    [switch]$SkipAppService,
    [string]$AuditTableName = "auditlogs",
    [int]$SasValidityDays = 365,

    # If provided, this principal will be granted KV read access (Secrets User)
    [string]$ExistingPrincipalObjectId = "",

    # Skip app creation; if set and ExistingPrincipalObjectId is empty, no KV reader assignment is created.
    [switch]$SkipAppRegistration,

    # Skip creating a separate OIDC app registration.
    [switch]$SkipOidcAppRegistration,

    # Base URL used to build OIDC redirect/logout callback URIs.
    [string]$OidcRedirectBaseUrl = "https://localhost:7099",

    [string]$OidcCallbackPath = "/signin-oidc",
    [string]$OidcSignedOutCallbackPath = "/signout-callback-oidc",
    # Entra app manifest groupMembershipClaims value for OIDC token group claims.
    # Common values: SecurityGroup, All, DirectoryRole, ApplicationGroup, None.
    [string]$OidcGroupMembershipClaims = "SecurityGroup",

    # If set, do not include secrets (clientSecret / SAS URL) in console output JSON.
    [switch]$NoSecretOutput
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
    if ([string]::IsNullOrWhiteSpace($value)) { $value = "sharepass" }
    return $value
}

function Join-Url {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseUrl,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
        throw "OidcRedirectBaseUrl cannot be empty."
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "OIDC path cannot be empty."
    }

    $normalizedBaseUrl = $BaseUrl.Trim()
    if ($normalizedBaseUrl.EndsWith("/")) {
        $normalizedBaseUrl = $normalizedBaseUrl.TrimEnd('/')
    }

    if ($normalizedBaseUrl -notmatch "^https?://") {
        throw "OidcRedirectBaseUrl must start with http:// or https://"
    }

    $normalizedPath = $Path.Trim()
    if (-not $normalizedPath.StartsWith('/')) {
        $normalizedPath = "/$normalizedPath"
    }

    return "$normalizedBaseUrl$normalizedPath"
}

# Ensure authenticated
try { Invoke-Az -Args @("account","show","--output","none") | Out-Null }
catch { throw "Azure CLI is not authenticated. Run 'az login' first." }

Invoke-Az -Args @("account","set","--subscription",$SubscriptionId) | Out-Null

$isKeyVaultNameExplicit = -not [string]::IsNullOrWhiteSpace($KeyVaultName)

$prefix = ConvertTo-NormalizedPrefix -InputPrefix $NamePrefix
$suffix = New-RandomSuffix

if ([string]::IsNullOrWhiteSpace($StorageAccountName)) {
    $seed = ($prefix -replace "-", "")
    if ($seed.Length -lt 3) { $seed = ($seed + "spa") }
    $StorageAccountName = ($seed + $suffix)
    if ($StorageAccountName.Length -gt 24) { $StorageAccountName = $StorageAccountName.Substring(0, 24) }
}

$StorageAccountName = $StorageAccountName.ToLowerInvariant()
if ($StorageAccountName -notmatch "^[a-z0-9]{3,24}$") {
    throw "StorageAccountName must be 3-24 chars, lowercase letters and numbers only."
}

if ([string]::IsNullOrWhiteSpace($KeyVaultName)) {
    $kvCandidate = "$prefix-kv-$suffix"
    if ($kvCandidate.Length -gt 24) { $kvCandidate = $kvCandidate.Substring(0, 24) }
    $KeyVaultName = $kvCandidate
}

$KeyVaultName = $KeyVaultName.ToLowerInvariant()
if ($KeyVaultName -notmatch "^[a-z0-9-]{3,24}$") {
    throw "KeyVaultName must be 3-24 chars, lowercase letters, numbers, and hyphens only."
}

if ([string]::IsNullOrWhiteSpace($AppServicePlanName)) {
    $AppServicePlanName = "$prefix-asp-$suffix"
    if ($AppServicePlanName.Length -gt 40) { $AppServicePlanName = $AppServicePlanName.Substring(0, 40) }
}

if ([string]::IsNullOrWhiteSpace($WebAppName)) {
    $WebAppName = "$prefix-web-$suffix"
    if ($WebAppName.Length -gt 60) { $WebAppName = $WebAppName.Substring(0, 60) }
}

if ($AppServicePlanName -notmatch "^[a-zA-Z0-9-]{1,40}$") {
    throw "AppServicePlanName must be 1-40 chars, letters/numbers/hyphens only."
}

$WebAppName = $WebAppName.ToLowerInvariant()
if ($WebAppName -notmatch "^[a-z0-9-]{2,60}$") {
    throw "WebAppName must be 2-60 chars, lowercase letters/numbers/hyphens only."
}

Write-Host "Creating resource group '$ResourceGroupName' in '$Location'..." -ForegroundColor Cyan
Invoke-Az -Args @("group","create","--name",$ResourceGroupName,"--location",$Location,"--output","none") | Out-Null

Write-Host "Creating storage account '$StorageAccountName'..." -ForegroundColor Cyan
Invoke-Az -Args @(
    "storage","account","create",
    "--name",$StorageAccountName,
    "--resource-group",$ResourceGroupName,
    "--location",$Location,
    "--sku","Standard_LRS",
    "--kind","StorageV2",
    "--https-only","true",
    "--min-tls-version","TLS1_2",
    "--allow-blob-public-access","false",
    "--output","none"
) | Out-Null

$storageKey = (Invoke-Az -Args @(
    "storage","account","keys","list",
    "--resource-group",$ResourceGroupName,
    "--account-name",$StorageAccountName,
    "--query","[0].value",
    "--output","tsv"
)).Trim()

if ([string]::IsNullOrWhiteSpace($storageKey)) { throw "Failed to retrieve storage account key." }

Write-Host "Creating table '$AuditTableName'..." -ForegroundColor Cyan
Invoke-Az -Args @(
    "storage","table","create",
    "--name",$AuditTableName,
    "--account-name",$StorageAccountName,
    "--account-key",$storageKey,
    "--output","none"
) | Out-Null

$expiry = (Get-Date).ToUniversalTime().AddDays($SasValidityDays).ToString("yyyy-MM-ddTHH\:mm\:ssZ")

# NOTE: Account SAS is broad. Keep as-is, but consider a narrower SAS if possible.
$sasToken = (Invoke-Az -Args @(
    "storage","account","generate-sas",
    "--account-name",$StorageAccountName,
    "--account-key",$storageKey,
    "--services","t",
    "--resource-types","sco",
    "--permissions","rwdlacu",
    "--expiry",$expiry,
    "--https-only",
    "--output","tsv"
)).Trim()

if ([string]::IsNullOrWhiteSpace($sasToken)) { throw "Failed to generate SAS token." }

$serviceSasUrl = "https://$StorageAccountName.table.core.windows.net/?$sasToken"

Write-Host "Creating key vault '$KeyVaultName' (RBAC enabled)..." -ForegroundColor Cyan
$existingKvResourceGroup = ""
try {
    $existingKvResourceGroup = (Invoke-Az -Args @(
        "keyvault","show",
        "--name",$KeyVaultName,
        "--query","resourceGroup",
        "--output","tsv"
    )).Trim()
} catch {
    $existingKvResourceGroup = ""
}

if (-not [string]::IsNullOrWhiteSpace($existingKvResourceGroup)) {
    if ($existingKvResourceGroup -ieq $ResourceGroupName) {
        Write-Host "Key vault '$KeyVaultName' already exists in resource group '$ResourceGroupName'. Reusing it." -ForegroundColor Yellow
    }
    else {
        if ($isKeyVaultNameExplicit) {
            throw "KeyVaultName '$KeyVaultName' already exists in resource group '$existingKvResourceGroup'. Choose a different -KeyVaultName or omit it to auto-generate a unique name."
        }

        $created = $false
        for ($attempt = 1; $attempt -le 10; $attempt++) {
            $candidateSuffix = New-RandomSuffix
            $candidateName = "$prefix-kv-$candidateSuffix"
            if ($candidateName.Length -gt 24) { $candidateName = $candidateName.Substring(0, 24) }

            $candidateExists = $false
            try {
                $existing = (Invoke-Az -Args @(
                    "keyvault","show",
                    "--name",$candidateName,
                    "--query","name",
                    "--output","tsv"
                )).Trim()
                $candidateExists = -not [string]::IsNullOrWhiteSpace($existing)
            } catch {
                $candidateExists = $false
            }

            if ($candidateExists) { continue }

            $KeyVaultName = $candidateName
            Write-Host "Key vault name already in use globally; using '$KeyVaultName' instead." -ForegroundColor Yellow
            Invoke-Az -Args @(
                "keyvault","create",
                "--name",$KeyVaultName,
                "--resource-group",$ResourceGroupName,
                "--location",$Location,
                "--enable-rbac-authorization","true",
                "--output","none"
            ) | Out-Null
            $created = $true
            break
        }

        if (-not $created) {
            throw "Could not find a unique Key Vault name after multiple attempts. Rerun with an explicit unique -KeyVaultName."
        }
    }
}
else {
    Invoke-Az -Args @(
        "keyvault","create",
        "--name",$KeyVaultName,
        "--resource-group",$ResourceGroupName,
        "--location",$Location,
        "--enable-rbac-authorization","true",
        "--output","none"
    ) | Out-Null
}

$kvId = (Invoke-Az -Args @(
    "keyvault","show",
    "--name",$KeyVaultName,
    "--resource-group",$ResourceGroupName,
    "--query","id",
    "--output","tsv"
)).Trim()

if ([string]::IsNullOrWhiteSpace($kvId)) { throw "Failed to resolve Key Vault resource id." }

$principalObjectId = $ExistingPrincipalObjectId
$appClientId = ""
$appClientSecret = ""
$tenantId = (Invoke-Az -Args @("account","show","--query","tenantId","--output","tsv")).Trim()
$appServiceUrl = ""
$appServicePortalUrl = ""

if (-not $SkipAppService) {
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
    } catch {
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
    } else {
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

    if (-not [string]::IsNullOrWhiteSpace($defaultHostName)) {
        $appServiceUrl = "https://$defaultHostName"
    }
    $appServicePortalUrl = "https://portal.azure.com/#view/WebsitesExtension/WebsiteOverviewBlade/id/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$WebAppName"
}

if (-not $PSBoundParameters.ContainsKey("OidcRedirectBaseUrl") -and -not [string]::IsNullOrWhiteSpace($appServiceUrl)) {
    $OidcRedirectBaseUrl = $appServiceUrl
    Write-Host "Using App Service URL for OIDC redirect base: $OidcRedirectBaseUrl" -ForegroundColor Cyan
}

$oidcAuthority = "https://login.microsoftonline.com/$tenantId/v2.0"
$oidcRedirectUri = Join-Url -BaseUrl $OidcRedirectBaseUrl -Path $OidcCallbackPath
$oidcPostLogoutRedirectUri = Join-Url -BaseUrl $OidcRedirectBaseUrl -Path $OidcSignedOutCallbackPath
$oidcAppClientId = ""
$oidcAppClientSecret = ""

if ([string]::IsNullOrWhiteSpace($principalObjectId) -and -not $SkipAppRegistration) {
    $appDisplayName = "$prefix-app-$suffix"

    Write-Host "Creating Microsoft Entra app registration '$appDisplayName'..." -ForegroundColor Cyan
    $appClientId = (Invoke-Az -Args @(
        "ad","app","create",
        "--display-name",$appDisplayName,
        "--sign-in-audience","AzureADMyOrg",
        "--query","appId",
        "--output","tsv"
    )).Trim()

    if ([string]::IsNullOrWhiteSpace($appClientId)) { throw "Failed to create app registration." }

    Invoke-Az -Args @("ad","sp","create","--id",$appClientId,"--output","none") | Out-Null

    # Poll for SP availability
    $deadline = (Get-Date).AddMinutes(2)
    do {
        try {
            $principalObjectId = (Invoke-Az -Args @("ad","sp","show","--id",$appClientId,"--query","id","--output","tsv")).Trim()
        } catch { $principalObjectId = "" }

        if (-not [string]::IsNullOrWhiteSpace($principalObjectId)) { break }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)

    if ([string]::IsNullOrWhiteSpace($principalObjectId)) {
        throw "Failed to resolve service principal object id within timeout."
    }

    $appClientSecret = (Invoke-Az -Args @(
        "ad","app","credential","reset",
        "--id",$appClientId,
        "--append",
        "--display-name","securejournal",
        "--years","2",
        "--query","password",
        "--output","tsv"
    )).Trim()

    if ([string]::IsNullOrWhiteSpace($appClientSecret)) { throw "Failed to create client secret for app registration." }
}

if (-not $SkipOidcAppRegistration) {
    $oidcAppDisplayName = "$prefix-oidc-$suffix"

    Write-Host "Creating dedicated Microsoft Entra OIDC app registration '$oidcAppDisplayName'..." -ForegroundColor Cyan
    $oidcAppClientId = (Invoke-Az -Args @(
        "ad","app","create",
        "--display-name",$oidcAppDisplayName,
        "--sign-in-audience","AzureADMyOrg",
        "--web-redirect-uris",$oidcRedirectUri,$oidcPostLogoutRedirectUri,
        "--query","appId",
        "--output","tsv"
    )).Trim()

    if ([string]::IsNullOrWhiteSpace($oidcAppClientId)) { throw "Failed to create OIDC app registration." }

    $oidcAppClientSecret = (Invoke-Az -Args @(
        "ad","app","credential","reset",
        "--id",$oidcAppClientId,
        "--append",
        "--display-name","securejournal-oidc",
        "--years","2",
        "--query","password",
        "--output","tsv"
    )).Trim()

    if ([string]::IsNullOrWhiteSpace($oidcAppClientSecret)) { throw "Failed to create client secret for OIDC app registration." }

    if (-not [string]::IsNullOrWhiteSpace($OidcGroupMembershipClaims) -and -not ($OidcGroupMembershipClaims -ieq "None")) {
        Write-Host "Configuring OIDC app group claims: groupMembershipClaims='$OidcGroupMembershipClaims'..." -ForegroundColor Cyan
        Invoke-Az -Args @(
            "ad","app","update",
            "--id",$oidcAppClientId,
            "--set","groupMembershipClaims=$OidcGroupMembershipClaims",
            "--output","none"
        ) | Out-Null
    }
}

# RBAC: grant the app/principal secret read/write access required by the app
if (-not [string]::IsNullOrWhiteSpace($principalObjectId)) {
    Write-Host "Assigning 'Key Vault Secrets Officer' on vault to principal '$principalObjectId'..." -ForegroundColor Cyan
    Invoke-Az -Args @(
        "role","assignment","create",
        "--assignee-object-id",$principalObjectId,
        "--assignee-principal-type","ServicePrincipal",
        "--role","Key Vault Secrets Officer",
        "--scope",$kvId,
        "--output","none"
    ) | Out-Null
}

$keyVaultUri = "https://$KeyVaultName.vault.azure.net/"

$result = [PSCustomObject]@{
    resourceGroupName = $ResourceGroupName
    location          = $Location
    storageAccountName= $StorageAccountName
    auditTableName    = $AuditTableName
    keyVaultName      = $KeyVaultName
    keyVaultUri       = $keyVaultUri
    keyVaultResourceId= $kvId
    appServicePlanName= $(if ($SkipAppService) { "" } else { $AppServicePlanName })
    webAppName        = $(if ($SkipAppService) { "" } else { $WebAppName })
    appServiceUrl     = $(if ($SkipAppService) { "" } else { $appServiceUrl })
    appServicePortalUrl = $(if ($SkipAppService) { "" } else { $appServicePortalUrl })
    azureTableServiceSasUrl = $(if ($NoSecretOutput) { "" } else { $serviceSasUrl })
    servicePrincipalObjectId = $principalObjectId
    tenantId          = $tenantId
    clientId          = $appClientId
    clientSecret      = $(if ($NoSecretOutput) { "" } else { $appClientSecret })
    oidcAuthority     = $oidcAuthority
    oidcClientId      = $oidcAppClientId
    oidcClientSecret  = $(if ($NoSecretOutput) { "" } else { $oidcAppClientSecret })
    oidcGroupMembershipClaims = $(if ([string]::IsNullOrWhiteSpace($oidcAppClientId)) { "" } else { $OidcGroupMembershipClaims })
    oidcRedirectBaseUrl = $OidcRedirectBaseUrl
    oidcRedirectUri   = $oidcRedirectUri
    oidcPostLogoutRedirectUri = $oidcPostLogoutRedirectUri
    appEnvironmentVariables = [PSCustomObject]@{
        Authentication__EnableOidc               = $(if ([string]::IsNullOrWhiteSpace($oidcAppClientId)) { "false" } else { "true" })
        Authentication__Oidc__Authority          = $oidcAuthority
        Authentication__Oidc__ClientId           = $oidcAppClientId
        Authentication__Oidc__ClientSecret       = $(if ($NoSecretOutput) { "" } else { $oidcAppClientSecret })
        Authentication__Oidc__CallbackPath       = $OidcCallbackPath
        Authentication__Oidc__GroupClaimType     = "groups"
        Authentication__OidcProviderName         = "Microsoft Entra ID"
    }
}

Write-Host "Provisioning completed." -ForegroundColor Green
Write-Host "App configuration values:" -ForegroundColor Yellow
Write-Host "  AzureKeyVault__VaultUri=$keyVaultUri"
Write-Host "  AzureKeyVault__TenantId=$tenantId"
Write-Host "  AzureKeyVault__ClientId=$appClientId"
Write-Host "  AzureKeyVault__ClientSecret=$(if ($NoSecretOutput) { '<hidden>' } else { $appClientSecret })"
Write-Host "  AzureTableAudit__ServiceSasUrl=$(if ($NoSecretOutput) { '<hidden>' } else { $serviceSasUrl })"
Write-Host "  AzureTableAudit__TableName=$AuditTableName"
Write-Host "  AzureTableAudit__PartitionKey=audit"
if (-not $SkipAppService) {
    Write-Host "  AppServicePlanName=$AppServicePlanName"
    Write-Host "  WebAppName=$WebAppName"
    Write-Host "  AppServiceUrl=$appServiceUrl"
    Write-Host "  AppServicePortalUrl=$appServicePortalUrl"
}
Write-Host "  Authentication__EnableOidc=$(if ([string]::IsNullOrWhiteSpace($oidcAppClientId)) { 'false' } else { 'true' })"
Write-Host "  Authentication__Oidc__Authority=$oidcAuthority"
Write-Host "  Authentication__Oidc__ClientId=$oidcAppClientId"
Write-Host "  Authentication__Oidc__ClientSecret=$(if ($NoSecretOutput) { '<hidden>' } else { $oidcAppClientSecret })"
Write-Host "  Authentication__Oidc__CallbackPath=$OidcCallbackPath"
Write-Host "  Authentication__Oidc__GroupClaimType=groups"
Write-Host "  OIDC app groupMembershipClaims=$(if ([string]::IsNullOrWhiteSpace($oidcAppClientId)) { '<not-configured>' } else { $OidcGroupMembershipClaims })"
Write-Host "  OIDC redirect URI: $oidcRedirectUri"
Write-Host "  OIDC post-logout redirect URI: $oidcPostLogoutRedirectUri"
$result | ConvertTo-Json -Depth 6
