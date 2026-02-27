param(
	[Parameter(Mandatory = $true)]
	[string]$SubscriptionId,

	[Parameter(Mandatory = $true)]
	[string]$ResourceGroupName,

	[Parameter(Mandatory = $true)]
	[string]$Location,

	[Parameter(Mandatory = $true)]
	[string]$AppServicePlanName,

	[Parameter(Mandatory = $true)]
	[string]$WebAppName,

	[string]$SettingsFile = "./SecureJournal.Web/appsettings.template.json",

	[string]$AdminPassword,

	[string]$ProjectPath = "./SecureJournal.Web/SecureJournal.Web.csproj",
	[string]$Configuration = "Release",
	[string]$OutputDirectory = "./.artifacts/deploy/appservice",
	[string]$Sku = "B1",
	[string]$Runtime = "DOTNETCORE:10.0",
	[string]$AppEnvironment = "Production",

	[string]$AdminUsername = "admin",
	[string]$AdminDisplayName = "Startup Administrator",
	[string]$JournalEncryptionKey = "",

	[bool]$OidcEnabled = $false,
	[string]$OidcAuthority = "",
	[string]$OidcClientId = "",
	[string]$OidcClientSecret = "",
	[bool]$OidcRequireHttpsMetadata = $true,
	[string]$OidcCallbackPath = "/signin-oidc",
	[string]$OidcGroupClaimType = "groups",
	[string[]]$OidcAdminGroups = @(),
	[string[]]$OidcAuditorGroups = @(),
	[string[]]$OidcProjectUserGroups = @(),

	[bool]$EnableLocalLogin = $true,
	[bool]$EnableAspNetIdentity = $true,
	[bool]$ConsoleAuditLoggingEnabled = $true,
	[bool]$SqlQueryLoggingEnabled = $false,
	[string]$LoggingDefaultLevel = "Information",
	[string]$LoggingMicrosoftAspNetCoreLevel = "Warning"
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

function Invoke-CommandStrict {
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

function Get-JsonValue {
	param(
		[Parameter(Mandatory = $true)]
		[object]$Root,
		[Parameter(Mandatory = $true)]
		[string]$Path
	)

	$current = $Root
	foreach ($segment in $Path.Split('.')) {
		if ($null -eq $current) {
			return $null
		}

		$property = $current.PSObject.Properties[$segment]
		if ($null -eq $property) {
			return $null
		}

		$current = $property.Value
	}

	return $current
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
	throw "Azure CLI is not installed. Install it first: https://aka.ms/installazurecliwindows"
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
	throw "dotnet SDK is not installed or not available in PATH."
}

$settingsJson = $null
if (-not [string]::IsNullOrWhiteSpace($SettingsFile) -and (Test-Path $SettingsFile)) {
	$settingsPath = (Resolve-Path $SettingsFile).Path
	Write-Host "Loading settings from '$settingsPath'..." -ForegroundColor Cyan
	$settingsJson = Get-Content -Path $settingsPath -Raw | ConvertFrom-Json

	$bootstrapUsername = Get-JsonValue -Root $settingsJson -Path "BootstrapAdmin.Username"
	$bootstrapDisplayName = Get-JsonValue -Root $settingsJson -Path "BootstrapAdmin.DisplayName"
	$bootstrapPassword = Get-JsonValue -Root $settingsJson -Path "BootstrapAdmin.Password"
	$legacyAdminUsername = Get-JsonValue -Root $settingsJson -Path "AdminAuth.Username"
	$legacyAdminPassword = Get-JsonValue -Root $settingsJson -Path "AdminAuth.Password"
	$journalEncryptionKey = Get-JsonValue -Root $settingsJson -Path "Security.JournalEncryptionKey"
	$legacyEncryptionPassphrase = Get-JsonValue -Root $settingsJson -Path "Encryption.Passphrase"
	$enableLocalLoginSetting = Get-JsonValue -Root $settingsJson -Path "Authentication.EnableLocalLogin"
	$enableAspNetIdentitySetting = Get-JsonValue -Root $settingsJson -Path "Authentication.EnableAspNetIdentity"
	$enableOidcSetting = Get-JsonValue -Root $settingsJson -Path "Authentication.EnableOidc"
	$legacyEnableOidcSetting = Get-JsonValue -Root $settingsJson -Path "OidcAuth.Enabled"
	$oidcAuthoritySetting = Get-JsonValue -Root $settingsJson -Path "Authentication.Oidc.Authority"
	$legacyOidcAuthoritySetting = Get-JsonValue -Root $settingsJson -Path "OidcAuth.Authority"
	$oidcClientIdSetting = Get-JsonValue -Root $settingsJson -Path "Authentication.Oidc.ClientId"
	$legacyOidcClientIdSetting = Get-JsonValue -Root $settingsJson -Path "OidcAuth.ClientId"
	$oidcClientSecretSetting = Get-JsonValue -Root $settingsJson -Path "Authentication.Oidc.ClientSecret"
	$legacyOidcClientSecretSetting = Get-JsonValue -Root $settingsJson -Path "OidcAuth.ClientSecret"
	$oidcCallbackPathSetting = Get-JsonValue -Root $settingsJson -Path "Authentication.Oidc.CallbackPath"
	$legacyOidcCallbackPathSetting = Get-JsonValue -Root $settingsJson -Path "OidcAuth.CallbackPath"
	$oidcRequireHttpsMetadataSetting = Get-JsonValue -Root $settingsJson -Path "Authentication.Oidc.RequireHttpsMetadata"
	$legacyOidcRequireHttpsMetadataSetting = Get-JsonValue -Root $settingsJson -Path "OidcAuth.RequireHttpsMetadata"
	$oidcGroupClaimTypeSetting = Get-JsonValue -Root $settingsJson -Path "Authentication.Oidc.GroupClaimType"
	$legacyOidcGroupClaimTypeSetting = Get-JsonValue -Root $settingsJson -Path "OidcAuth.GroupClaimType"
	$oidcAdminGroupsSetting = Get-JsonValue -Root $settingsJson -Path "Authentication.Oidc.RoleGroupMappings.Administrator"
	$oidcAuditorGroupsSetting = Get-JsonValue -Root $settingsJson -Path "Authentication.Oidc.RoleGroupMappings.Auditor"
	$oidcProjectUserGroupsSetting = Get-JsonValue -Root $settingsJson -Path "Authentication.Oidc.RoleGroupMappings.ProjectUser"
	$consoleLoggingEnabledSetting = Get-JsonValue -Root $settingsJson -Path "Logging.Console.Enabled"
	$sqlQueryLoggingEnabledSetting = Get-JsonValue -Root $settingsJson -Path "Logging.SqlQueries.Enabled"
	$loggingDefaultLevelSetting = Get-JsonValue -Root $settingsJson -Path "Logging.LogLevel.Default"
	$loggingAspNetCoreLevelSetting = Get-JsonValue -Root $settingsJson -Path "Logging.LogLevel.Microsoft.AspNetCore"

	if (-not $PSBoundParameters.ContainsKey("AdminUsername")) {
		if ($bootstrapUsername) { $AdminUsername = [string]$bootstrapUsername }
		elseif ($legacyAdminUsername) { $AdminUsername = [string]$legacyAdminUsername }
	}
	if (-not $PSBoundParameters.ContainsKey("AdminDisplayName") -and $bootstrapDisplayName) {
		$AdminDisplayName = [string]$bootstrapDisplayName
	}
	if (-not $PSBoundParameters.ContainsKey("AdminPassword")) {
		if ($bootstrapPassword) { $AdminPassword = [string]$bootstrapPassword }
		elseif ($legacyAdminPassword) { $AdminPassword = [string]$legacyAdminPassword }
	}
	if (-not $PSBoundParameters.ContainsKey("JournalEncryptionKey")) {
		if ($journalEncryptionKey) { $JournalEncryptionKey = [string]$journalEncryptionKey }
		elseif ($legacyEncryptionPassphrase) { $JournalEncryptionKey = [string]$legacyEncryptionPassphrase }
	}

	if (-not $PSBoundParameters.ContainsKey("EnableLocalLogin") -and $enableLocalLoginSetting -ne $null) {
		$EnableLocalLogin = [bool]$enableLocalLoginSetting
	}
	if (-not $PSBoundParameters.ContainsKey("EnableAspNetIdentity") -and $enableAspNetIdentitySetting -ne $null) {
		$EnableAspNetIdentity = [bool]$enableAspNetIdentitySetting
	}
	if (-not $PSBoundParameters.ContainsKey("OidcEnabled")) {
		if ($enableOidcSetting -ne $null) { $OidcEnabled = [bool]$enableOidcSetting }
		elseif ($legacyEnableOidcSetting -ne $null) { $OidcEnabled = [bool]$legacyEnableOidcSetting }
	}
	if (-not $PSBoundParameters.ContainsKey("OidcAuthority")) {
		if ($oidcAuthoritySetting) { $OidcAuthority = [string]$oidcAuthoritySetting }
		elseif ($legacyOidcAuthoritySetting) { $OidcAuthority = [string]$legacyOidcAuthoritySetting }
	}
	if (-not $PSBoundParameters.ContainsKey("OidcClientId")) {
		if ($oidcClientIdSetting) { $OidcClientId = [string]$oidcClientIdSetting }
		elseif ($legacyOidcClientIdSetting) { $OidcClientId = [string]$legacyOidcClientIdSetting }
	}
	if (-not $PSBoundParameters.ContainsKey("OidcClientSecret")) {
		if ($oidcClientSecretSetting) { $OidcClientSecret = [string]$oidcClientSecretSetting }
		elseif ($legacyOidcClientSecretSetting) { $OidcClientSecret = [string]$legacyOidcClientSecretSetting }
	}
	if (-not $PSBoundParameters.ContainsKey("OidcCallbackPath")) {
		if ($oidcCallbackPathSetting) { $OidcCallbackPath = [string]$oidcCallbackPathSetting }
		elseif ($legacyOidcCallbackPathSetting) { $OidcCallbackPath = [string]$legacyOidcCallbackPathSetting }
	}
	if (-not $PSBoundParameters.ContainsKey("OidcRequireHttpsMetadata")) {
		if ($oidcRequireHttpsMetadataSetting -ne $null) { $OidcRequireHttpsMetadata = [bool]$oidcRequireHttpsMetadataSetting }
		elseif ($legacyOidcRequireHttpsMetadataSetting -ne $null) { $OidcRequireHttpsMetadata = [bool]$legacyOidcRequireHttpsMetadataSetting }
	}
	if (-not $PSBoundParameters.ContainsKey("OidcGroupClaimType")) {
		if ($oidcGroupClaimTypeSetting) { $OidcGroupClaimType = [string]$oidcGroupClaimTypeSetting }
		elseif ($legacyOidcGroupClaimTypeSetting) { $OidcGroupClaimType = [string]$legacyOidcGroupClaimTypeSetting }
	}
	if (-not $PSBoundParameters.ContainsKey("OidcAdminGroups") -and $oidcAdminGroupsSetting) {
		$OidcAdminGroups = @($oidcAdminGroupsSetting | ForEach-Object { [string]$_ })
	}
	if (-not $PSBoundParameters.ContainsKey("OidcAuditorGroups") -and $oidcAuditorGroupsSetting) {
		$OidcAuditorGroups = @($oidcAuditorGroupsSetting | ForEach-Object { [string]$_ })
	}
	if (-not $PSBoundParameters.ContainsKey("OidcProjectUserGroups") -and $oidcProjectUserGroupsSetting) {
		$OidcProjectUserGroups = @($oidcProjectUserGroupsSetting | ForEach-Object { [string]$_ })
	}

	if (-not $PSBoundParameters.ContainsKey("ConsoleAuditLoggingEnabled") -and $consoleLoggingEnabledSetting -ne $null) {
		$ConsoleAuditLoggingEnabled = [bool]$consoleLoggingEnabledSetting
	}
	if (-not $PSBoundParameters.ContainsKey("SqlQueryLoggingEnabled") -and $sqlQueryLoggingEnabledSetting -ne $null) {
		$SqlQueryLoggingEnabled = [bool]$sqlQueryLoggingEnabledSetting
	}
	if (-not $PSBoundParameters.ContainsKey("LoggingDefaultLevel") -and $loggingDefaultLevelSetting) { $LoggingDefaultLevel = [string]$loggingDefaultLevelSetting }
	if (-not $PSBoundParameters.ContainsKey("LoggingMicrosoftAspNetCoreLevel") -and $loggingAspNetCoreLevelSetting) { $LoggingMicrosoftAspNetCoreLevel = [string]$loggingAspNetCoreLevelSetting }
}

if ([string]::IsNullOrWhiteSpace($AdminPassword)) {
	throw "AdminPassword is required. Provide -AdminPassword or set BootstrapAdmin:Password in the settings file."
}

if ([string]::IsNullOrWhiteSpace($JournalEncryptionKey)) {
	throw "JournalEncryptionKey is required. Provide -JournalEncryptionKey or set Security:JournalEncryptionKey in the settings file."
}

try {
	Invoke-Az -Args @("account", "show", "--output", "none") | Out-Null
}
catch {
	throw "Azure CLI is not authenticated. Run 'az login' first."
}

Invoke-Az -Args @("account", "set", "--subscription", $SubscriptionId) | Out-Null

$projectFile = (Resolve-Path $ProjectPath).Path
$outputRoot = (Resolve-Path ".").Path
$deployRoot = Join-Path $outputRoot $OutputDirectory
$publishDir = Join-Path $deployRoot "publish"
$zipPath = Join-Path $deployRoot "$WebAppName.zip"

if (Test-Path $deployRoot) {
	Remove-Item -Path $deployRoot -Recurse -Force
}

New-Item -Path $deployRoot -ItemType Directory -Force | Out-Null

Write-Host "Creating/updating resource group '$ResourceGroupName' in '$Location'..." -ForegroundColor Cyan
Invoke-Az -Args @("group", "create", "--name", $ResourceGroupName, "--location", $Location, "--output", "none") | Out-Null

Write-Host "Creating/updating App Service plan '$AppServicePlanName' (SKU: $Sku, Linux)..." -ForegroundColor Cyan
Invoke-Az -Args @(
	"appservice", "plan", "create",
	"--name", $AppServicePlanName,
	"--resource-group", $ResourceGroupName,
	"--location", $Location,
	"--sku", $Sku,
	"--is-linux",
	"--output", "none"
) | Out-Null

$webAppExists = $false
try {
	$existingName = (Invoke-Az -Args @("webapp", "show", "--resource-group", $ResourceGroupName, "--name", $WebAppName, "--query", "name", "--output", "tsv")).Trim()
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
		"--runtime", $Runtime,
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

$oidcEnabledValue = if ($OidcEnabled) { "true" } else { "false" }
$oidcRequireHttpsMetadataValue = if ($OidcRequireHttpsMetadata) { "true" } else { "false" }
$localLoginEnabledValue = if ($EnableLocalLogin) { "true" } else { "false" }
$aspNetIdentityEnabledValue = if ($EnableAspNetIdentity) { "true" } else { "false" }
$consoleLoggingEnabledValue = if ($ConsoleAuditLoggingEnabled) { "true" } else { "false" }
$sqlQueryLoggingEnabledValue = if ($SqlQueryLoggingEnabled) { "true" } else { "false" }

$settings = @(
	"ASPNETCORE_ENVIRONMENT=$AppEnvironment",
	"Kestrel__Endpoints__Http__Url=http://+:8080",
	"Persistence__Provider=Sqlite",
	"Persistence__EnableProductionAppDatabase=true",
	"Persistence__EnableProductionIdentityDatabase=true",
	"Persistence__AutoMigrateOnStartup=true",
	"ConnectionStrings__SecureJournalSqlite=Data Source=/home/site/wwwroot/securejournal.db",
	"ConnectionStrings__SecureJournalIdentitySqlite=Data Source=/home/site/wwwroot/securejournal.identity.db",
	"Security__JournalEncryptionKey=$JournalEncryptionKey",
	"BootstrapAdmin__Username=$AdminUsername",
	"BootstrapAdmin__DisplayName=$AdminDisplayName",
	"BootstrapAdmin__Password=$AdminPassword",
	"BootstrapAdmin__SyncPasswordOnStartup=true",
	"Authentication__EnableLocalLogin=$localLoginEnabledValue",
	"Authentication__EnableAspNetIdentity=$aspNetIdentityEnabledValue",
	"Authentication__EnableOidc=$oidcEnabledValue",
	"Authentication__OidcProviderName=Microsoft Entra ID",
	"Authentication__Oidc__Authority=$OidcAuthority",
	"Authentication__Oidc__ClientId=$OidcClientId",
	"Authentication__Oidc__ClientSecret=$OidcClientSecret",
	"Authentication__Oidc__CallbackPath=$OidcCallbackPath",
	"Authentication__Oidc__RequireHttpsMetadata=$oidcRequireHttpsMetadataValue",
	"Authentication__Oidc__GroupClaimType=$OidcGroupClaimType",
	"Logging__Console__Enabled=$consoleLoggingEnabledValue",
	"Logging__SqlQueries__Enabled=$sqlQueryLoggingEnabledValue",
	"Logging__LogLevel__Default=$LoggingDefaultLevel",
	"Logging__LogLevel__Microsoft__AspNetCore=$LoggingMicrosoftAspNetCoreLevel",
	"AllowedHosts=*"
)

for ($i = 0; $i -lt $OidcAdminGroups.Count; $i++) {
	$settings += "Authentication__Oidc__RoleGroupMappings__Administrator__$i=$($OidcAdminGroups[$i])"
}

for ($i = 0; $i -lt $OidcAuditorGroups.Count; $i++) {
	$settings += "Authentication__Oidc__RoleGroupMappings__Auditor__$i=$($OidcAuditorGroups[$i])"
}

for ($i = 0; $i -lt $OidcProjectUserGroups.Count; $i++) {
	$settings += "Authentication__Oidc__RoleGroupMappings__ProjectUser__$i=$($OidcProjectUserGroups[$i])"
}

Write-Host "Configuring App Service application settings..." -ForegroundColor Cyan
$settingsObject = [ordered]@{}
foreach ($setting in $settings) {
	$separatorIndex = $setting.IndexOf('=')
	if ($separatorIndex -lt 0) {
		continue
	}

	$key = $setting.Substring(0, $separatorIndex)
	$value = $setting.Substring($separatorIndex + 1)
	$settingsObject[$key] = $value
}

$settingsFilePath = Join-Path $deployRoot "appsettings.deploy.json"
$settingsObject | ConvertTo-Json -Compress | Set-Content -Path $settingsFilePath -Encoding utf8

Invoke-Az -Args @(
	"webapp", "config", "appsettings", "set",
	"--resource-group", $ResourceGroupName,
	"--name", $WebAppName,
	"--settings", "@$settingsFilePath",
	"--output", "none"
) | Out-Null

Write-Host "Publishing app from '$projectFile' ($Configuration)..." -ForegroundColor Cyan
Invoke-CommandStrict -FileName "dotnet" -Arguments @(
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

$defaultHostName = (Invoke-Az -Args @("webapp", "show", "--resource-group", $ResourceGroupName, "--name", $WebAppName, "--query", "defaultHostName", "--output", "tsv")).Trim()
$appUrl = "https://$defaultHostName"
$portalUrl = "https://portal.azure.com/#view/WebsitesExtension/WebsiteOverviewBlade/id/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$WebAppName"

Write-Host "Deployment completed successfully." -ForegroundColor Green
Write-Host "App URL: $appUrl" -ForegroundColor Green
Write-Host "Azure Portal: $portalUrl" -ForegroundColor Green
