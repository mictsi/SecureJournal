param()

$scriptPath = Join-Path $PSScriptRoot "start.ps1"
& $scriptPath -CleanDb
exit $LASTEXITCODE
