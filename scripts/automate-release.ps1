# Automate SecureJournal release and publish to GitHub
param(
    [string]$VersionTag,
    [string]$ReleaseTitle = "Release $VersionTag",
    [string]$ReleaseNotesFile = "..\docs\releases\$VersionTag.md",
    [string]$ProjectPath = "..\SecureJournal.Web\SecureJournal.Web.csproj",
    [string]$ArtifactDir = "..\artifacts\releases",
    [string]$ZipName = "SecureJournal.Web-$VersionTag-publish.zip"
)

Write-Host "Building project..."
dotnet publish $ProjectPath -c Release -o "$ArtifactDir\$VersionTag"

Write-Host "Packaging artifact..."
Compress-Archive -Path "$ArtifactDir\$VersionTag\*" -DestinationPath "$ArtifactDir\$ZipName" -Force

Write-Host "Creating git tag $VersionTag..."
git tag $VersionTag
git push origin $VersionTag

Write-Host "Publishing release to GitHub..."
gh release create $VersionTag "$ArtifactDir\$ZipName" --title "$ReleaseTitle" --notes-file $ReleaseNotesFile

Write-Host "Release $VersionTag published successfully!"