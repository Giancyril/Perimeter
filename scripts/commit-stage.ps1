# scripts/commit-stage.ps1
param (
    [Parameter(Mandatory=$true)]
    [string]$Message
)
git add -A
git commit -m $Message
if ($LASTEXITCODE -ne 0) {
    Write-Host "Nothing to commit or commit failed."
}
