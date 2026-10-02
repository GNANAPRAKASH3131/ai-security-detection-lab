param(
    [string]$Message = ""
)

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   Antigravity -> GitHub Auto-Sync Tool" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Stage all files
git add .

# Check if there are changes to commit
$status = git status --porcelain
if ($status) {
    if (-not $Message) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $Message = "Sync changes from Antigravity [$timestamp]"
    }
    Write-Host "[*] Committing: $Message" -ForegroundColor Yellow
    git commit -m "$Message"
} else {
    Write-Host "[*] No new file modifications to commit." -ForegroundColor Gray
}

# Push to GitHub
Write-Host "[*] Pushing to GitHub repository..." -ForegroundColor Cyan
git push -u origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] SUCCESS: Antigravity changes are now live on GitHub!" -ForegroundColor Green
} else {
    Write-Host "[!] Note: If prompted, authenticate via GitHub browser login or personal access token." -ForegroundColor Yellow
}
