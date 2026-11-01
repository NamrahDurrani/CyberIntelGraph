# git_init.ps1 - Initialize Git, make the first commit, and (optionally) connect GitHub.
# Run from the project root:
#   .\scripts\git_init.ps1                                  (local repo + commit only)
#   .\scripts\git_init.ps1 -RemoteUrl https://github.com/YOUR-USER/CyberIntelGraph.git   (also push)
param([string]$RemoteUrl = "")
Set-Location (Split-Path -Parent $PSScriptRoot)

if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Write-Host "Git is not installed." -ForegroundColor Red; exit 1 }

$name  = git config --global user.name
$email = git config --global user.email
if (-not $name -or -not $email) {
    Write-Host "Set your Git identity first (once per PC):" -ForegroundColor Yellow
    Write-Host '  git config --global user.name  "Your Name"'
    Write-Host '  git config --global user.email "you@example.com"'
    exit 1
}

if (-not (Test-Path ".git")) { git init -b main } else { Write-Host ".git already exists - skipping init." }

git add .
Write-Host "--- Files staged (check that .venv and .env are NOT listed) ---" -ForegroundColor Cyan
git status --short | Select-Object -First 15
Write-Host "..."

$pending = git status --porcelain
if ($pending) { git commit -m "Milestone 1: project structure, docs and helper scripts" } else { Write-Host "Nothing new to commit." }

if ($RemoteUrl) {
    $existing = git remote
    if ($existing -contains "origin") { git remote set-url origin $RemoteUrl } else { git remote add origin $RemoteUrl }
    git push -u origin main
}
git log --oneline
