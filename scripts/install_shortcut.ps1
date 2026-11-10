# install_shortcut.ps1 - register the "cig" command so you can get into the project from ANY terminal, on any drive.
#
#   .\scripts\install_shortcut.ps1            install (run it once from inside the project folder)
#   .\scripts\install_shortcut.ps1 -Remove    uninstall
#
# What it does:
#   1. Stores THIS project's folder in the user environment variable CYBERINTELGRAPH_HOME.
#   2. Adds a small function called cig to your PowerShell profile. In any NEW terminal:
#         cig           go to the project folder and activate its virtual environment
#         cig doctor    the same, then run the project health check
#   If you ever move the project, run this script again from the new location.
param([switch]$Remove)

$root = Split-Path -Parent $PSScriptRoot
$profilePath = $PROFILE
$begin = "# >>> CyberIntelGraph >>>"
$end   = "# <<< CyberIntelGraph <<<"

if (-not (Test-Path $profilePath)) {
    New-Item -ItemType File -Force -Path $profilePath | Out-Null
}
$existing = Get-Content -Path $profilePath -Raw
if ($null -eq $existing) { $existing = "" }
$pattern = "(?s)" + [regex]::Escape($begin) + ".*?" + [regex]::Escape($end) + "\r?\n?"
$clean = [regex]::Replace($existing, $pattern, "").TrimEnd()

if ($Remove) {
    Set-Content -Path $profilePath -Value $clean -Encoding UTF8
    [Environment]::SetEnvironmentVariable("CYBERINTELGRAPH_HOME", $null, "User")
    Write-Host "cig removed. Open a new terminal for it to take effect." -ForegroundColor Green
    return
}

$block = @'
# >>> CyberIntelGraph >>>
function cig {
    param([string]$Task = "")
    $projectHome = [Environment]::GetEnvironmentVariable("CYBERINTELGRAPH_HOME", "User")
    if (-not $projectHome -or -not (Test-Path $projectHome)) {
        Write-Host "CYBERINTELGRAPH_HOME is not set or the folder is missing. Run scripts\install_shortcut.ps1 from the project folder." -ForegroundColor Red
        return
    }
    Set-Location $projectHome
    $activate = Join-Path $projectHome ".venv\Scripts\Activate.ps1"
    if (Test-Path $activate) { & $activate } else { Write-Host "No .venv in $projectHome. Run .\scripts\setup_env.ps1" -ForegroundColor Yellow }
    if ($Task -eq "doctor") { python scripts\doctor.py }
}
# <<< CyberIntelGraph <<<
'@

$newContent = $clean
if ($newContent.Length -gt 0) { $newContent += "`r`n`r`n" }
$newContent += $block.Trim() + "`r`n"
Set-Content -Path $profilePath -Value $newContent -Encoding UTF8
[Environment]::SetEnvironmentVariable("CYBERINTELGRAPH_HOME", $root, "User")
$env:CYBERINTELGRAPH_HOME = $root

Write-Host "Installed. Project folder: $root" -ForegroundColor Green
Write-Host "Profile updated:           $profilePath"
Write-Host "Open a NEW PowerShell window and type:  cig        (or: cig doctor)"
