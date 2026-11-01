# setup_env.ps1 - Create the Python 3.12 virtual environment for CyberIntelGraph.
# Run from the project root:   .\scripts\setup_env.ps1
Set-Location (Split-Path -Parent $PSScriptRoot)

Write-Host "== Step 1: look for Python 3.12 ==" -ForegroundColor Cyan
$ver = ""
try { $ver = & py -3.12 --version 2>&1 } catch { $LASTEXITCODE = 1 }
if ($LASTEXITCODE -ne 0) {
    Write-Host "Python 3.12 was NOT found." -ForegroundColor Red
    Write-Host "Install it with:  winget install --id Python.Python.3.12 -e"
    Write-Host "Then CLOSE and reopen PowerShell and run this script again."
    exit 1
}
Write-Host "Found: $ver"

Write-Host "== Step 2: create .venv ==" -ForegroundColor Cyan
if (Test-Path ".venv\Scripts\python.exe") {
    Write-Host ".venv already exists - keeping it."
} else {
    & py -3.12 -m venv .venv
    Write-Host ".venv created."
}

Write-Host "== Step 3: upgrade pip inside the venv ==" -ForegroundColor Cyan
& .\.venv\Scripts\python.exe -m pip install --upgrade pip

Write-Host "== Step 4: verify ==" -ForegroundColor Cyan
& .\.venv\Scripts\python.exe --version
& .\.venv\Scripts\python.exe -c "import sys; print(sys.executable)"

Write-Host ""
Write-Host "Done. Activate the environment in YOUR terminal with:" -ForegroundColor Green
Write-Host "    .\.venv\Scripts\Activate.ps1"
Write-Host "(If scripts are blocked: Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned)"
