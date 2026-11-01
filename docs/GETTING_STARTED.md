# Getting Started (Windows + PowerShell)

Analogy: a **virtual environment** is a separate toolbox for this project. Tools (packages)
you put in it cannot clash with tools from your other projects.

## 0. What you need
| Tool | Check command | Expected |
|---|---|---|
| Git | `git --version` | `git version 2.x` |
| VS Code | `code --version` | a version number |
| Python 3.12 | `py -3.12 --version` | `Python 3.12.x` |

Your PC may have Python 3.13 as the default. That is fine: we use the `py` launcher to pick 3.12
for this project only.

## 1. Install Python 3.12 (only if step 0 failed)
```powershell
winget install --id Python.Python.3.12 -e
```
Close and reopen PowerShell, then run `py -3.12 --version` again.
If `winget` is missing: download the 3.12 installer from python.org, tick "Add python.exe to
PATH", and (optional, saves C: space) choose a custom path such as `D:\Python312`.

## 2. Create the virtual environment
```powershell
cd C:\CyberIntelGraph
.\scripts\setup_env.ps1
```
Expected last lines: `Python 3.12.x` and `C:\CyberIntelGraph\.venv\Scripts\python.exe`.

## 3. Activate it (every new terminal)
```powershell
.\.venv\Scripts\Activate.ps1
```
Your prompt starts with `(.venv)`.
If you see "running scripts is disabled", run once:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

## 4. Verify
```powershell
python --version
python -c "import sys; print(sys.executable)"
.\scripts\verify_structure.ps1
```
| Command | Expected |
|---|---|
| `python --version` | `Python 3.12.x` |
| `sys.executable` | `C:\CyberIntelGraph\.venv\Scripts\python.exe` |
| `verify_structure.ps1` | `STRUCTURE OK` |

## 5. Tell VS Code which Python to use
`Ctrl+Shift+P` -> **Python: Select Interpreter** -> choose `.venv (3.12.x)`.

## 6. Create your .env (later milestones need it)
```powershell
Copy-Item .env.example .env
```
Never commit `.env`. Keys are added only when a milestone asks for them.

## Troubleshooting
| Problem | Fix |
|---|---|
| `py` is not recognized | Reinstall Python from python.org and tick "py launcher" |
| `python --version` shows 3.13 inside the venv | You are not in the venv. Re-run the Activate command |
| Disk full on C: | Keep everything on D:. Set `$env:PIP_CACHE_DIR="D:\pip_cache"` before installing big packages |
| `Activate.ps1` blocked | Use the `Set-ExecutionPolicy` command above |
