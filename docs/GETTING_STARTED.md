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
Open PowerShell in the project folder (the one that contains `README.md`; it can be on any drive), then:
```powershell
.\scripts\setup_env.ps1
```
Expected last lines: `Python 3.12.x` and `<your project folder>\.venv\Scripts\python.exe`.

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
| `sys.executable` | `<your project folder>\.venv\Scripts\python.exe` |
| `verify_structure.ps1` | `STRUCTURE OK` |

## 5. Tell VS Code which Python to use
`Ctrl+Shift+P` -> **Python: Select Interpreter** -> choose `.venv (3.12.x)`.

## 6. Create your .env (later milestones need it)
```powershell
Copy-Item .env.example .env
```
Never commit `.env`. Keys are added only when a milestone asks for them.

## 7. Install the `cig` shortcut (once)
```powershell
.\scripts\install_shortcut.ps1
```
Open a **new** PowerShell window and type `cig`: it goes to the project and activates `.venv`, from any folder. `cig doctor` also runs the health check.
If you ever move the project, run `install_shortcut.ps1` again from the new location.

## Troubleshooting
| Problem | Fix |
|---|---|
| `py` is not recognized | Reinstall Python from python.org and tick "py launcher" |
| `python --version` shows 3.13 inside the venv | You are not in the venv. Re-run the Activate command |
| Disk full on C: | Keep everything on D:. Set `$env:PIP_CACHE_DIR="D:\pip_cache"` before installing big packages |
| `Activate.ps1` blocked | Use the `Set-ExecutionPolicy` command above |
| `python can't open file ... [Errno 2]`, `Ran 0 tests`, or `.\.venv\... is not recognized` | The terminal is in the wrong folder (not the project). Type `cig`, or run `python <project folder>\scripts\doctor.py`. See `docs/PROJECT_LOCATION.md` |
| `ModuleNotFoundError: requests` or the collector says the package is not available | The project's `.venv` is not active (the global Python is running). Type `cig` |
