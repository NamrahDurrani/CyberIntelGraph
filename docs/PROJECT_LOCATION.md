# Where is the project? (location, `cig`, moving, OneDrive)

## The one idea
**The project is whatever folder contains `README.md`.** Nothing in the code depends on a fixed address:
the Python scripts find the project root from their own file location, and the PowerShell scripts find it from `$PSScriptRoot`.
So the project works on any drive, in a folder with spaces, or after being moved. What *can* go wrong is **your terminal being in a different folder**.

**Analogy:** the project is a house. The scripts always know which house they are in. Your terminal is you, standing somewhere in town: if you type "open the kitchen door" in the wrong street, nothing happens.

## Symptoms of "the terminal is in the wrong folder"
| What you see | Meaning |
|---|---|
| `python: can't open file '...\ingestion\...': [Errno 2] No such file or directory` | There is no `ingestion` folder where the terminal is |
| `Ran 0 tests ... NO TESTS RAN` | There is no `tests\unit` folder where the terminal is |
| `.\.venv\Scripts\Activate.ps1 : ... is not recognized` | No `.venv` where the terminal is (wrong folder, or the environment was never created) |
| `ModuleNotFoundError: requests`, or a collector saying the package is not available | The project's `.venv` is not active; the **global** Python is running |

Also remember: `Expand-Archive -DestinationPath <folder>` writes into `<folder>` whatever your terminal location is. Extracting into one folder and running in another is how updates "disappear".

## The `cig` shortcut (install once)
```powershell
.\scripts\install_shortcut.ps1        # run once, from inside the project folder
```
It stores the project folder in the user variable `CYBERINTELGRAPH_HOME` and adds a function to your PowerShell profile. In any **new** terminal:
```powershell
cig            # go to the project folder and activate .venv
cig doctor     # the same, then run the health check
```
Moved the project? Run `install_shortcut.ps1` again from the new location. Remove it: `.\scripts\install_shortcut.ps1 -Remove`.

## The doctor
```powershell
python "<project folder>\scripts\doctor.py"      # works from ANY folder, even with the wrong Python
```
It reports: the project folder it belongs to, whether your terminal is inside it, whether `.venv` is the Python that is running, Python version, packages, key files and tests,
data present per source, whether `.env` exists and the NVD key is set (yes/no only, never the key), disk space, OneDrive, whether `CYBERINTELGRAPH_HOME` points here, and Git state.
Exit code 1 only when something is broken (FAIL lines); WARN lines are advice.

## OneDrive: allowed, but know the trade-off
| | Outside OneDrive (for example `C:\CyberIntelGraph`) | Inside OneDrive |
|---|---|---|
| Sync traffic | none | OneDrive uploads `.venv` (thousands of files) and the data (hundreds of MB) |
| Files On-Demand | n/a | files may be "online only" and download when first read (slow first audit) |
| Locked files | rare | a file being synced can briefly block a write |
| Backup | Git (code and docs) + you rebuild data by re-running collectors | extra copy in the cloud |
| Path | short, no spaces | long, with spaces: always quote it |

Recommendation: keep the project outside OneDrive; Git is the backup for code and docs, and data can be rebuilt. If you do keep it inside OneDrive, set the folder to
**Always keep on this device** and avoid editing raw data files. The doctor warns about OneDrive but never blocks you.

## Moving the project (to or from OneDrive, or to another drive)
A virtual environment is **not** portable (it stores absolute paths), so it is recreated, not copied. Everything else, including `data\` and `.git`, can be copied.
```powershell
$old = "C:\CyberIntelGraph"                                                     # where it is now
$new = "C:\Users\User\OneDrive\Desktop\My Projects\CyberIntelGraph"            # where it should go (quote paths with spaces)

robocopy $old $new /E /XD .venv                 # copy everything except the environment (exit codes 0-7 mean success)
cd $new
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
.\scripts\install_shortcut.ps1                  # point cig at the new location
python scripts\doctor.py                        # everything should be OK
python ingestion\validation\audit_raw_data.py   # SHA-256 proves the raw data survived the move
```
Only after the doctor and the audit are happy, delete the old folder. Then open the new one in VS Code (`code $new`).

## VS Code tip
Open the project with **File > Open Folder** on the real project folder. New integrated terminals start in the opened folder; if VS Code still has an old or deleted folder open,
every terminal starts there. That is what happened when commands ran in an empty copy of the project.

## Quick self-check (copy and paste)
```powershell
Get-Location                        # where am I?
Test-Path .\.venv\Scripts\python.exe   # True if this is a project folder with an environment
python -c "import sys; print(sys.executable)"   # should end with ...\.venv\Scripts\python.exe
```
